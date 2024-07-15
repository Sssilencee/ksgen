use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::{rngs::OsRng, Rng};
use scrypt::{password_hash::SaltString, Params};
use sha3::{Digest, Keccak256};

use crate::error::Result;

const SCRYPT_DK_LEN: usize = 32;
const SCRYPT_N: u8 = 13;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 8;

type Aes128Ctr128BE = ctr::Ctr128BE<aes::Aes128>;

pub struct KeystoreInternal<'a> {
    pub cipher: &'a str,
    pub cipherparams: CipherParams,
    ciphertext: [u8; 32],
    pub kdf: &'a str,
    pub kdfparams: KdfParamsInternal,
    mac: [u8; 32],
}

impl<'a> KeystoreInternal<'a> {
    pub fn from_secret_key(mut secret_key: [u8; 32], password: &[u8]) -> Result<Self> {
        let kdfparams = KdfParamsInternal::new()?;
        let scrypt_params = kdfparams.as_scrypt_params()?;

        // Hashes password bytes with a Scrypt function
        let mut password_hash = [0u8; 32];
        scrypt::scrypt(
            password,
            &kdfparams.salt,
            &scrypt_params,
            &mut password_hash
        )?;

        let (encryption_key, mac_key) = password_hash.split_at(16);

        // Encrypts secret key with an AES-128-CTR and initial vector
        let cipherparams = CipherParams::new();
        let mut cipher = Aes128Ctr128BE::new(
            encryption_key.into(),
            &cipherparams.iv.into(),
        );
        cipher.apply_keystream(&mut secret_key);

        // Hashes message authentication code with a Keccak256 function
        // of the second-leftmost 16 bytes of the derived key together
        // with the full ciphertext
        let mut mac_base = [0; 48];
        mac_base[..16].copy_from_slice(mac_key);
        mac_base[16..].copy_from_slice(&secret_key);
        let mut mac_hasher = Keccak256::new();
        mac_hasher.update(&mac_base);

        let mut mac = [0; 32];
        mac_hasher.finalize_into(mac.as_mut_slice().into());

        let ciphertext = secret_key;

        Ok(Self {
            cipher: "aes-128-ctr",
            cipherparams, ciphertext,
            kdf: "scrypt",
            kdfparams, mac
        })
    }

    #[inline]
    pub fn ciphertext_hex_encoded(&self) -> Result<[u8; 64]> {
        to_hex(&self.ciphertext)
    }

    #[inline]
    pub fn mac_hex_encoded(&self) -> Result<[u8; 64]> {
        to_hex(&self.mac)
    }
}

pub struct CipherParams {
    iv: [u8; 16],
}

impl CipherParams {
    pub fn new() -> Self {
        let iv: [u8; 16] = rand::thread_rng().gen();
        Self { iv }
    }

    #[inline]
    pub fn iv_hex_encoded(&self) -> Result<[u8; 32]> {
        to_hex(&self.iv)
    }
}

pub struct KdfParamsInternal {
    pub dklen: usize,
    pub n: u8,
    pub r: u32,
    pub p: u32,
    salt: [u8; 16],
}

impl KdfParamsInternal {
    pub fn new() -> Result<Self> {
        let salt_string = SaltString::generate(&mut OsRng);
        let mut salt = [0u8; 16];
        salt_string.decode_b64(&mut salt)?;

        Ok(Self {
            dklen: SCRYPT_DK_LEN,
            n: SCRYPT_N,
            r: SCRYPT_R,
            p: SCRYPT_P,
            salt
        })
    }

    pub fn as_scrypt_params(&self) -> Result<Params> {
        Ok(Params::new(
            self.n,
            self.r,
            self.p,
            self.dklen,
        )?)
    }

    #[inline]
    pub fn salt_hex_encoded(&self) -> Result<[u8; 32]> {
        to_hex(&self.salt)
    }
}

fn to_hex<const N: usize>(input: &[u8]) -> Result<[u8; N]> {
    let mut output = [0; N];
    hex::encode_to_slice(input, &mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore() {
        let password = b"STRONG_PASSWORD";
        let secret_key = rand::random();

        let keystore = KeystoreInternal::from_secret_key(secret_key, password).unwrap();
        let ciphertext_hex = keystore.ciphertext_hex_encoded().unwrap();
        let iv_hex = keystore.cipherparams.iv_hex_encoded().unwrap();

        let kdfparams = keystore.kdfparams;
        let scrypt_params = kdfparams.as_scrypt_params().unwrap();

        let mut password_hash = [0u8; 16];
        scrypt::scrypt(
            password,
            &kdfparams.salt,
            &scrypt_params,
            &mut password_hash
        ).unwrap();

        let mut secret_key_output = [0; 32];
        hex::decode_to_slice(ciphertext_hex, &mut secret_key_output).unwrap();

        let mut iv = [0; 16];
        hex::decode_to_slice(iv_hex,&mut iv).unwrap();

        let mut cipher = Aes128Ctr128BE::new(
            &password_hash.into(),
            &iv.into(),
        );
        cipher.apply_keystream(&mut secret_key_output);

        assert_eq!(secret_key, secret_key_output);
    }
}