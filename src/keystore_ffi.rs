use std::{ffi::c_char, slice};

use crate::{error::{KsgenError, Result}, keystore::{KdfParamsInternal, KeystoreInternal}};

pub const CIPHER_LEN: usize = 11 + 1;
pub const IV_LEN: usize = 32 + 1;
pub const CIPHERTEXT_LEN: usize = 64 + 1;
pub const KDF_LEN: usize = 6 + 1;
pub const SALT_LEN: usize = 32 + 1;
pub const MAC_LEN: usize = 64 + 1;

#[repr(C)]
pub struct Keystore {
    cipher: SizedStr,
    cipherparams: CipherParams,
    ciphertext: SizedStr,
    kdf: SizedStr,
    kdfparams: KdfParams,
    mac: SizedStr,
}

impl Keystore {
    pub unsafe fn write(&self, keystore: KeystoreInternal) -> Result<()> {
        let cipherparams = keystore.cipherparams.iv_hex_encoded()?;
        let ciphertext = keystore.ciphertext_hex_encoded()?;
        let mac = keystore.mac_hex_encoded()?;

        self.kdfparams.write_kdf_params_internal(&keystore.kdfparams)?;

        self.cipher.write_bytes(keystore.cipher.as_bytes());
        self.cipherparams.iv.write_bytes(&cipherparams);
        self.ciphertext.write_bytes(&ciphertext);
        self.kdf.write_bytes(keystore.kdf.as_bytes());
        self.mac.write_bytes(&mac);

        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.cipher.validate(CIPHER_LEN, "cipher")?;
        self.cipherparams.iv.validate(IV_LEN, "iv")?;
        self.ciphertext.validate(CIPHERTEXT_LEN, "ciphertext")?;
        self.kdf.validate(KDF_LEN, "kdf")?;
        self.kdfparams.validate()?;
        self.mac.validate(MAC_LEN, "mac")?;

        Ok(())
    }
}

#[repr(C)]
pub struct CipherParams {
    iv: SizedStr,
}

#[repr(C)]
pub struct KdfParams {
    dklen: *mut usize,
    n: *mut u32,
    r: *mut u32,
    p: *mut u32,
    salt: SizedStr,
}

impl KdfParams {
    unsafe fn write_kdf_params_internal(&self, params: &KdfParamsInternal) -> Result<()> {
        let salt = params.salt_hex_encoded()?;

        *self.dklen = params.dklen;
        *self.n = 2u32.pow(params.n.into());
        *self.r = params.r;
        *self.p = params.p;
        self.salt.write_bytes(&salt);

        Ok(())
    }

    #[inline]
    fn validate(&self) -> Result<()> {
        ptr_is_null(self.dklen, "dklen")?;
        ptr_is_null(self.n, "n")?;
        ptr_is_null(self.r, "r")?;
        ptr_is_null(self.p, "p")?;

        self.salt.validate(SALT_LEN, "salt")?;

        Ok(())
    }
}

#[repr(C)]
#[derive(Debug)]
pub enum Network {
    Aptos,
    Bitcoin,
    Ethereum,
    Litecoin,
    Solana,
    Sui,
    Tron,
}

#[repr(C)]
pub struct SizedStr {
    str: *mut c_char,
    len: usize,
}

impl SizedStr {
    pub unsafe fn write_bytes(&self, input: &[u8]) {
        let output = slice::from_raw_parts_mut(self.str as *mut u8, self.len);
        output[..self.len - 1].copy_from_slice(input);
    }

    pub fn validate(&self, expected_len: usize, field_name: &str) -> Result<()> {
        ptr_is_null(self.str, field_name)?;

        if self.len != expected_len {
            let err = KsgenError::invalid_output(
                expected_len, self.len,
                field_name.into(),
            );
            return Err(err);
        }

        Ok(())
    }
}

#[repr(C)]
pub struct SizedStrConst {
    str: *const c_char,
    len: usize,
}

impl SizedStrConst {
    pub fn validate(&self, field_name: &str) -> Result<()> {
        ptr_is_null(self.str, field_name)?;
        Ok(())
    }

    pub unsafe fn as_slice(&self) -> &[u8] {
        slice::from_raw_parts(self.str as *const u8, self.len)
    }
}

trait IsNull {
    fn is_null(self) -> bool;
}

impl<T> IsNull for *const T {
    #[inline]
    fn is_null(self) -> bool {
        self.is_null()
    }
}

impl<T> IsNull for *mut T {
    #[inline]
    fn is_null(self) -> bool {
        self.is_null()
    }
}

#[inline]
fn ptr_is_null<T: IsNull>(ptr: T, field_name: &str) -> Result<()> {
    if ptr.is_null() {
        return Err(KsgenError::null_ptr(field_name.into()));
    }

    Ok(())
}

