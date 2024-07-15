use sha3::{Digest, Keccak256};

use crate::{bs58_check, error::Result, kp::{derived_kp::KeypairDerived, secp256k1_kp::Keypair}};

const ADDRESS_LEN_INTERNAL: usize = 34;
pub const ADDRESS_LEN: usize = ADDRESS_LEN_INTERNAL + 1;

pub fn get_keypair() -> Result<KeypairDerived<ADDRESS_LEN_INTERNAL>> {
    let kp = Keypair::generate();

    let secret_key = kp.secret_key();
    let public_key = kp.public_key();

    let mut address = [0; ADDRESS_LEN_INTERNAL];

    // 0x41 version byte + 32 bytes for hashed public key
    // Insert 4-byte checksum after last 20 bytes of the public key and encode the 25 bytes using Base58
    let mut pk_hash = [0; 33];
    pk_hash[0] = 0x41;

    let mut hasher = Keccak256::new();
    hasher.update(&public_key);
    hasher.finalize_into((&mut pk_hash[1..]).into());

    // Put the last 20 bytes of a pk hash to 1..21 indexes
    for i in 1..21 {
        pk_hash.swap(i, i + 12);
    }

    bs58_check::bs58_check(&mut pk_hash[..25], address.as_mut_slice())?;

    Ok(KeypairDerived::new(secret_key, address))
}