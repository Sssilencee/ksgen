use sha3::{Digest, Keccak256};

use crate::{error::Result, kp::{derived_kp::KeypairDerived, secp256k1_kp::Keypair}};

const ADDRESS_LEN_INTERNAL: usize = 40;
pub const ADDRESS_LEN: usize = ADDRESS_LEN_INTERNAL + 1;

pub fn get_keypair() -> Result<KeypairDerived<ADDRESS_LEN_INTERNAL>> {
    let kp = Keypair::generate();

    let secret_key = kp.secret_key();
    let public_key = kp.public_key();

    let mut address = [0; ADDRESS_LEN_INTERNAL];
    let mut pk_hash = [0; 32];

    let mut hasher = Keccak256::new();
    hasher.update(&public_key[1..]);
    hasher.finalize_into(pk_hash.as_mut_slice().into());

    hex::encode_to_slice(&pk_hash[12..], &mut address)?;

    Ok(KeypairDerived::new(secret_key, address))
}