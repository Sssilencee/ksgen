use sha3::{Digest, Sha3_256};

use crate::{error::Result, kp::{derived_kp::KeypairDerived, ed25519_kp::Keypair}};

const ADDRESS_LEN_INTERNAL: usize = 64;
pub const ADDRESS_LEN: usize = ADDRESS_LEN_INTERNAL + 1;

pub fn get_keypair() -> Result<KeypairDerived<ADDRESS_LEN_INTERNAL>> {
    let kp = Keypair::generate();

    let secret_key = kp.secret_key();
    let public_key = kp.public_key();

    let mut address = [0; ADDRESS_LEN_INTERNAL];

    // In-place hashing of the public key with ending version byte (0x00)
    address[0..32].copy_from_slice(&public_key);

    let mut pk_hash = [0; 32];

    let mut hasher = Sha3_256::new();
    hasher.update(&address[..33]);
    hasher.finalize_into(pk_hash.as_mut_slice().into());

    hex::encode_to_slice(pk_hash, &mut address)?;

    Ok(KeypairDerived::new(secret_key, address))
}