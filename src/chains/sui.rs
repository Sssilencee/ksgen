use blake2::{Blake2b, digest::consts::U32, Digest};

use crate::{error::Result, kp::{derived_kp::KeypairDerived, ed25519_kp::Keypair}};

const ADDRESS_LEN_INTERNAL: usize = 64;
pub const ADDRESS_LEN: usize = ADDRESS_LEN_INTERNAL + 1;

type Blake2b32 = Blake2b<U32>;

pub fn get_keypair() -> Result<KeypairDerived<ADDRESS_LEN_INTERNAL>> {
    let kp = Keypair::generate();

    let secret_key = kp.secret_key();
    let public_key = kp.public_key();

    let mut address = [0; ADDRESS_LEN_INTERNAL];

    // In-place hashing of the public key with starting version byte (0x00)
    address[1..33].copy_from_slice(&public_key);

    let mut pk_hash = [0; 32];

    let mut hasher = Blake2b32::new();
    hasher.update(&address[..33]);
    hasher.finalize_into(pk_hash.as_mut_slice().into());

    hex::encode_to_slice(pk_hash, &mut address)?;

    Ok(KeypairDerived::new(secret_key, address))
}