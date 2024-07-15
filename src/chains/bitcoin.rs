use ripemd::Ripemd160;
use sha2::{Sha256, Digest};

use crate::{bs58_check, error::Result, kp::{derived_kp::KeypairDerived, secp256k1_kp::Keypair}};

pub(super) const ADDRESS_LEN_INTERNAL: usize = 34;
pub const ADDRESS_LEN: usize = ADDRESS_LEN_INTERNAL + 1;

pub fn get_keypair() -> Result<KeypairDerived<ADDRESS_LEN_INTERNAL>> {
    get_keypair_internal(0x00)
}

pub(super) fn get_keypair_internal(version_byte: u8) -> Result<KeypairDerived<ADDRESS_LEN_INTERNAL>> {
    let kp = Keypair::generate();

    let secret_key = kp.secret_key();
    let public_key = kp.public_key();

    let mut address = [0; ADDRESS_LEN_INTERNAL];

    let mut pk_hash = [0; 33];
    pk_hash[0] = version_byte;

    let mut hasher = Sha256::new();
    hasher.update(&public_key);
    hasher.finalize_into((&mut pk_hash[1..]).into());

    let mut hasher = Ripemd160::new();
    hasher.update(&pk_hash);
    hasher.finalize_into((&mut pk_hash[1..21]).into());

    bs58_check::bs58_check(&mut pk_hash[..25], address.as_mut_slice())?;

    Ok(KeypairDerived::new(secret_key, address))
}