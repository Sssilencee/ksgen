use crate::{error::Result, kp::{derived_kp::KeypairDerived, ed25519_kp::Keypair}};

const ADDRESS_LEN_INTERNAL: usize = 44;
pub const ADDRESS_LEN: usize = ADDRESS_LEN_INTERNAL + 1;

pub fn get_keypair() -> Result<KeypairDerived<ADDRESS_LEN_INTERNAL>> {
    let kp = Keypair::generate();

    let secret_key = kp.secret_key();
    let public_key = kp.public_key();

    let mut address = [0; ADDRESS_LEN_INTERNAL];
    bs58::encode(public_key)
        .onto(address.as_mut_slice())?;

    Ok(KeypairDerived::new(secret_key, address))
}