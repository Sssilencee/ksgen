use crate::{error::Result, kp::derived_kp::KeypairDerived};

use super::bitcoin;

const ADDRESS_LEN_INTERNAL: usize = bitcoin::ADDRESS_LEN_INTERNAL;
pub const ADDRESS_LEN: usize = bitcoin::ADDRESS_LEN;

pub fn get_keypair() -> Result<KeypairDerived<ADDRESS_LEN_INTERNAL>> {
    bitcoin::get_keypair_internal(0x30)
}