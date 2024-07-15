use crate::error::Result;

pub struct KeypairDerived<const N: usize> {
    pub secret_key: [u8; 32],
    address: [u8; N],
}

impl<const N: usize> KeypairDerived<N> {
    pub fn new(secret_key: [u8; 32], address: [u8; N]) -> Self {
        Self { secret_key, address }
    }

    pub fn address_ref(&self) -> Result<&[u8]> {
        let s = self.address.iter()
            .position(|x| x == &0)
            .map(|i| &self.address[..i])
            .unwrap_or(&self.address);

        Ok(s)
    }

    pub fn address_ref_fixed(&self) -> Result<&[u8]> {
        Ok(&self.address)
    }
}