use ed25519_dalek::{SigningKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use rand::rngs::OsRng;

pub struct Keypair(SigningKey);

impl Keypair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;

        Self(SigningKey::generate(&mut csprng))
    }

    #[inline]
    pub fn secret_key(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0.to_bytes()
    }

    #[inline]
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.verifying_key().to_bytes()
    }
}