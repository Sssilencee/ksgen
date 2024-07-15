use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

pub struct Keypair {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl Keypair {
    pub fn generate() -> Self {
        let kp = Secp256k1::new();
        let (secret_key, public_key) = kp.generate_keypair(&mut OsRng);

        Self { secret_key, public_key }
    }

    #[inline]
    pub fn secret_key(&self) -> [u8; 32] {
        self.secret_key.secret_bytes()
    }

    #[inline]
    pub fn public_key(&self) -> [u8; 65] {
        self.public_key.serialize_uncompressed()
    }
}