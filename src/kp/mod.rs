pub mod derived_kp;

#[cfg(any(feature = "aptos", feature = "solana", feature = "sui"))]
pub mod ed25519_kp;

#[cfg(any(feature = "bitcoin", feature = "ethereum", feature = "litecoin", feature = "tron"))]
pub mod secp256k1_kp;