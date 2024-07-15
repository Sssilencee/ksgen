use hex::FromHexError;
use scrypt::{errors::{InvalidOutputLen, InvalidParams}, password_hash::Error as ScryptHashingError};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, KsgenError>;

#[cfg(any(feature = "bitcoin", feature = "litecoin", feature = "solana", feature = "tron"))]
use bs58::encode::Error as Bs58Error;

#[derive(Error, Debug)]
pub enum KsgenError {
    #[error("err scrypt hashing: {0}")]
    ScrypHashingtErr(#[from] ScryptHashingError),

    #[error("err scrypt invalid output len: {0}")]
    ScryptInvalidOutputLenErr(#[from] InvalidOutputLen),

    #[error("err scrypt invalid params: {0}")]
    ScryptInvalidParamsErr(#[from] InvalidParams),

    #[error("err encoding to Hex: {0}")]
    FromHexErr(#[from] FromHexError),

    #[error("err invalid output len: (expected: {input_len:}, actual: {output_len:})")]
    InvalidOutputLenErr {
        input_len: usize,
        output_len: usize,
        field_name: String,
    },

    #[error("err field pointer is null: (field name: {field_name:}")]
    NullPtrErr {
        field_name: String,
    },

    #[cfg(any(feature = "bitcoin", feature = "litecoin", feature = "solana", feature = "tron"))]
    #[error("err encoding to Base58: {0}")]
    Bs58Err(#[from] Bs58Error),
}

impl KsgenError {
    pub fn invalid_output(
        input_len: usize,
        output_len: usize,
        field_name: String,
    ) -> Self {
        Self::InvalidOutputLenErr { input_len, output_len, field_name }
    }

    pub fn null_ptr(field_name: String) -> Self {
        Self::NullPtrErr { field_name }
    }
}