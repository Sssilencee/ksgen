use sha2::{Digest, Sha256};

use crate::error::Result;

pub fn bs58_check(input: &mut [u8], output: &mut [u8]) -> Result<()> {
    let mut chk = [0; 32];
    let end = input.len() - 4;

    let mut hasher = Sha256::new();
    hasher.update(&input[..end]);
    hasher.finalize_into(chk.as_mut_slice().into());

    let mut hasher = Sha256::new();
    hasher.update(&chk);
    hasher.finalize_into(chk.as_mut_slice().into());

    input[end..].copy_from_slice(&mut chk[..4]);

    bs58::encode(input)
        .onto(output)?;

    Ok(())
}