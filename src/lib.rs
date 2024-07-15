mod chains;
mod kp;
mod error;
mod keystore;
mod keystore_ffi;
mod macros;

#[cfg(any(feature = "bitcoin", feature = "litecoin", feature = "tron"))]
mod bs58_check;

use std::{ffi::{c_char, CString}, ptr::null};

use keystore::KeystoreInternal;
use keystore_ffi::{Keystore, Network, SizedStr, SizedStrConst};

type ErrorPtr = *const c_char;

#[no_mangle]
pub unsafe extern "C" fn init_keystore(
    keystore: *mut Keystore,
    address: SizedStr,
    password: SizedStrConst,
    network: Network,
) -> ErrorPtr {
    const ADDRESS_FIELD_NAME: &str = "address";

    let keystore = keystore.read();

    unwrap_or_handle!(keystore.validate());
    unwrap_or_handle!(password.validate("password"));

    let secret_key = match network {
        #[cfg(feature = "aptos")]
        Network::Aptos => {
            use chains::aptos;

            unwrap_or_handle!(address.validate(aptos::ADDRESS_LEN, ADDRESS_FIELD_NAME));

            let kp = unwrap_or_handle_ctx!(aptos::get_keypair(), "err aptos::get_keypair()");
            let address_slice = unwrap_or_handle_ctx!(kp.address_ref_fixed(), "err kp.address_ref_fixed()");

            address.write_bytes(address_slice);

            kp.secret_key
        },

        #[cfg(feature = "bitcoin")]
        Network::Bitcoin => {
            use chains::bitcoin;

            unwrap_or_handle!(address.validate(bitcoin::ADDRESS_LEN, ADDRESS_FIELD_NAME));

            let kp = unwrap_or_handle_ctx!(bitcoin::get_keypair(), "err bitcoin::get_keypair()");
            let address_slice = unwrap_or_handle_ctx!(kp.address_ref(), "err kp.address_ref_fixed()");

            address.write_bytes(address_slice);

            kp.secret_key
        },

        #[cfg(feature = "ethereum")]
        Network::Ethereum => {
            use chains::ethereum;

            unwrap_or_handle!(address.validate(ethereum::ADDRESS_LEN, ADDRESS_FIELD_NAME));

            let kp = unwrap_or_handle_ctx!(ethereum::get_keypair(), "err ethereum::get_keypair()");
            let address_slice = unwrap_or_handle_ctx!(kp.address_ref_fixed(), "err kp.address_ref_fixed()");

            address.write_bytes(address_slice);

            kp.secret_key
        },

        #[cfg(feature = "litecoin")]
        Network::Litecoin => {
            use chains::litecoin;

            unwrap_or_handle!(address.validate(litecoin::ADDRESS_LEN, ADDRESS_FIELD_NAME));

            let kp = unwrap_or_handle_ctx!(litecoin::get_keypair(), "err litecoin::get_keypair()");
            let address_slice = unwrap_or_handle_ctx!(kp.address_ref(), "err kp.address_ref_fixed()");

            address.write_bytes(address_slice);

            kp.secret_key
        },

        #[cfg(feature = "solana")]
        Network::Solana => {
            use chains::solana;

            unwrap_or_handle!(address.validate(solana::ADDRESS_LEN, ADDRESS_FIELD_NAME));

            let kp = unwrap_or_handle_ctx!(solana::get_keypair(), "err solana::get_keypair()");
            let address_slice = unwrap_or_handle_ctx!(kp.address_ref(), "err kp.address_ref()");

            address.write_bytes(address_slice);

            kp.secret_key
        },

        #[cfg(feature = "sui")]
        Network::Sui => {
            use chains::sui;

            unwrap_or_handle!(address.validate(sui::ADDRESS_LEN, ADDRESS_FIELD_NAME));

            let kp = unwrap_or_handle_ctx!(sui::get_keypair(), "err sui::get_keypair()");
            let address_slice = unwrap_or_handle_ctx!(kp.address_ref_fixed(), "err kp.address_ref_fixed()");

            address.write_bytes(address_slice);

            kp.secret_key
        },

        #[cfg(feature = "tron")]
        Network::Tron => {
            use chains::tron;

            unwrap_or_handle!(address.validate(tron::ADDRESS_LEN, ADDRESS_FIELD_NAME));

            let kp = unwrap_or_handle_ctx!(tron::get_keypair(), "err tron::get_keypair()");
            let address_slice = unwrap_or_handle_ctx!(kp.address_ref_fixed(), "err kp.address_ref_fixed()");

            address.write_bytes(address_slice);

            kp.secret_key
        },

        _ => bail!("an unknown network ({:?}) was passed as a parameter; try building the library using available features", network),
    };

    let password = password.as_slice();

    let keystore_internal = unwrap_or_handle_ctx!(
        KeystoreInternal::from_secret_key(secret_key, password),
        "err KeystoreInternal::from_secret_key()",
    );
    unwrap_or_handle_ctx!(keystore.write(keystore_internal), "err keystore.write()");

    null()
}

#[no_mangle]
pub unsafe extern "C" fn free_cstring(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    let _ = CString::from_raw(ptr);
}