#![no_std]

extern crate cfg_if;
use cfg_if::cfg_if;
extern crate hex;
extern crate log;
extern crate sha2;

cfg_if! {
    if #[cfg(feature = "untrusted")] {
        #[macro_use]
        extern crate serde;
        extern crate std;
        extern crate ed25519_dalek_untrusted as ed25519_dalek;
    } else if #[cfg(feature = "trusted")] {
        #[macro_use]
        extern crate serde_sgx;
        extern crate sgx_tstd as std;
        extern crate byteorder;
        extern crate sgx_rand;
        extern crate sgx_rand_derive;
        extern crate sgx_tcrypto;
        extern crate ed25519_dalek_trusted as ed25519_dalek;
    } else {
        compile_error!{"must be either trusted or untrusted"}
    }
}

mod array2d;
mod ecall_interface_types;
mod params;
mod sgx_protected_keys;
mod user_request;

pub use ecall_interface_types::*;
pub use params::*;
pub use sgx_protected_keys::*;
pub use user_request::*;
