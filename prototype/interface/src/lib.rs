#![no_std]

extern crate cfg_if;
use cfg_if::cfg_if;
extern crate hex;

cfg_if! {
    if #[cfg(feature = "untrusted")] {
        #[macro_use]
        extern crate serde;
        #[macro_use]
        extern crate serde_big_array;
        extern crate std;
    } else if #[cfg(feature = "trusted")] {
        #[macro_use]
        extern crate serde_sgx;
        #[macro_use]
        extern crate serde_big_array_sgx;
        extern crate sgx_tstd as std;
        extern crate sha2;
        extern crate byteorder;
        extern crate sgx_rand;
        #[macro_use]
        extern crate sgx_rand_derive;
        extern crate sgx_tcrypto;
    } else {
        compile_error!{"must be either trusted or untrusted"}
    }
}

use std::prelude::v1::*;

big_array! { BigArray; }

mod ecall_interface;
mod params;
mod sealed_types;
mod sgx_protected_keys;
mod user_request;

pub use ecall_interface::*;
pub use params::*;
pub use sealed_types::*;
#[allow(dead_code)]
pub use sgx_protected_keys::*;
pub use user_request::*;
