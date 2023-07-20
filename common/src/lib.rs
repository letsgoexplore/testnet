extern crate interface;
extern crate quick_error;
extern crate serde;
extern crate serde_cbor;
extern crate sgx_types;
extern crate sgx_urts;
extern crate tonic;

pub mod cli_util;
pub mod enclave;
pub mod types_nosgx;
pub mod funcs_nosgx;

mod aes_prng;
mod ecall_wrapper;

use enclave::EnclaveResult;

pub mod dc_proto {
    tonic::include_proto!("dc_proto");
}

#[macro_use]
extern crate log;
