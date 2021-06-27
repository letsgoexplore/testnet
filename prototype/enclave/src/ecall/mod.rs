mod aggregation;
mod register;
mod submit;

use utils::serialize_to_ptr;
use sgx_types::{SgxResult, sgx_status_t};
use sgx_status_t::{SGX_SUCCESS, SGX_ERROR_INVALID_PARAMETER};
use std::slice;

enum EcallId {
    Keygen = 1,
}

use std::convert::TryFrom;

impl TryFrom<u8> for EcallId {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == EcallId::Keygen as u8 => Ok(EcallId::Keygen),
            _ => Err(()),
        }
    }
}

#[no_mangle]
pub extern "C" fn ecall_entrypoint(
    ecall_id_raw: u8,
    inp: *const u8,
    inp_len: usize,
    output: *mut u8,
    output_cap: usize,
    output_used: *mut usize,
) -> sgx_status_t {
    let ecall_id = match EcallId::try_from(ecall_id_raw) {
        Ok(i) => i,
        Err(_) => return SGX_ERROR_INVALID_PARAMETER,
    };

    match ecall_id {
        EcallId::Keygen => {
            generic_ecall(inp, inp_len, output, output_cap, output_used, register::new_sgx_keypair_internal_2)
        }
    }
}


fn generic_ecall<I, O>(inp: *const u8,
                       inp_len: usize,
                       output: *mut u8,
                       output_cap: usize,
                       output_used: *mut usize, internal_fn: fn(&I) -> SgxResult<O>) -> sgx_status_t
    where I: serde::de::DeserializeOwned, O: serde::Serialize {
    let input: I = unmarshal_or_abort!(I, inp, inp_len);
    let result = match internal_fn(&input) {
        Ok(o) => o,
        Err(e) => return e,
    };

    match unsafe { serialize_to_ptr(&result, output, output_cap, output_used) } {
        Ok(_) => SGX_SUCCESS,
        Err(e) => {
            println!("[IN] can't write to untrusted land {}", e);
            e
        }
    }
}

pub use self::aggregation::*;
pub use self::register::{ecall_new_sgx_keypair, ecall_unseal_to_pubkey};
pub use self::submit::ecall_user_submit;
use sgx_types::sgx_status_t::SGX_ERROR_UNEXPECTED;
