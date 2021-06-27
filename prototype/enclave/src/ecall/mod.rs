mod aggregation;
mod register;
mod submit;

use interface::*;
use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_SUCCESS};
use sgx_types::{sgx_status_t, SgxResult};
use std::convert::TryFrom;
use std::slice;
use utils::serialize_to_ptr;

#[no_mangle]
pub extern "C" fn ecall_entrypoint(
    ecall_id_raw: u8,
    inp: *const u8,
    inp_len: usize,
    output: *mut u8,
    output_cap: usize,
    output_used: *mut usize,
) -> sgx_status_t {
    let ecall_id = match EcallId::from_repr(ecall_id_raw) {
        Some(i) => i,
        None => return SGX_ERROR_INVALID_PARAMETER,
    };

    match ecall_id {
        EcallId::EcallNewSgxKeypair => generic_ecall(
            inp,
            inp_len,
            output,
            output_cap,
            output_used,
            register::new_sgx_keypair_internal,
        ),
        EcallId::EcallUnsealToPublicKey => generic_ecall(
            inp,
            inp_len,
            output,
            output_cap,
            output_used,
            register::unseal_to_pubkey_internal,
        ),
        EcallId::EcallRegisterUser => generic_ecall(
            inp,
            inp_len,
            output,
            output_cap,
            output_used,
            register::register_user_internal,
        ),
    }
}

fn generic_ecall<I, O>(
    inp: *const u8,
    inp_len: usize,
    output: *mut u8,
    output_cap: usize,
    output_used: *mut usize,
    internal_fn: fn(&I) -> SgxResult<O>,
) -> sgx_status_t
where
    I: serde::de::DeserializeOwned,
    O: serde::Serialize,
{
    println!("================== IN ENCLAVE ==================");
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
pub use self::submit::ecall_user_submit;
use sgx_types::sgx_status_t::SGX_ERROR_UNEXPECTED;
