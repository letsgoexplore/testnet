extern crate sgx_types;

use sgx_status_t;

extern crate interface;

use self::interface::*;
use std::convert::TryInto;
use std::prelude::v1::*;

use sgx_types::*;

use crypto;
use types::*;

use crypto::{SignMutable, Verifiable};

// the safe version
fn submit(request: &SendRequest, tee_sk: &PrvKey) -> DcNetResult<SignedUserMessage> {
    let round_key = crypto::derive_round_secret(request.round, &request.server_keys)?;
    let encrypted_msg = round_key.encrypt(&request.message);
    let mut mutable = SignedUserMessage {
        user_id: request.user_id,
        round: request.round,
        message: encrypted_msg,
        tee_sig: Default::default(),
        tee_pk: Default::default(),
    };

    mutable.sign(tee_sk).map_err(DcNetError::from)?;

    Ok(mutable)
}

use std::slice;
use std::string;

use keygen;
use serde;
use serde_json;
use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED};

#[no_mangle]
pub extern "C" fn client_submit(
    send_request: *const u8,
    send_request_len: usize,
    sealed_tee_prv_key: *mut u8,
    sealed_tee_prv_key_len: u32,
    output: *mut u8,
    output_size: usize,
    output_bytes_written: *mut usize,
) -> sgx_status_t {
    let send_request: SendRequest = match serde_json::from_slice(unsafe {
        slice::from_raw_parts(send_request, send_request_len)
    }) {
        Ok(j) => j,
        Err(e) => {
            println!("Err: {}", e);
            return SGX_ERROR_INVALID_PARAMETER;
        }
    };

    let tee_prv_key_unsealed =
        match keygen::unseal_data::<PrvKey>(sealed_tee_prv_key, sealed_tee_prv_key_len) {
            Ok(k) => k,
            Err(e) => return e,
        };

    let tee_prv_key = tee_prv_key_unsealed.get_decrypt_txt();

    match submit(&send_request, &tee_prv_key) {
        Ok(signed_msg) => {
            let serialized: Vec<u8> = match serde_json::to_vec(&signed_msg) {
                Ok(vec) => vec,
                Err(e) => {
                    println!("err {}", e);
                    return SGX_ERROR_UNEXPECTED;
                }
            };

            if serialized.len() > output_size {
                println!("not enough output space. need {}", serialized.len());
                return SGX_ERROR_INVALID_PARAMETER;
            }

            unsafe {
                output.copy_from(serialized.as_ptr(), serialized.len());
                output_bytes_written.write(serialized.len())
            }

            sgx_status_t::SGX_SUCCESS
        }
        Err(e) => {
            println!("Err: {}", e);
            sgx_status_t::SGX_ERROR_UNEXPECTED
        }
    }
}
