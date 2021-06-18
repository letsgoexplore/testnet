extern crate interface;
extern crate sgx_types;

use serde_cbor;
use sgx_status_t;
use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED};

use std::prelude::v1::*;
use std::slice;

use crypto;
use crypto::{SgxSigningKey, SignMutable};

use self::interface::*;
use interface::UserSubmissionReq;
use messages_types::SignedUserMessage;
use types::*;
use utils;

// the safe version
fn submit(request: &UserSubmissionReq, tee_sk: &SgxSigningKey) -> DcNetResult<SignedUserMessage> {
    // unseal
    unimplemented!();

    // let round_key = crypto::derive_round_secret(
    //     request.round, &shared_secrets)?;
    // let encrypted_msg = round_key.encrypt(&request.message);
    // let mut mutable = SignedUserMessage {
    //     user_id: request.user_id,
    //     round: request.round,
    //     message: encrypted_msg,
    //     tee_sig: Default::default(),
    //     tee_pk: Default::default(),
    // };
    //
    // mutable.sign_mut(tee_sk).map_err(DcNetError::from)?;
    //
    // Ok(mutable)
}

#[no_mangle]
pub extern "C" fn ecall_client_submit(
    send_request_ptr: *const u8,
    send_request_len: usize,
    sealed_tee_prv_key_ptr: *mut u8,
    sealed_tee_prv_key_len: usize,
    output: *mut u8,
    output_size: usize,
    output_bytes_written: *mut usize,
) -> sgx_status_t {
    let send_request = unmarshal_or_return!(UserSubmissionReq, send_request_ptr, send_request_len);
    let tee_prv_key = unwrap_or_return!(
        utils::unseal_prv_key(sealed_tee_prv_key_ptr, sealed_tee_prv_key_len),
        SGX_ERROR_UNEXPECTED
    );

    let signed_msg = match submit(&send_request, &tee_prv_key) {
        Ok(m) => m,
        Err(e) => {
            println!("Err: {}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let serialized = unwrap_or_return!(serde_cbor::to_vec(&signed_msg), SGX_ERROR_UNEXPECTED);
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
