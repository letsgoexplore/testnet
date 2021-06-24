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
use crypto::SharedServerSecret;
use interface::UserSubmissionReq;
use messages_types::SignedUserMessage;
use types::*;

// the safe version
// fn user_submit_internal(request: &UserSubmissionReq, tee_sk: &SgxSigningKey) -> DcNetResult<SignedUserMessage> {
// unseal shared server secrets

// derive the round key from shared secrets
// let round_key = crypto::derive_round_secret(
//     request.round, &request.shared_secrets)?;
// unimplemented!();
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
// }

fn user_submit_internal(
    send_request_ptr: *const u8,
    send_request_len: usize,
    sealed_tee_prv_key_ptr: *mut u8,
    sealed_tee_prv_key_len: usize,
    output: *mut u8,
    output_size: usize,
    output_bytes_written: *mut usize,
) -> SgxError {
    let send_request = serde_cbor::from_slice::<UserSubmissionReq>(unsafe {
        slice::from_raw_parts(send_request_ptr, send_request_len)
    })
    .map_err(|e| SGX_ERROR_INVALID_PARAMETER)?;

    //
    println!("got request {:?}", send_request);

    // 1) TODO: check ticket first
    println!("checking ticket");

    // 2) unseal private key
    let tee_prv_key = unsafe {
        unseal_from_ptr_and_deser::<SgxSigningKey>(sealed_tee_prv_key_ptr, sealed_tee_prv_key_len)
    }?;
    println!(
        "using signing (pub) key {}",
        tee_prv_key.try_get_public_key()?
    );

    // 3) derive the round key from shared secrets
    let shared_server_secrets = unsafe {
        unseal_from_vec_and_deser::<Vec<SharedServerSecret>>(send_request.shared_secrets.0)
    }?;
    // TODO: check shared_server_secrets correspond to anytrust_group_id
    println!("using {} servers", shared_server_secrets.len());

    let round_key = crypto::derive_round_secret(send_request.round, &shared_server_secrets)
        .map_err(|e| SGX_ERROR_INVALID_PARAMETER)?;

    println!("round_key derived: {}", round_key);

    // encrypt the message with round_key
    let encrypted_msg = round_key.encrypt(&send_request.msg);

    println!("encrypted message {}", hex::encode(encrypted_msg.0));

    // FIXME: add missing default fields
    let mut mutable = SignedUserMessage {
        user_id: send_request.user_id,
        anytrust_group_id: send_request.anytrust_group_id,
        round: send_request.round,
        tee_sig: Default::default(),
        tee_pk: Default::default(),
        msg: encrypted_msg,
    };

    // sign
    mutable.sign_mut(&tee_prv_key).map_err(|e| {
        println!("error signing: {}", e);
        SGX_ERROR_INVALID_PARAMETER
    })?;

    println!("signed use message {:?}", mutable);

    // serialize SignedUserMessage
    let serialized = serde_cbor::to_vec(&mutable).map_err(|e| {
        println!("error serializing: {}", e);
        SGX_ERROR_INVALID_PARAMETER
    })?;

    if serialized.len() > output_size {
        println!(
            "not enough output to write serialized message. need {} got {}",
            serialized.len(),
            output_size,
        );
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    unsafe {
        output.copy_from(serialized.as_ptr(), serialized.len());
        output_bytes_written.write(serialized.len())
    }

    Ok(())
}

use sgx_types::sgx_status_t::SGX_SUCCESS;
use sgx_types::{SgxError, SgxResult};
use utils::{unseal_data, unseal_from_ptr_and_deser, unseal_from_vec_and_deser, unseal_prv_key};

#[no_mangle]
pub extern "C" fn ecall_user_submit(
    send_request_ptr: *const u8,
    send_request_len: usize,
    sealed_tee_prv_key_ptr: *mut u8,
    sealed_tee_prv_key_len: usize,
    output: *mut u8,
    output_size: usize,
    output_bytes_written: *mut usize,
) -> sgx_status_t {
    match user_submit_internal(
        send_request_ptr,
        send_request_len,
        sealed_tee_prv_key_ptr,
        sealed_tee_prv_key_len,
        output,
        output_size,
        output_bytes_written,
    ) {
        Ok(()) => SGX_SUCCESS,
        Err(e) => e,
    }
}
