extern crate interface;
extern crate sgx_types;

use serde_cbor;
use sgx_status_t;
use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED};

use std::prelude::v1::*;
use std::slice;

use crypto;
use crypto::{SgxSigningKey, SharedSecretsWithAnyTrustGroup, SignMutable};

use self::interface::*;
use crypto::SharedServerSecret;
use interface::UserSubmissionReq;
use messages_types::SignedUserMessage;
use types::*;
use utils;

use std::convert::TryFrom;

pub fn user_submit_internal(
    send_request: &UserSubmissionReq,
    tee_prv_key: &SgxSigningKey,
    shared_server_secrets: &SharedSecretsWithAnyTrustGroup,
) -> SgxResult<SignedUserMessage> {
    println!("got request {:?}", send_request);

    // 1) TODO: check ticket first
    println!("[WARN] NOT checking ticket ATM");

    // 2) unseal private key
    println!(
        "using signing (pub) key {}",
        SgxProtectedKeyPub::try_from(tee_prv_key)?
    );

    // 3) derive the round key from shared secrets
    // TODO: check shared_server_secrets correspond to anytrust_group_id
    println!(
        "using {} servers",
        shared_server_secrets.anytrust_group_pairwise_keys.len()
    );

    let round_key = crypto::derive_round_secret(send_request.round, &shared_server_secrets)
        .map_err(|e| SGX_ERROR_INVALID_PARAMETER)?;

    println!("round_key derived: {}", round_key);

    // encrypt the message with round_key
    let encrypted_msg = round_key.encrypt(&send_request.msg);

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
    Ok(mutable)
}

use sgx_types::sgx_status_t::SGX_SUCCESS;
use sgx_types::{SgxError, SgxResult};
use utils::{unseal_ptr_and_deser, unseal_vec_and_deser};

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
    // Deser and unseal everything
    let send_request = unmarshal_or_abort!(UserSubmissionReq, send_request_ptr, send_request_len);
    let tee_signing_sk = unseal_or_abort!(
        SgxSigningKey,
        sealed_tee_prv_key_ptr,
        sealed_tee_prv_key_len
    );
    let shared_server_secrets = unseal_vec_or_abort!(
        SharedSecretsWithAnyTrustGroup,
        &send_request.shared_secrets.sealed_server_secrets
    );

    // Forward ecall to the internal call
    let signed_msg = unwrap_or_abort!(
        user_submit_internal(&send_request, &tee_signing_sk, &shared_server_secrets,),
        SGX_ERROR_INVALID_PARAMETER
    );

    // Write to user land
    match utils::serialize_to_ptr(&signed_msg, output, output_size, output_bytes_written) {
        Ok(_) => SGX_SUCCESS,
        Err(e) => e,
    }
}
