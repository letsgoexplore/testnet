extern crate interface;
extern crate sgx_types;

use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED};

use std::prelude::v1::*;

use sgx_types::SgxResult;

use crypto;
use crypto::{SgxPrivateKey, SharedSecretsWithAnyTrustGroup, SignMutable};

use self::interface::*;

use interface::UserSubmissionReq;
use messages_types::SignedUserMessage;

use utils;

use std::convert::TryFrom;
use utils::serialize_to_vec;

pub fn user_submit_internal(
    input: &(UserSubmissionReq, SealedKey),
) -> SgxResult<MarshalledSignedUserMessage> {
    let (send_request, sealed_key) = input;
    println!("got request {:?}", send_request);

    // 1) TODO: check ticket first
    println!("[WARN] NOT checking ticket ATM");

    // 2) unseal private key
    let sk: SgxPrivateKey = utils::unseal_vec_and_deser(&sealed_key.sealed_sk)?;
    let pk = SgxProtectedKeyPub::try_from(&sk)?;
    println!("using signing (pub) key {}", pk);

    if send_request.user_id != EntityId::from(&pk) {
        println!("send_request.user_id != EntityId::from(&pk)");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // 3) derive the round key from shared secrets
    let shared_secrets: SharedSecretsWithAnyTrustGroup =
        utils::unseal_vec_and_deser(&send_request.shared_secrets.sealed_server_secrets)?;

    if shared_secrets.user_id != send_request.user_id {
        println!("shared_secrets.user_id != send_request.user_id");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    if shared_secrets.anytrust_group_id() != send_request.anytrust_group_id {
        println!("shared_secrets.anytrust_group_id() != send_request.anytrust_group_id");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    println!(
        "using {} servers",
        shared_secrets.anytrust_group_pairwise_keys.len()
    );

    let round_key = crypto::derive_round_secret(send_request.round, &shared_secrets)
        .map_err(|_e| SGX_ERROR_INVALID_PARAMETER)?;

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
    if mutable.sign_mut(&sk).is_err() {
        println!("can't sign");
        return Err(SGX_ERROR_UNEXPECTED);
    }

    println!("signed user message {:?}", mutable);

    // serialized
    Ok(MarshalledSignedUserMessage(serialize_to_vec(&mutable)?))
}
