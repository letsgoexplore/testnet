extern crate interface;
extern crate sgx_types;
use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED};
use std::prelude::v1::*;
use sgx_types::SgxResult;
use crypto;
use crypto::{SgxPrivateKey, SharedSecretsWithAnyTrustGroup, SignMutable};
use crate::messages_types::AggregatedMessage;
use self::interface::*;
use interface::UserSubmissionReq;
use utils;
use std::convert::TryFrom;
use utils::serialize_to_vec;

pub fn user_submit_internal(
    input: &(UserSubmissionReq, SealedSigPrivKey),
) -> SgxResult<RoundSubmissionBlob> {
    let (send_request, sealed_key) = input;

    // 1) TODO: check ticket first
    warn!("NOT checking ticket ATM");

    // 2) unseal private key
    let sk: SgxPrivateKey = utils::unseal_vec_and_deser(&sealed_key.0.sealed_sk)?;
    let pk = SgxProtectedKeyPub::try_from(&sk)?;
    debug!("using signing (pub) key {}", pk);

    if send_request.user_id != EntityId::from(&pk) {
        error!("send_request.user_id != EntityId::from(&pk)");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // 3) derive the round key from shared secrets
    let shared_secrets: SharedSecretsWithAnyTrustGroup =
        utils::unseal_vec_and_deser(&send_request.shared_secrets.sealed_server_secrets)?;

    if shared_secrets.user_id != send_request.user_id {
        error!("shared_secrets.user_id != send_request.user_id");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    if shared_secrets.anytrust_group_id() != send_request.anytrust_group_id {
        error!("shared_secrets.anytrust_group_id() != send_request.anytrust_group_id");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    let round_key = crypto::derive_round_secret(send_request.round, &shared_secrets)
        .map_err(|_e| SGX_ERROR_INVALID_PARAMETER)?;

    // encrypt the message with round_key
    let encrypted_msg = round_key.encrypt(&send_request.msg);

    // FIXME: add missing default fields
    let mut mutable = AggregatedMessage {
        user_ids: vec![send_request.user_id],
        anytrust_group_id: send_request.anytrust_group_id,
        round: send_request.round,
        tee_sig: Default::default(),
        tee_pk: Default::default(),
        aggregated_msg: encrypted_msg,
    };

    // sign
    if mutable.sign_mut(&sk).is_err() {
        println!("can't sign");
        return Err(SGX_ERROR_UNEXPECTED);
    }

    // serialized
    Ok(RoundSubmissionBlob(serialize_to_vec(&mutable)?))
}
