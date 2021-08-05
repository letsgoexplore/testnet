extern crate interface;
extern crate sgx_types;
use self::interface::*;
use crate::messages_types::AggregatedMessage;
use crate::types::UnsealableAs;
use crate::types::Xor;
use core::convert::TryInto;
use crypto;
use crypto::{SgxPrivateKey, SharedSecretsDb, SignMutable};
use interface::UserSubmissionReq;
use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED};
use sgx_types::SgxResult;
use std::convert::TryFrom;
use std::debug;
use std::prelude::v1::*;
use utils::serialize_to_vec;

pub fn user_submit_internal(
    input: &(UserSubmissionReq, SealedSigPrivKey),
) -> SgxResult<RoundSubmissionBlob> {
    let send_request = &input.0;

    // 1) TODO: check ticket first
    warn!("NOT checking ticket ATM");

    // 2) unseal signing key
    let sk = input.1.unseal()?;
    let pk = SgxProtectedKeyPub::try_from(&sk)?;
    debug!("using signing (pub) key {}", pk);

    if send_request.user_id != EntityId::from(&pk) {
        error!("send_request.user_id != EntityId::from(&pk)");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // 3) derive the round key from shared secrets
    let shared_secrets = send_request.shared_secrets.unseal()?;
    if shared_secrets.anytrust_group_id() != send_request.anytrust_group_id {
        error!("shared_secrets.anytrust_group_id() != send_request.anytrust_group_id");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    let round_key = crypto::derive_round_secret(send_request.round, &shared_secrets)
        .map_err(|_e| SGX_ERROR_INVALID_PARAMETER)?;

    // encrypt the message with round_key
    let encrypted_msg = round_key.xor(&send_request.msg);

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
        error!("can't sign");
        return Err(SGX_ERROR_UNEXPECTED);
    }

    // serialized
    Ok(RoundSubmissionBlob(serialize_to_vec(&mutable)?))
}
