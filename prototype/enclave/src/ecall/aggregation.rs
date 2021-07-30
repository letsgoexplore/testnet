use crypto::*;
use interface::*;
use messages_types::AggregatedMessage;
use sgx_types::SgxResult;
use std::prelude::v1::*;
use types::*;
use crypto::Signable;

use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER};
use utils;



pub fn add_to_aggregate_internal(
    input: &(RoundSubmissionBlob, SignedPartialAggregate, SealedSigPrivKey)
) -> SgxResult<SignedPartialAggregate> {
    // let (incoming_msg, current_aggregation, sealed_sk) = input;

    let incoming_msg: AggregatedMessage = utils::deserialize_from_vec(&input.0.0)?;
    if incoming_msg.user_ids.len() != 1 {
        error!("incoming message is already aggregated. This interface only accept user submission");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // if input.1.0.is_empty(), we create a new aggregation
    // input.1 is a MarshalledSignedUserMessage
    // input.1.0 is the vec contained in a MarshalledSignedUserMessage
    let current_aggregation = if !input.1.0.is_empty() {
        utils::deserialize_from_vec(&input.1.0)?
    } else {
        AggregatedMessage {
            round: incoming_msg.round,
            anytrust_group_id: incoming_msg.anytrust_group_id,
            user_ids: vec![],
            aggregated_msg: DcMessage([0u8; DC_NET_MESSAGE_LENGTH]),
            tee_sig: Default::default(),
            tee_pk: Default::default(),
        }
    };

    let tee_signing_sk: SgxSigningKey = utils::unseal_vec_and_deser(&input.2.0.sealed_sk)?;

    // verify signature
    if !incoming_msg.verify()? {
        error!("can't verify sig on incoming_msg");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // FIXME: check incoming_msg.pk against a list of accepted public keys

    if incoming_msg.round != current_aggregation.round {
        error!("incoming_msg.round != agg.round");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // we already checked that incoming_msg.user_ids has only one element
    if current_aggregation.user_ids.contains(&incoming_msg.user_ids[0]) {
        error!("user already in");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // create a new aggregation
    let mut new_agg = current_aggregation.clone();

    // aggregate in the new message
    new_agg.user_ids.push(incoming_msg.user_ids[0]);
    new_agg
        .aggregated_msg
        .xor_mut(&DcMessage(incoming_msg.aggregated_msg.0));

    // sign
    new_agg.sign_mut(&tee_signing_sk)?;

    debug!("new agg: {:?}", new_agg.user_ids);

    Ok(SignedPartialAggregate(utils::serialize_to_vec(&new_agg)?))
}