use crypto::Signable;
use crypto::*;
use interface::*;
use messages_types::AggregatedMessage;
use sgx_types::SgxResult;
use std::prelude::v1::*;
use types::*;

use crate::unseal::{UnmarshalledAs, UnsealableAs};
use sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
use sgx_types::sgx_status_t::SGX_SUCCESS;
use std::collections::BTreeSet;
use unseal::MarshallAs;

pub fn add_to_aggregate_internal(
    input: &(
        RoundSubmissionBlob,
        SignedPartialAggregate,
        SealedSigPrivKey,
    ),
) -> SgxResult<SignedPartialAggregate> {
    let (incoming_msg, current_aggregation, sealed_sk) = input;

    // unmarshal
    let mut current_aggregation = current_aggregation.unmarshal()?;

    // if incoming_msg is empty just return the current aggregation. No op.
    if incoming_msg.0.is_empty() {
        warn!("empty incoming_msg");
        return current_aggregation.marshal();
    }

    // unmarshal and unseal
    let incoming_msg = incoming_msg.unmarshal()?;
    let tee_signing_key = sealed_sk.unseal()?;

    // verify signature
    // FIXME: check incoming_msg.pk against a list of accepted public keys
    if !incoming_msg.verify()? {
        error!("can't verify sig on incoming_msg");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // we treat an agg with an empty user id list as uninitialized. We initialize it with the
    // incoming transaction.
    if current_aggregation.user_ids.is_empty() {
        current_aggregation.round = incoming_msg.round;
        current_aggregation.anytrust_group_id = incoming_msg.anytrust_group_id;
    } else {
        if current_aggregation.round != incoming_msg.round {
            error!("current_aggregation.round != incoming_msg.round");
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }

        if current_aggregation.anytrust_group_id != incoming_msg.anytrust_group_id {
            error!("current_aggregation.anytrust_group_id != incoming_msg.anytrust_group_id");
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }

        if !current_aggregation
            .user_ids
            .is_disjoint(&incoming_msg.user_ids)
        {
            error!("current_aggregation.user_ids overlap with incoming_msg.user_ids");
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
    }

    // aggregate in the new message
    current_aggregation.user_ids.extend(&incoming_msg.user_ids);
    current_aggregation
        .aggregated_msg
        .xor_mut(&incoming_msg.aggregated_msg);

    // sign
    current_aggregation.sign_mut(&tee_signing_key)?;

    debug!("new agg with users {:?}", current_aggregation.user_ids);

    current_aggregation.marshal()
}
