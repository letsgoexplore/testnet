use crypto::Signable;
use crypto::*;
use interface::*;
use messages_types::AggregatedMessage;
use sgx_types::SgxResult;
use std::prelude::v1::*;
use types::*;

use crate::unseal::{UnmarshalledAs, UnsealableInto};
use sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
use sgx_types::sgx_status_t::{SGX_ERROR_SERVICE_UNAVAILABLE, SGX_SUCCESS};
use std::collections::BTreeSet;
use unseal::MarshallAs;

pub fn add_to_aggregate_internal(
    input: &(
        RoundSubmissionBlob,
        SignedPartialAggregate,
        Option<BTreeSet<RateLimitNonce>>,
        SealedSigPrivKey,
    ),
) -> SgxResult<(SignedPartialAggregate, Option<BTreeSet<RateLimitNonce>>)> {
    let (incoming_msg, current_aggregation, observed_nonces, sealed_sk) = input;

    // Error if asked to add an empty msg to an empty aggregation
    if current_aggregation.0.is_empty() && incoming_msg.0.is_empty() {
        error!("cannot add an empty message to an empty aggregate");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // If incoming_msg is empty we just return the current aggregation as is. No op.
    if incoming_msg.0.is_empty() {
        warn!("empty incoming_msg. not changing the aggregation");
        return Ok((current_aggregation.clone(), observed_nonces.clone()));
    }

    // now we are sure incoming_msg is not empty we treat it as untrusted input and verify signature
    let incoming_msg = incoming_msg.unmarshal()?;
    // FIXME: check incoming_msg.pk against a list of accepted public keys
    if !incoming_msg.verify()? {
        error!("can't verify sig on incoming_msg");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // If the set of rate-limit nonces is Some, see if the given nonce appears in it. If so, this
    // message is dropped. If not, add the nonce to the set. If no nonce is provided, error.
    let new_observed_nonces = if let Some(observed_nonces) = observed_nonces {
        if let Some(ref nonce) = incoming_msg.rate_limit_nonce {
            // We reject messages whose nonces have been seen before
            if observed_nonces.contains(nonce) {
                error!("duplicate rate limit nonce detected");
                return Err(SGX_ERROR_INVALID_PARAMETER);
            }
            // No duplicate was found. Add this nonce to the set
            let mut new_set = observed_nonces.clone();
            new_set.insert(nonce.clone());
            Some(new_set)
        } else {
            error!("no rate limit nonce provided");
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
    } else {
        None
    };

    let tee_signing_key = sealed_sk.unseal_into()?;

    // if the current aggregation is empty we create a single-msg aggregation
    if current_aggregation.0.is_empty() {
        let mut agg = incoming_msg.clone();
        agg.sign_mut(&tee_signing_key)?;
        return Ok((incoming_msg.marshal()?, new_observed_nonces));
    } else {
        // now that we know both current_aggregation and incoming_msg are not empty
        // we first validate they match
        let mut current_aggregation = current_aggregation.unmarshal()?;
        if current_aggregation.round != incoming_msg.round {
            error!("current_aggregation.round_info != incoming_msg.round_info");
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

        debug!("✅ various checks passed now we can aggregate");
        // debug!("incoming msg: {:?}", incoming_msg);
        // debug!("current agg: {:?}", current_aggregation);

        // aggregate in the new message
        current_aggregation.user_ids.extend(&incoming_msg.user_ids);
        current_aggregation
            .aggregated_msg
            .xor_mut(&incoming_msg.aggregated_msg);

        // sign
        current_aggregation.sign_mut(&tee_signing_key)?;

        debug!("✅ new agg with users {:?}", current_aggregation.user_ids);

        Ok((current_aggregation.marshal()?, new_observed_nonces))
    }
}
