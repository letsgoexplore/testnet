use crate::util::{AggregatorError, Result};

use ed25519_dalek::{SecretKey, PublicKey};
extern crate rand;
use rand::rngs::OsRng;

use interface::{
    EntityId,
    RateLimitNonce,
    UserSubmissionMessageUpdated,

};
use common::types_nosgx::{
    AggRegistrationBlobNoSGX,
    AggregatedMessage,
    SignableNoSGX,
    SignMutableNoSGX,
    XorNoSGX,
    SubmissionMessage,
};
use common::funcs_nosgx::verify_user_submission_msg;
use std::collections::BTreeSet;
use std::iter::FromIterator;

use log::{error, debug, warn};

/// Create a new secret key for an aggregator.
/// Returns secret key, entity id, and an AggRegistrationBlobNoSGX that contains the
/// information to send to anytrust nodes.
pub fn new_aggregator() -> Result<(SecretKey, EntityId, AggRegistrationBlobNoSGX)> {
    let mut csprng = OsRng{};
    let sk = SecretKey::generate(&mut csprng);
    // The standard hash function used for most ed25519 libraries is SHA-512
    let pk: PublicKey = (&sk).into();

    let blob = AggRegistrationBlobNoSGX {
        pk,
        role: "agg".to_string(),
    };

    Ok((
        sk,
        EntityId::from(&pk),
        blob,
    ))
}

/// TODO: Consider removing this function
/// Constructs an aggregate message from the given state. The returned blob is to be sent to
/// the parent aggregator or an anytrust server.
/// Note: this is an identity function because AggregatedMessage and AggregatedMessage
/// are exact the same thing.
pub fn finalize_aggregate(
    agg: &AggregatedMessage,
) -> Result<AggregatedMessage> {
    return Ok(agg.clone());
}

/// Adds the given input from a user to the given partial aggregate
/// Note: if marshalled_current_aggregation is empty (len = 0), an empty aggregation is created
///  and the signed message is aggregated into that.
pub fn add_to_aggregate(
    agg: &mut AggregatedMessage,
    observed_nonces: &mut Option<BTreeSet<RateLimitNonce>>,
    new_input: &SubmissionMessage,
    signing_key: &SecretKey,
) -> Result<()> {
    match new_input {
        SubmissionMessage::UserSubmission(new_input) => {
            add_to_agg_user_submit((new_input, agg, observed_nonces, signing_key))?;
        },
        SubmissionMessage::AggSubmission(new_input) => {
            add_to_agg((new_input, agg, observed_nonces, signing_key))?;
        }
    }

    Ok(())
}

fn add_to_agg(
    input: (
        &AggregatedMessage,
        &mut AggregatedMessage,
        &mut Option<BTreeSet<RateLimitNonce>>,
        &SecretKey,
    ),
) -> Result<()> {
    let (incoming_msg, current_aggregation, observed_nonces, sk) = input;

    // Error if asked to add an empty msg to an empty aggregation
    if current_aggregation.is_empty() && incoming_msg.is_empty() {
        error!("cannot add an empty message to an emtpy aggregate");
        return Err(AggregatorError::InvalidParameter);
    }

    // if incoming_msg is empty we just return the current aggregation as is. No op.
    if incoming_msg.is_empty() {
        warn!("empty incoming_msg. not changing the aggregation");
        return Ok(());
    }

    // now we are sure incoming_msg is not empty we treat it as untrusted input and verify signature
    match incoming_msg.verify() {
        Ok(()) => {
            // debug!("signature verification succeeded");
        },
        Err(e) => {
            error!("can't verify sig on incoming_msg: {:?}", e);
            return Err(AggregatorError::InvalidParameter);
        }
    }

    // If the set of rate-limit nonces is Some, see if the given nonce appears in it. If so, this
    // message is dropped. If not, add the nonce to the set. If no nonce is provided, error.
    if let Some(observed_nonces) = observed_nonces {
        if let Some(ref nonce) = incoming_msg.rate_limit_nonce {
            // We reject messages whose nonces have been seen before
            if observed_nonces.contains(nonce) {
                error!("duplicate rate limit nonce detected");
                return Err(AggregatorError::InvalidParameter);
            }

            // No duplicate was found. Add this nonce to the set
            observed_nonces.insert(nonce.clone());
        } else {
            error!("no rate limit nonce provided");
            return Err(AggregatorError::InvalidParameter);
        }
    }

    // if the current aggregation is empty we create a single-msg aggregation
    if current_aggregation.is_empty() {
        debug!("current aggregation is emtpy");
        let incoming_msg_clone = incoming_msg.clone();
        current_aggregation.round = incoming_msg_clone.round;
        current_aggregation.anytrust_group_id = incoming_msg_clone.anytrust_group_id;
        current_aggregation.user_ids=incoming_msg_clone.user_ids.clone();
        current_aggregation.rate_limit_nonce = incoming_msg_clone.rate_limit_nonce;
        current_aggregation.aggregated_msg = incoming_msg_clone.aggregated_msg;
        current_aggregation.sig = incoming_msg_clone.sig;
        current_aggregation.pk = incoming_msg_clone.pk;

        current_aggregation.sign_mut(&sk).map_err(|e| {
            error!("can't sign on aggregation: {:?}", e);
            AggregatorError::InvalidParameter
        })?;
        return Ok(());
    } else {
        // now that we know both current_aggregation and incoming_msg are not empty
        // we first validate they match
        if current_aggregation.round != incoming_msg.round {
            error!("current_aggregation.round != incoming_msg.round");
            return Err(AggregatorError::InvalidParameter);
        }

        if current_aggregation.anytrust_group_id != incoming_msg.anytrust_group_id {
            error!("current_aggregation.anytrust_group_id != incoming_msg.anytrust_group_id");
            return Err(AggregatorError::InvalidParameter);
        }

        if !current_aggregation
            .user_ids
            .is_disjoint(&incoming_msg.user_ids)
        {
            error!("current_aggregation.user_ids overlap with incoming_msg.user_ids");
            return Err(AggregatorError::InvalidParameter);
        }

        // debug!("✅ various checks passed now we can aggregate");
        // debug!("incoming msg: {:?}", incoming_msg);
        // debug!("current agg: {:?}", current_aggregation);

        // aggregate in the new message
        current_aggregation.user_ids.extend(&incoming_msg.user_ids);
        current_aggregation
            .aggregated_msg
            .xor_mut_nosgx(&incoming_msg.aggregated_msg);

        // sign
        match current_aggregation.sign_mut(&sk){
            Ok(()) => (),
            Err(e) => {
                error!("can't sign on current aggregation: {:?}", e);
                return Err(AggregatorError::InvalidParameter);
            }
        };

        debug!("✅ new agg with users {:?}", current_aggregation.user_ids);

        Ok(())
    }
}

fn add_to_agg_user_submit(
    input: (
        &UserSubmissionMessageUpdated,
        &mut AggregatedMessage,
        &mut Option<BTreeSet<RateLimitNonce>>,
        &SecretKey,
    ),
) -> Result<()> {
    let (incoming_msg, current_aggregation, observed_nonces, sk) = input;

    // Error if asked to add an empty msg to an empty aggregation
    if current_aggregation.is_empty() && incoming_msg.is_empty() {
        error!("cannot add an empty message to an empty aggregate");
        return Err(AggregatorError::InvalidParameter);
    }

    // If incoming_msg is empty we just return the current aggregation as is. No op.
    if incoming_msg.is_empty() {
        warn!("empty incoming_msg. not changing the aggregation");
        return Ok(());
    }

    // now we are sure incoming_msg is not empty we treat it as untrusted input and verify signature
    match verify_user_submission_msg(&incoming_msg) {
        Ok(()) => {
            // debug!("signature verification succeeded");
        },
        Err(e) => {
            error!("can't verify sig on incoming_msg: {:?}", e);
            return Err(AggregatorError::InvalidParameter);
        }
    }

    // If the set of rate-limit nonces is Some, see if the given nonce appears in it. If so, this
    // message is dropped. If not, add the nonce to the set. If no nonce is provided, error.
    if let Some(observed_nonces) = observed_nonces {
        if let Some(ref nonce) = incoming_msg.rate_limit_nonce {
            // We reject messages whose nonces have been seen before
            if observed_nonces.contains(nonce) {
                error!("duplicate rate limit nonce detected");
                return Err(AggregatorError::InvalidParameter);
            }
            // No duplicate was found. Add this nonce to the set
            observed_nonces.insert(nonce.clone());
        } else {
            error!("no rate limit nonce provided");
            return Err(AggregatorError::InvalidParameter);
        }
    }

    // if the current aggregation is empty we create a single-msg aggregation
    if current_aggregation.is_empty() {
        let incoming_msg_clone = incoming_msg.clone();
        current_aggregation.round = incoming_msg_clone.round;
        current_aggregation.anytrust_group_id = incoming_msg_clone.anytrust_group_id;
        current_aggregation.user_ids.insert(incoming_msg_clone.user_id.clone());
        current_aggregation.rate_limit_nonce = incoming_msg_clone.rate_limit_nonce;
        current_aggregation.aggregated_msg = incoming_msg_clone.aggregated_msg;
        current_aggregation.sign_mut(&sk).map_err(|e| {
            error!("can't sign on aggregation: {:?}", e);
            AggregatorError::InvalidParameter
        })?;
        return Ok(());
    } else {
        // now that we know both current_aggregation and incoming_msg are not empty
        // we first validate they match
        if current_aggregation.round != incoming_msg.round {
            error!("current_aggregation.round_info != incoming_msg.round_info");
            return Err(AggregatorError::InvalidParameter);
        }

        if current_aggregation.anytrust_group_id != incoming_msg.anytrust_group_id {
            error!("current_aggregation.anytrust_group_id != incoming_msg.anytrust_group_id");
            return Err(AggregatorError::InvalidParameter);
        }

        if current_aggregation
            .user_ids
            .contains(&incoming_msg.user_id)
        {
            error!("current_aggregation.user_ids overlap with incoming_msg.user_id");
            return Err(AggregatorError::InvalidParameter);
        }

        // debug!("✅ various checks passed now we can aggregate");
        // debug!("incoming msg: {:?}", incoming_msg);
        // debug!("current agg: {:?}", current_aggregation);

        // aggregate in the new message
        current_aggregation.user_ids.insert(incoming_msg.user_id.clone());
        current_aggregation
            .aggregated_msg
            .xor_mut_nosgx(&incoming_msg.aggregated_msg);

        // sign
        match current_aggregation.sign_mut(&sk) {
            Ok(()) => (),
            Err(e) => {
                error!("can't sign on aggregation: {:?}", e);
                return Err(AggregatorError::InvalidParameter);
            }
        };

        Ok(())
    }   
}
