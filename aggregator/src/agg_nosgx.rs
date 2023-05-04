use crate::util::{AggregatorError, Result};

use ed25519_dalek::{SecretKey, PublicKey};
use rand::rngs::OsRng;
use sha2::Sha512;

use interface::{
    EntityId,
    RateLimitNonce,
};
use common::types_nosgx::{
    AggRegistrationBlobNoSGX,
    AggregatedMessage,
    SignableNoSGX,
    SignMutableNoSGX,
    XorNoSGX,
};
use common::funcs_nosgx::{pk_to_entityid};
use std::collections::BTreeSet;

use log::{error, debug, warn};

/// Create a new secret key for an aggregator.
/// Returns secret key, entity id, and an AggRegistrationBlobNoSGX that contains the
/// information to send to anytrust nodes.
pub fn new_aggregator() -> Result<(SecretKey, EntityId, AggRegistrationBlobNoSGX)> {
    let mut csprng = match OsRng::new() {
        Ok(val) => val,
        Err(e) => {
            error!("Rand OsRng error:{:?}", e);
            return Err(AggregatorError::InvalidParameter);
        }
    };
    let sk = SecretKey::generate(&mut csprng);
    // The standard hash function used for most ed25519 libraries is SHA-512
    let pk = PublicKey::from_secret::<Sha512>(&sk);

    let blob = AggRegistrationBlobNoSGX {
        pk,
        role: "agg".to_string(),
    };

    Ok((
        sk,
        pk_to_entityid(&pk),
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
    new_input: &AggregatedMessage,
    signing_key: &SecretKey,
) -> Result<()> {
    let (new_agg, new_observed_nonces) = add_to_agg((new_input, agg, observed_nonces, signing_key))?;

    // Update the agg and nonces
    *agg = new_agg;
    *observed_nonces = new_observed_nonces;

    Ok(())
}

fn add_to_agg(
    input: (
        &AggregatedMessage,
        &AggregatedMessage,
        &Option<BTreeSet<RateLimitNonce>>,
        &SecretKey,
    ),
) -> Result<(AggregatedMessage, Option<BTreeSet<RateLimitNonce>>)> {
    let (incoming_msg, current_aggregation, observed_nonces, sk) = input;

    // Error if asked to add an empty msg to an empty aggregation
    if current_aggregation.is_empty() && incoming_msg.is_empty() {
        error!("cannot add an empty message to an emtpy aggregate");
        return Err(AggregatorError::InvalidParameter);
    }

    // if incoming_msg is empty we just return the current aggregation as is. No op.
    if incoming_msg.is_empty() {
        warn!("empty incoming_msg. not changing the aggregation");
        return Ok((current_aggregation.clone(), observed_nonces.clone()));
    }

    // now we are sure incoming_msg is not empty we treat it as untrusted input and verify signature
    match incoming_msg.verify() {
        Ok(()) => {
            debug!("signature verification succeeded");
        },
        Err(e) => {
            error!("can't verify sig on incoming_msg: {:?}", e);
            return Err(AggregatorError::InvalidParameter);
        }
    }

    // If the set of rate-limit nonces is Some, see if the given nonce appears in it. If so, this
    // message is dropped. If not, add the nonce to the set. If no nonce is provided, error.
    let new_observed_nonces = if let Some(observed_nonces) = observed_nonces {
        if let Some(ref nonce) = incoming_msg.rate_limit_nonce {
            // We reject messages whose nonces have been seen before
            if observed_nonces.contains(nonce) {
                error!("duplicate rate limit nonce detected");
                return Err(AggregatorError::InvalidParameter);
            }

            // No duplicate was found. Add this nonce to the set
            let mut new_set = observed_nonces.clone();
            new_set.insert(nonce.clone());
            Some(new_set)
        } else {
            error!("no rate limit nonce provided");
            return Err(AggregatorError::InvalidParameter);
        }
    } else {
        None
    };

    // if the current aggregation is empty we create a single-msg aggregation
    if current_aggregation.is_empty() {
        debug!("current aggregation is emtpy");
        let mut agg = incoming_msg.clone();
        match agg.sign_mut(&sk) {
            Ok(()) => (),
            Err(e) => {
                error!("can't sign on aggregation: {:?}", e);
                return Err(AggregatorError::InvalidParameter);
            }
        };
        return Ok((incoming_msg.clone(), new_observed_nonces));
    } else {
        // now that we know both current_aggregation and incoming_msg are not empty
        // we first validate they match
        let mut current_aggregation = current_aggregation.clone();
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

        debug!("✅ various checks passed now we can aggregate");
        debug!("incoming msg: {:?}", incoming_msg);
        debug!("current agg: {:?}", current_aggregation);

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

        Ok((current_aggregation, new_observed_nonces))
    }
}