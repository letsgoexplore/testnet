use crate::util::{AggregatorError, Result};

use ed25519_dalek::{SecretKey, PublicKey};
use rand::rngs::OsRng;
use sha2::Sha512;

use interface::{EntityId};
use common::types_nosgx::{
    AggRegistrationBlobNoSGX,
    SignedPartialAggregateNoSGX,
    RoundSubmissionBlobNoSGX,
};
use common::funcs_nosgx::{pk_to_entityid};


/// Create a new secret key for an aggregator.
/// Returns secret key, entity id, and an AggRegistrationBlobNoSGX that contains the
/// information to send to anytrust nodes.
pub fn new_aggregator() -> Result<(SecretKey, EntityId, AggRegistrationBlobNoSGX)> {
    let mut csprng = OsRng::new().unwrap();
    let sk = SecretKey::generate(&mut csprng);
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

/// Makes an empty aggregation state for the given round and wrt the given anytrust nodes
pub fn new_aggregate(
    _round: u32,
    _anytrust_group_id: &EntityId,
) -> Result<SignedPartialAggregateNoSGX> {
    // A new aggregator is simply an empty blob
    Ok(Default::default())    
}

/// Constructs an aggregate message from the given state. The returned blob is to be sent to
/// the parent aggregator or an anytrust server.
/// Note: this is an identity function because SignedPartialAggregateNoSGX and RoundSubmissionBlobNoSGX
/// are exact the same thing.
pub fn finalize_aggregate(
    agg: &SignedPartialAggregateNoSGX,
) -> Result<RoundSubmissionBlobNoSGX> {
    return Ok(agg.clone());
}
