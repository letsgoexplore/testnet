use crate::util::{AggregatorError, Result};

use ed25519_dalek::{SecretKey, PublicKey};
use rand::rngs::OsRng;
use sha2::Sha512;

use interface::{EntityId, AggRegistrationBlob};
use common::types_nosgx::{AggRegistrationBlobNoSGX};
use common::funcs_nosgx::{pk_to_entityid};

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