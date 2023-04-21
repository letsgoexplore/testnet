use ed25519_dalek::{PublicKey, Signature, SecretKey};
use serde::{Serialize, Deserialize};

use interface::{EntityId, RateLimitNonce, DcRoundMessage};
use std::{collections::BTreeSet, vec::Vec};

#[derive(Serialize, Debug, Deserialize)]
pub struct AggRegistrationBlobNoSGX {
    pub pk: PublicKey,
    pub role: std::string::String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AggregatedMessageNoSGX {
    pub round: u32,
    pub anytrust_group_id: EntityId,
    pub user_ids: BTreeSet<EntityId>,
    /// This is only Some for user-submitted messages
    pub rate_limit_nonce: Option<RateLimitNonce>,
    pub aggregated_msg: DcRoundMessage,
    pub sig: Signature,
    pub pk: PublicKey,
}

impl AggregatedMessageNoSGX {
    pub fn is_empty(&self) -> bool {
        self.user_ids.is_empty()
    }
}

