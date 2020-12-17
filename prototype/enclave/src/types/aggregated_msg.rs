use super::*;
use crate::interface::*;
use std::vec::Vec;

#[derive(Serializable, DeSerializable, Clone)]
pub struct AggregatedMessage {
    pub user_ids: Vec<UserId>,
    pub aggregated_msg: DCMessage,
    // pub tee_sig: Signature,
    // pub tee_pk: PubKey,
}

impl Zero for AggregatedMessage {
    fn zero() -> Self {
        AggregatedMessage {
            user_ids: Vec::new(),
            aggregated_msg: DCMessage::zero(),
            // tee_sig: Signature::default(),
            // tee_pk: PubKey::default()
        }
    }
}
