use crate::interface::*;
use crypto::{SgxSignature, Signable};
use std::vec::Vec;

#[serde(crate = "serde")]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AggregatedMessage {
    pub user_ids: Vec<EntityId>,
    // pub group id
    pub aggregated_msg: DcMessage,
    pub round: u32,
    pub tee_sig: SgxSignature,
    pub tee_pk: SgxSigningPubKey,
}

use types::Zero;

impl Zero for AggregatedMessage {
    fn zero() -> Self {
        AggregatedMessage {
            user_ids: Vec::new(),
            aggregated_msg: DcMessage::zero(),
            round: 0,
            tee_sig: SgxSignature::default(),
            tee_pk: SgxSigningPubKey::default(),
        }
    }
}

use sha2::Digest;
use sha2::Sha256;

impl Signable for AggregatedMessage {
    fn digest(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        for id in self.user_ids.iter() {
            hasher.input(id);
        }
        hasher.input(&self.aggregated_msg);

        hasher.result().to_vec()
    }

    fn get_sig(&self) -> SgxSignature {
        self.tee_sig
    }

    fn get_pk(&self) -> SgxSigningPubKey {
        self.tee_pk
    }
}
