use crate::interface::*;
use crypto::Signable;
use std::vec::Vec;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AggregatedMessage {
    pub user_ids: Vec<UserId>,
    pub aggregated_msg: DCMessage,
    pub round: u32,
    pub tee_sig: Signature,
    pub tee_pk: PubKey,
}

impl Zero for AggregatedMessage {
    fn zero() -> Self {
        AggregatedMessage {
            user_ids: Vec::new(),
            aggregated_msg: DCMessage::zero(),
            round: 0,
            tee_sig: Signature::default(),
            tee_pk: PubKey::default(),
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

    fn get_sig(&self) -> Signature {
        self.tee_sig
    }

    fn get_pk(&self) -> PubKey {
        self.tee_pk
    }
}
