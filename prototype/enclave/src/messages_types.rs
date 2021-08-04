use crypto::SgxSignature;
use interface::{DcMessage, EntityId, SgxSigningPubKey};
use std::vec::Vec;

/// A (potentially aggregated) message that's produced by an enclaave
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AggregatedMessage {
    pub round: u32,
    pub anytrust_group_id: EntityId,
    pub user_ids: Vec<EntityId>,
    pub aggregated_msg: DcMessage,
    pub tee_sig: SgxSignature,
    pub tee_pk: SgxSigningPubKey,
}

use types::Zero;

impl Zero for AggregatedMessage {
    fn zero() -> Self {
        AggregatedMessage {
            round: 0,
            anytrust_group_id: EntityId::default(),
            user_ids: Vec::new(),
            aggregated_msg: DcMessage::zero(),
            tee_sig: SgxSignature::default(),
            tee_pk: SgxSigningPubKey::default(),
        }
    }
}

use crypto::SgxSigningKey;
use crypto::{SignMutable, Signable};
use sgx_types::SgxError;
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

impl SignMutable for AggregatedMessage {
    fn sign_mut(&mut self, sk: &SgxSigningKey) -> SgxError {
        let (sig, pk) = self.sign(sk)?;
        self.tee_pk = pk;
        self.tee_sig = sig;

        Ok(())
    }
}
