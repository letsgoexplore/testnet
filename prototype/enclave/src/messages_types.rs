use crypto::RoundSecret;
use crypto::SgxSigningKey;
use crypto::{SignMutable, Signable};
use interface::{
    DcMessage, DcRoundMessage, EntityId, SgxSignature, SgxSigningPubKey, DC_NET_N_SLOTS,
    FOOTPRINT_BIT_SIZE,
};
use sgx_tcrypto::SgxRsaPubKey;
use sgx_types::SgxError;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeSet;
use std::vec::Vec;

/// A (potentially aggregated) message that's produced by an enclave
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AggregatedMessage {
    pub round: u32,
    pub anytrust_group_id: EntityId,
    pub user_ids: BTreeSet<EntityId>,
    pub aggregated_msg: DcRoundMessage,
    pub tee_sig: SgxSignature,
    pub tee_pk: SgxSigningPubKey,
}

impl Default for AggregatedMessage {
    fn default() -> Self {
        AggregatedMessage {
            round: 0,
            anytrust_group_id: EntityId::default(),
            user_ids: BTreeSet::new(),
            aggregated_msg: DcRoundMessage::default(),
            tee_sig: SgxSignature::default(),
            tee_pk: SgxSigningPubKey::default(),
        }
    }
}

impl Signable for AggregatedMessage {
    fn digest(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.input(&self.anytrust_group_id);
        for id in self.user_ids.iter() {
            hasher.input(id);
        }
        hasher.input(&self.aggregated_msg.digest());

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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UnblindedAggregateShare {
    pub encrypted_msg: AggregatedMessage,
    pub key_share: RoundSecret,
    pub sig: SgxSignature,
    pub pk: SgxSigningPubKey,
}

impl Signable for UnblindedAggregateShare {
    fn digest(&self) -> Vec<u8> {
        warn!("sig not implemented");
        Default::default()
    }

    fn get_sig(&self) -> SgxSignature {
        warn!("sig not implemented");
        Default::default()
    }

    fn get_pk(&self) -> SgxSigningPubKey {
        warn!("sig not implemented");
        Default::default()
    }

    fn sign(&self, _ssk: &SgxSigningKey) -> sgx_types::SgxResult<(SgxSignature, SgxSigningPubKey)> {
        warn!("sig not implemented");
        Ok((Default::default(), Default::default()))
    }

    fn verify(&self) -> sgx_types::SgxResult<bool> {
        warn!("sig not implemented");
        Ok(true)
    }
}

impl SignMutable for UnblindedAggregateShare {
    fn sign_mut(&mut self, ssk: &SgxSigningKey) -> SgxError {
        let (sig, pk) = self.sign(ssk)?;
        self.sig = sig;
        self.pk = pk;

        Ok(())
    }
}
