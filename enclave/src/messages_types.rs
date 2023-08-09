use crypto::SgxSigningKey;
use crypto::{SignMutable, Signable};
use crypto::SignMutableUpdated;
use interface::{RoundSecret, SgxSignature, SgxSigningPubKey, NoSgxPrivateKey, NoSgxSignature};
use sgx_types::SgxError;
use sha2::Digest;
use sha2::Sha256;
use std::vec::Vec;

use ed25519_dalek::PublicKey;

// /// A (potentially aggregated) message that's produced by an enclave
// #[derive(Serialize, Deserialize, Clone, Debug, Default)]
// pub struct AggregatedMessageObsolete {
//     pub round: u32,
//     pub anytrust_group_id: EntityId,
//     pub user_ids: BTreeSet<EntityId>,
//     /// This is only Some for user-submitted messages
//     pub rate_limit_nonce: Option<RateLimitNonce>,
//     pub aggregated_msg: DcRoundMessage,
//     pub tee_sig: SgxSignature,
//     pub tee_pk: SgxSigningPubKey,
// }

use interface::AggregatedMessageObsolete;

impl Signable for AggregatedMessageObsolete {
    fn digest(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.input(b"Begin AggregatedMessageObsolete");
        hasher.input(&self.anytrust_group_id);
        for id in self.user_ids.iter() {
            hasher.input(id);
        }
        hasher.input(&self.aggregated_msg.digest());
        hasher.input(b"End AggregatedMessageObsolete");

        hasher.result().to_vec()
    }

    fn get_sig(&self) -> SgxSignature {
        self.tee_sig
    }

    fn get_pk(&self) -> SgxSigningPubKey {
        self.tee_pk
    }
}

impl SignMutable for AggregatedMessageObsolete {
    fn sign_mut(&mut self, sk: &SgxSigningKey) -> SgxError {
        let (sig, pk) = self.sign(sk)?;
        self.tee_pk = pk;
        self.tee_sig = sig;

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UnblindedAggregateShare {
    pub encrypted_msg: AggregatedMessageObsolete,
    pub key_share: RoundSecret,
    pub sig: SgxSignature,
    pub pk: SgxSigningPubKey,
}

impl Signable for UnblindedAggregateShare {
    fn digest(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.input(b"Begin UnblindedAggregateShare");
        hasher.input(self.encrypted_msg.digest());
        hasher.input(self.key_share.digest());
        hasher.input(b"End UnblindedAggregateShare");

        hasher.result().to_vec()
    }

    fn get_sig(&self) -> SgxSignature {
        self.sig
    }

    fn get_pk(&self) -> SgxSigningPubKey {
        self.pk
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


use interface::{UserSubmissionMessage, UserSubmissionMessageUpdated, SignableUpdated};
use sgx_types::sgx_status_t::SGX_ERROR_UNEXPECTED;

impl Signable for UserSubmissionMessage {
    fn digest(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.input(b"Begin UserSubmissionMessage");
        hasher.input(&self.anytrust_group_id);
        // for id in self.user_ids.iter() {
        //     hasher.input(id);
        // }
        hasher.input(self.user_id);
        hasher.input(&self.aggregated_msg.digest());
        hasher.input(b"End UserSubmissionMessage");

        hasher.result().to_vec()
    }

    fn get_sig(&self) -> SgxSignature {
        self.tee_sig
    }

    fn get_pk(&self) -> SgxSigningPubKey {
        self.tee_pk
    }
}

impl SignMutable for UserSubmissionMessage {
    fn sign_mut(&mut self, sk: &SgxSigningKey) -> SgxError {
        let (sig, pk) = self.sign(sk)?;
        self.tee_pk = pk;
        self.tee_sig = sig;

        Ok(())
    }
}

impl SignMutableUpdated for UserSubmissionMessageUpdated {
    fn sign_mut_updated(&mut self, sk: &NoSgxPrivateKey) -> SgxError {
        let (sig, pk) = self.sign(sk).expect("Signing the user submission message failed");
        self.tee_pk = pk;
        self.tee_sig = sig;

        Ok(())
    }
}