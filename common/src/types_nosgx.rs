use ed25519_dalek::{
    SecretKey,
    PublicKey,
    Signature,
    Keypair,
    SECRET_KEY_LENGTH,
    PUBLIC_KEY_LENGTH,
    KEYPAIR_LENGTH,
    SIGNATURE_LENGTH,
    SignatureError
};
use serde::{Serialize, Deserialize};
use sha2::{Sha512};
use interface::{EntityId, RateLimitNonce, DcRoundMessage};
use std::{collections::BTreeSet, vec::Vec};

#[derive(Serialize, Debug, Deserialize)]
pub struct AggRegistrationBlobNoSGX {
    pub pk: PublicKey,
    pub role: std::string::String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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
impl Default for AggregatedMessageNoSGX {
    fn default() -> Self {
        AggregatedMessageNoSGX {
            round: Default::default(),
            anytrust_group_id: EntityId::default(),
            user_ids: BTreeSet::new(),
            rate_limit_nonce: None,
            aggregated_msg: DcRoundMessage::default(),
            sig: Signature::from_bytes(&[0u8;SIGNATURE_LENGTH]).unwrap(),
            pk: PublicKey::default(),
        }
    }
}


impl AggregatedMessageNoSGX {
    pub fn is_empty(&self) -> bool {
        self.user_ids.is_empty()
    }
}

pub trait SignableNoSGX {
    fn digest(&self) -> Vec<u8>;
    fn get_sig(&self) -> Signature;
    fn get_pk(&self) -> PublicKey;
    
    fn sign(&self, sk: &SecretKey) -> Result<(Signature, PublicKey), SignatureError> {
        let dig: Vec<u8> = self.digest();
        let pk = PublicKey::from_secret::<Sha512>(&sk);
        let sk_bytes: [u8; SECRET_KEY_LENGTH] = sk.to_bytes();
        let pk_bytes: [u8; PUBLIC_KEY_LENGTH] = pk.to_bytes();

        let mut keypair_bytes: [u8; KEYPAIR_LENGTH] = [0; KEYPAIR_LENGTH];
        keypair_bytes[..SECRET_KEY_LENGTH].copy_from_slice(&sk_bytes);
        keypair_bytes[SECRET_KEY_LENGTH..].copy_from_slice(&pk_bytes);

        let keypair: Keypair = Keypair::from_bytes(&keypair_bytes)?;
        let sig = keypair.sign::<Sha512>(dig.as_slice());

        Ok((sig, pk))
    }

    fn verify(&self) -> Result<(), SignatureError> {
        let msg_hash = self.digest();
        let pk = self.get_pk();
        pk.verify::<Sha512>(msg_hash.as_slice(), &self.get_sig())
    }
}

pub trait SignMutableNoSGX {
    fn sign_mut(&mut self, _: &SecretKey) -> Result<(), SignatureError>;
}

/// The state of an aggregator.
pub type SignedPartialAggregateNoSGX = AggregatedMessageNoSGX;

/// Contains a set of entity IDs along with the XOR of their round submissions. This is passed to
/// aggregators of all levels as well as anytrust nodes.
pub type RoundSubmissionBlobNoSGX = AggregatedMessageNoSGX;