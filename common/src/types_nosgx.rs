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
use sha2::{Digest, Sha256, Sha512};
use interface::{
    EntityId,
    RateLimitNonce,
    DcRoundMessage,
    UserSubmissionMessage,
    SgxProtectedKeyPub,
    AttestedPublicKey,
    ServerPubKeyPackageNoSGX,
    compute_anytrust_group_id,
};

use std::prelude::v1::*;
use std::collections::{BTreeSet, BTreeMap};
use crate::funcs_nosgx::pk_to_entityid;

use core::fmt::{Debug, Formatter};

use x25519_dalek::{
    SharedSecret,
    StaticSecret,
    PublicKey as xPublicKey,
};
use rand_os::OsRng;

#[derive(Clone, Serialize, Debug, Deserialize)]
pub struct AggRegistrationBlobNoSGX {
    pub pk: PublicKey,
    pub role: std::string::String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AggregatedMessage {
    pub round: u32,
    pub anytrust_group_id: EntityId,
    pub user_ids: BTreeSet<EntityId>,
    /// This is only Some for user-submitted messages
    pub rate_limit_nonce: Option<RateLimitNonce>,
    pub aggregated_msg: DcRoundMessage,
    pub sig: Signature,
    pub pk: PublicKey,
}

impl Default for AggregatedMessage {
    fn default() -> Self {
        AggregatedMessage {
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


impl AggregatedMessage {
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
        // The standard hash function used for most ed25519 libraries is SHA-512
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

impl SignableNoSGX for AggregatedMessage {
    fn digest(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.input(b"Begin AggregatedMessage");
        hasher.input(&self.anytrust_group_id);
        for id in self.user_ids.iter() {
            hasher.input(id);
        }
        hasher.input(&self.aggregated_msg.digest());
        hasher.input(b"End AggregatedMessage");

        hasher.result().to_vec()
    }

    fn get_sig(&self) -> Signature {
        self.sig
    }

    fn get_pk(&self) -> PublicKey {
        self.pk
    }
}

pub trait SignMutableNoSGX {
    fn sign_mut(&mut self, _: &SecretKey) -> Result<(), SignatureError>;
}

impl SignMutableNoSGX for AggregatedMessage {
    fn sign_mut(&mut self, sk: &SecretKey) -> Result<(), SignatureError> {
        let (sig, pk) = self.sign(sk)?;
        self.pk = pk;
        self.sig = sig;

        Ok(())
    }
}

pub trait XorNoSGX: Clone {
    // xor_mut_nosgx computes and sets self = xor(self, other)
    fn xor_mut_nosgx(&mut self, other: &Self)
    where
        Self: Sized;

    // xor_nosgx returns xor(self, other)
    fn xor_nosgx(&self, other: &Self) -> Self {
        let mut copy = self.clone();
        copy.xor_mut_nosgx(other);
        copy
    }
}

impl XorNoSGX for DcRoundMessage {
    fn xor_mut_nosgx(&mut self, other: &Self) {
        assert_eq!(
            self.aggregated_msg.num_rows(),
            other.aggregated_msg.num_rows()
        );
        assert_eq!(
            self.aggregated_msg.num_columns(),
            other.aggregated_msg.num_columns()
        );

        // XOR the scheduling messages
        for (lhs, rhs) in self
            .scheduling_msg
            .as_mut_slice()
            .iter_mut()
            .zip(other.scheduling_msg.as_slice().iter())
        {
            *lhs ^= rhs;
        }

        // XOR the round messages
        for (lhs, rhs) in self
            .aggregated_msg
            .as_mut_slice()
            .iter_mut()
            .zip(other.aggregated_msg.as_slice().iter())
        {
            *lhs ^= rhs;
        }
    }
}

pub enum SubmissionMessage {
    UserSubmission(UserSubmissionMessage),
    AggSubmission(AggregatedMessage),
}

/// Secrets shared between anytrust servers and users.
/// This data structure is used only by servers.
/// This is the server side, the key is user's signing key
/// TODO: new type SharedSecretDbClient, corresponds to client side
/// TODO: upgrade Rust version, migrate project using x25519_dalek 1.2.0
/// where StaticSecret implements Clone, Serialize and Deserialize traits
/// #[derive(Clone, Serialize, Deserialize)]
pub struct SharedSecretsDbServer {
    pub round: u32,
    /// a dictionary of keys
    /// We use StaticSecret to store SharedSecret, since SharedSecret is ephemeral
    pub db: BTreeMap<SgxProtectedKeyPub, StaticSecret>,
}

impl SharedSecretsDbServer {
    pub fn anytrust_group_id(&self) -> EntityId {
        let keys: Vec<SgxProtectedKeyPub> = self.db.keys().cloned().collect();
        compute_anytrust_group_id(&keys)
    }

    // pub fn derive_shared_secrets(
    //     my_sk: &SecretKey,
    //     other_pks: &[SgxProtectedKeyPub],
    // ) -> Result<Self, SignatureError> {
    //     // 1. Generate StaticSecret from server's secret key
    //     let my_secret = StaticSecret::from(my_sk.to_bytes());

    //     let mut server_secrets: BTreeMap<SgxProtectedKeyPub, StaticSecret> = BTreeMap::new();

    //      for client_pk in other_pks.iter() {
    //         // TODO: 2. Convert client pk (SgxProtectedKeyPub) to xPublicKey

    //         // 3. Compute the DH secret for the server and xPublicKeys
    //         let shared_secret = my_secret.diffie_hellman(&client_pk);
    //         // 4. Save ephemeral SharedSecret into StaticSecret
    //         let shared_secret_bytes: [u8; 32] = shared_secret.as_bytes().to_owned();
    //         server_secrets.insert(client_pk.to_owned(), StaticSecret::from(shared_secret_bytes));
    //     }

    //     Ok(SharedSecretsDbServer {
    //         db: server_secrets,
    //         ..Default::default()
    //     })
    // }
}

impl Default for SharedSecretsDbServer {
    fn default() -> Self {
        SharedSecretsDbServer {
            round: 0,
            db: BTreeMap::new(),
        }
    }
}

impl Debug for SharedSecretsDbServer {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let pks: Vec<SgxProtectedKeyPub> = self.db.keys().cloned().collect();
        f.debug_struct("SharedSecretsDbServer")
            .field("round", &self.round)
            .field("pks", &pks)
            .finish()
    }
}

pub type AggPublicKey = AggRegistrationBlobNoSGX;

impl From<&ServerPubKeyPackageNoSGX> for EntityId {
    // server's entity id is computed from the signing key
    fn from(spk: &ServerPubKeyPackageNoSGX) -> Self {
        pk_to_entityid(&spk.sig)
    }
}

/// SignedPubKeyDbNoSGX is a signed mapping between entity id and public key
#[derive(Clone, Default, Serialize, Debug, Deserialize)]
pub struct SignedPubKeyDbNoSGX {
    pub users: BTreeMap<EntityId, AttestedPublicKey>,
    pub servers: BTreeMap<EntityId, ServerPubKeyPackageNoSGX>,
    pub aggregators: BTreeMap<EntityId, AggPublicKey>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_sign_verify_agg_msg() -> Result<(), SignatureError> {
        // generate secret key first
        let mut csprng = OsRng::new().unwrap();

        let sk = SecretKey::generate(&mut csprng);
        let mut agg_msg = AggregatedMessage::default();
        
        // sign the aggregated message using secret key
        agg_msg.sign_mut(&sk)?;

        // verify the aggregated message
        agg_msg.verify()?;

        Ok(())
    }
}