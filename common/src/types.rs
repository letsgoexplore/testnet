use ed25519_dalek::{
    Keypair, PublicKey, SecretKey, Signature, SignatureError, Signer, Verifier, KEYPAIR_LENGTH,
    PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};

use interface::{
    compute_anytrust_group_id, AttestedPublicKey, DcRoundMessage, DiffieHellmanSharedSecret,
    EntityId, RateLimitNonce, RoundSecret, ServerPubKeyPackage, SgxProtectedKeyPub,
    UserSubmissionMessage,
};
use sha2::{Digest, Sha256};

use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryInto;
use std::prelude::v1::*;

use core::fmt::Debug;

use x25519_dalek::{PublicKey as xPublicKey, StaticSecret};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_cbor;

#[derive(Clone, Serialize, Debug, Deserialize)]
pub struct AggRegistrationBlob {
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
            sig: Signature::from_bytes(&[0u8; SIGNATURE_LENGTH])
                .expect("failed to generate Signature from bytes"),
            pk: PublicKey::default(),
        }
    }
}

impl AggregatedMessage {
    pub fn is_empty(&self) -> bool {
        self.user_ids.is_empty()
    }
}

pub trait Signable {
    fn digest(&self) -> Vec<u8>;
    fn get_sig(&self) -> Signature;
    fn get_pk(&self) -> PublicKey;

    fn sign(&self, sk: &SecretKey) -> Result<(Signature, PublicKey), SignatureError> {
        let dig: Vec<u8> = self.digest();
        // The standard hash function used for most ed25519 libraries is SHA-512
        let pk: PublicKey = sk.into();
        let sk_bytes: [u8; SECRET_KEY_LENGTH] = sk.to_bytes();
        let pk_bytes: [u8; PUBLIC_KEY_LENGTH] = pk.to_bytes();

        let mut keypair_bytes: [u8; KEYPAIR_LENGTH] = [0; KEYPAIR_LENGTH];
        keypair_bytes[..SECRET_KEY_LENGTH].copy_from_slice(&sk_bytes);
        keypair_bytes[SECRET_KEY_LENGTH..].copy_from_slice(&pk_bytes);

        let keypair: Keypair = Keypair::from_bytes(&keypair_bytes)?;
        let sig = keypair.sign(dig.as_slice());

        Ok((sig, pk))
    }

    fn verify(&self) -> Result<(), SignatureError> {
        let msg_hash = self.digest();
        let pk = self.get_pk();
        pk.verify(msg_hash.as_slice(), &self.get_sig())
    }
}

impl Signable for AggregatedMessage {
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

pub trait SignMutable {
    fn sign_mut(&mut self, _: &SecretKey) -> Result<(), SignatureError>;
}

impl SignMutable for AggregatedMessage {
    fn sign_mut(&mut self, sk: &SecretKey) -> Result<(), SignatureError> {
        let (sig, pk) = self.sign(sk)?;
        self.pk = pk;
        self.sig = sig;

        Ok(())
    }
}

pub enum SubmissionMessage {
    UserSubmission(UserSubmissionMessage),
    AggSubmission(AggregatedMessage),
}

/// Secrets shared between anytrust servers and users.
/// This data structure is used only by servers.
/// This is the server side, the key is user's signing key
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SharedSecretsDbServer {
    pub round: u32,
    /// a dictionary of keys
    /// We use DiffieHellmanSharedSecret to store SharedSecret, since SharedSecret is ephemeral
    pub db: BTreeMap<SgxProtectedKeyPub, DiffieHellmanSharedSecret>,
}

impl SharedSecretsDbServer {
    pub fn anytrust_group_id(&self) -> EntityId {
        let keys: Vec<SgxProtectedKeyPub> = self.db.keys().cloned().collect();
        compute_anytrust_group_id(&keys)
    }

    pub fn derive_shared_secrets(
        my_sk: &SecretKey,
        other_pks: &BTreeMap<SgxProtectedKeyPub, SgxProtectedKeyPub>, // todo: what is the first and second SgxProtectedKeyPub?
    ) -> Result<Self, SignatureError> {
        // 1. Generate StaticSecret from server's secret key
        let my_secret = StaticSecret::from(my_sk.to_bytes());
        let mut server_secrets: BTreeMap<SgxProtectedKeyPub, DiffieHellmanSharedSecret> =
            BTreeMap::new();

        for (client_xpk, client_pk) in other_pks {
            // 2. Derive the exchange pk from the client_xpk
            let xpk = xPublicKey::from(client_xpk.0);
            // 3. Compute the DH shared secret from client exchange pk and server secret
            let shared_secret = my_secret.diffie_hellman(&xpk);
            // 4. Save the ephemeral SharedSecret into DiffieHellmanSharedSecret
            let shared_secret_bytes: [u8; 32] = shared_secret.to_bytes();
            server_secrets.insert(
                client_pk.to_owned(),
                DiffieHellmanSharedSecret(shared_secret_bytes),
            );
        }

        Ok(SharedSecretsDbServer {
            db: server_secrets,
            ..Default::default()
        })
    }

    pub fn ratchet(&self) -> SharedSecretsDbServer {
        let a = self
            .db
            .iter()
            .map(|(&k, v)| {
                let new_key = Sha256::digest(&v.0);
                let secret_bytes: [u8; 32] = new_key
                    .try_into()
                    .expect("cannot convert Sha256 digest to [u8; 32");
                let new_sec = DiffieHellmanSharedSecret(secret_bytes);

                (k, new_sec)
            })
            .collect();

        SharedSecretsDbServer {
            round: self.round + 1,
            db: a,
        }
    }
}

impl Default for SharedSecretsDbServer {
    fn default() -> Self {
        SharedSecretsDbServer {
            round: 0,
            db: BTreeMap::new(),
        }
    }
}

pub type AggPublicKey = AggRegistrationBlob;

/// SignedPubKeyDb is a signed mapping between entity id and public key
#[derive(Clone, Default, Serialize, Debug, Deserialize)]
pub struct SignedPubKeyDb {
    pub users: BTreeMap<EntityId, AttestedPublicKey>,
    pub servers: BTreeMap<EntityId, ServerPubKeyPackage>,
    pub aggregators: BTreeMap<EntityId, AggPublicKey>,
}

/// Contains a set of entity IDs along with the XOR of their round submissions. This is passed to anytrust nodes.
pub type RoundSubmissionBlob = AggregatedMessage;

/// Describes anytrust server registration information. This contains sig key and kem key.
pub type ServerRegistrationBlob = ServerPubKeyPackage;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UnblindedAggregateShare {
    pub encrypted_msg: AggregatedMessage,
    pub key_share: RoundSecret,
    pub sig: Signature,
    pub pk: PublicKey,
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

    fn get_sig(&self) -> Signature {
        self.sig
    }

    fn get_pk(&self) -> PublicKey {
        self.pk
    }
}

impl SignMutable for UnblindedAggregateShare {
    fn sign_mut(&mut self, ssk: &SecretKey) -> Result<(), SignatureError> {
        let (sig, pk) = self.sign(ssk)?;
        self.sig = sig;
        self.pk = pk;

        Ok(())
    }
}

pub fn serialize_to_vec<T: Serialize>(v: &T) -> Result<Vec<u8>, serde_cbor::Error> {
    serde_cbor::to_vec(v).map_err(|e| {
        println!("can't serialize to vec {}", e);
        e
    })
}

pub fn deserialize_from_vec<T: DeserializeOwned>(bin: &[u8]) -> Result<T, serde_cbor::Error> {
    serde_cbor::from_slice::<T>(bin).map_err(|e| {
        println!("can't deserialize from vec {}", e);
        e
    })
}

/// The unblinded aggregate output by a single anytrust node
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UnblindedAggregateShareBlob(pub Vec<u8>);

pub trait MarshallAs<T> {
    fn marshal(&self) -> Result<T, serde_cbor::Error>;
}

pub trait UnmarshalledAs<T> {
    fn unmarshal(&self) -> Result<T, serde_cbor::Error>;
}

impl MarshallAs<UnblindedAggregateShareBlob> for UnblindedAggregateShare {
    fn marshal(&self) -> Result<UnblindedAggregateShareBlob, serde_cbor::Error> {
        Ok(UnblindedAggregateShareBlob(serialize_to_vec(&self)?))
    }
}

impl UnmarshalledAs<UnblindedAggregateShare> for UnblindedAggregateShareBlob {
    fn unmarshal(&self) -> Result<UnblindedAggregateShare, serde_cbor::Error> {
        deserialize_from_vec(&self.0)
    }
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
