use std::collections::BTreeSet;
use std::prelude::v1::*;

use crate::{ecall_interface_types::*, params::*, sgx_protected_keys::*};

use sha2::{Digest, Sha256};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

big_array! { BigArray; }

// a wrapper around RawMessage so that we can impl traits
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize)]
pub struct DcMessage(#[serde(with = "BigArray")] pub [u8; DC_NET_MESSAGE_LENGTH]);

impl Default for DcMessage {
    fn default() -> DcMessage {
        DcMessage([0u8; DC_NET_MESSAGE_LENGTH])
    }
}

#[cfg(feature = "trusted")]
use sgx_rand::{Rand, Rng};

#[cfg(feature = "trusted")]
impl Rand for DcMessage {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        let mut r = DcMessage::default();
        rng.fill_bytes(&mut r.0);

        r
    }
}

impl std::cmp::PartialEq for DcMessage {
    fn eq(&self, other: &Self) -> bool {
        self.0.iter().zip(&other.0).all(|(x, y)| x == y)
    }
}

impl Debug for DcMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(&hex::encode(&self))
    }
}

impl From<[u8; DC_NET_MESSAGE_LENGTH]> for DcMessage {
    fn from(raw: [u8; DC_NET_MESSAGE_LENGTH]) -> Self {
        DcMessage(raw)
    }
}

impl AsRef<[u8]> for DcMessage {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; DC_NET_MESSAGE_LENGTH]> for DcMessage {
    fn as_ref(&self) -> &[u8; DC_NET_MESSAGE_LENGTH] {
        &self.0
    }
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntityId(pub [u8; USER_ID_LENGTH]);

impl Display for EntityId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(&hex::encode(self.0))
    }
}

impl Debug for EntityId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(&hex::encode(self.0))
    }
}

impl AsRef<[u8]> for EntityId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; USER_ID_LENGTH]> for EntityId {
    fn from(raw: [u8; USER_ID_LENGTH]) -> Self {
        EntityId(raw)
    }
}

impl From<&SgxProtectedKeyPub> for EntityId {
    fn from(pk: &SgxProtectedKeyPub) -> Self {
        let mut hasher = Sha256::new();
        hasher.update("anytrust_group_id");
        hasher.update(pk.gx);
        hasher.update(pk.gy);

        let digest = hasher.finalize();

        let mut id = EntityId::default();
        id.0.copy_from_slice(&digest);
        id
    }
}

impl From<&AttestedPublicKey> for EntityId {
    fn from(pk: &AttestedPublicKey) -> Self {
        EntityId::from(&pk.pk)
    }
}

impl From<&ServerPubKeyPackage> for EntityId {
    // server's entity id is computed from the signing key
    fn from(spk: &ServerPubKeyPackage) -> Self {
        EntityId::from(&spk.sig)
    }
}

/// Computes a group ID given a list of entity IDs
pub fn compute_group_id(ids: &BTreeSet<EntityId>) -> EntityId {
    // The group ID of a set of entities is the hash of their IDs, concatenated in ascending order.
    // There's also the context str of "grp" prepended.
    let mut hasher = Sha256::new();
    hasher.update(b"grp");
    for id in ids {
        hasher.update(&id.0);
    }
    let digest = hasher.finalize();

    let mut id = EntityId::default();
    id.0.copy_from_slice(&digest);
    id
}

/// An anytrust_group_id is computed from sig keys
pub fn compute_anytrust_group_id(keys: &[SgxSigningPubKey]) -> EntityId {
    compute_group_id(&keys.iter().map(|k| EntityId::from(k)).collect())
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserSubmissionReq {
    pub user_id: EntityId,
    pub anytrust_group_id: EntityId,
    pub round: u32,
    pub msg: DcMessage,
    /// output of previous round signed by one or more anytrust server
    pub prev_round_output: RoundOutput,
    /// A map from server public key to sealed shared secret
    pub shared_secrets: SealedSharedSecretDb,
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserReservationReq {
    pub user_id: EntityId,
    pub anytrust_group_id: EntityId,
    pub round: u32,
    pub prev_round_output: RoundOutput,
    /// A map from server public key to sealed shared secret
    pub shared_secrets: SealedSharedSecretDb,
}

// #[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
// #[derive(Clone, Serialize, Debug, Deserialize)]
// pub struct UserRegistration {
//     pub key: SealedSigPrivKey,
//     pub shared_secrets: SealedSharedSecretDb,
// }
//
// impl UserRegistration {
//     pub fn get_user_id(&self) -> EntityId {
//         EntityId::from(&self.key.0.attested_pk.pk)
//     }
//
//     pub fn get_sealed_shared_secrets(&self) -> &SealedSharedSecretDb {
//         &self.shared_secrets
//     }
//
//     pub fn get_sealed_usk(&self) -> &SealedSigPrivKey {
//         &self.key
//     }
//
//     pub fn get_registration_blob(&self) -> UserRegistrationBlob {
//         UserRegistrationBlob(self.key.0.attested_pk.clone())
//     }
// }
