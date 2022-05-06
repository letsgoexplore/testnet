use std::prelude::v1::*;
use std::{collections::BTreeSet, vec};

use crate::{array2d::Array2D, ecall_interface_types::*, params::*, sgx_protected_keys::*};

use sha2::{Digest, Sha256};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

// a wrapper around RawMessage so that we can impl traits. This stores DC_NET_MESSAGE_LENGTH bytes
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize)]
pub struct DcMessage(pub Vec<u8>);

impl Default for DcMessage {
    fn default() -> DcMessage {
        DcMessage(vec![0u8; DC_NET_MESSAGE_LENGTH])
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
        // Try interpreting as UTF-8. If it fails, write out the base64
        if let Ok(s) = String::from_utf8(self.0.to_vec()) {
            f.write_str(&s)
        } else {
            f.write_str(&base64::encode(&self.0))
        }
    }
}

impl AsRef<[u8]> for DcMessage {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// we store footprints in u32s (enclave/ecall/submit.rs)
pub type Footprint = u32;

/// What's broadcast through the channel
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct DcRoundMessage {
    // Contains FOOTPRINT_N_SLOTS elements
    pub scheduling_msg: Vec<Footprint>,
    // Contains DC_NET_N_SLOTS rows, each of which is DC_NET_MESSAGE_LENGTH bytes
    pub aggregated_msg: Array2D<u8>,
}

/// Used to generate round secrets
#[cfg(feature = "trusted")]
impl Rand for DcRoundMessage {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        let mut m = DcRoundMessage::default();

        // Fill scheduling slots with random u32s
        for s in m.scheduling_msg.as_mut_slice() {
            *s = rng.gen::<u32>();
        }
        // Fill msg slots with random bytes
        rng.fill_bytes(m.aggregated_msg.as_mut_slice());

        m
    }
}

impl Default for DcRoundMessage {
    fn default() -> Self {
        DcRoundMessage {
            scheduling_msg: vec![0; FOOTPRINT_N_SLOTS],
            aggregated_msg: Array2D::filled_with(0u8, DC_NET_N_SLOTS, DC_NET_MESSAGE_LENGTH),
        }
    }
}

impl Debug for DcRoundMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // First convert aggregated_msg back to a vec of DcMessages
        let aggregated_msg: Vec<DcMessage> = self
            .aggregated_msg
            .rows_iter()
            .map(|row_it| DcMessage(row_it.cloned().collect()))
            .collect();
        f.debug_struct("DcRoundMessage")
            .field("scheduling_msg", &self.scheduling_msg)
            .field("aggregated_msg", &aggregated_msg)
            .finish()
    }
}

impl DcRoundMessage {
    /// used by signature
    pub fn digest(&self) -> Vec<u8> {
        let mut b: Vec<u8> = Vec::new();
        for i in self.scheduling_msg.iter() {
            b.extend(&i.to_le_bytes())
        }

        b.extend(&self.aggregated_msg.as_row_major());

        b
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

/// This is a token that's intended to be used for rate limiting. It's just the sha256 hash of the
/// current window along with the number of times the user has already talked this window. This
/// number may not exceed DC_NET_MSGS_PER_WINDOW. If a token ever repeats then the aggregator will
/// know that the user is disobeying its talking limit.
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct RateLimitNonce([u8; 32]);

impl RateLimitNonce {
    pub fn from_bytes(bytes: &[u8]) -> RateLimitNonce {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(bytes);
        RateLimitNonce(buf)
    }
}

#[cfg(feature = "trusted")]
impl Rand for RateLimitNonce {
    fn rand<R: Rng>(rng: &mut R) -> RateLimitNonce {
        let mut nonce = RateLimitNonce::default();
        rng.fill_bytes(&mut nonce.0);
        nonce
    }
}

/// In a single round a user can either talk+reserve, reserve, or do nothing (i.e., provide cover
/// traffic).
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UserMsg {
    TalkAndReserve {
        msg: DcMessage,
        /// Output of previous round signed by one or more anytrust server
        prev_round_output: RoundOutput,
        /// The number of times the user has already talked or reserved this window
        times_participated: u32,
    },
    Reserve {
        /// The number of times the user has already talked or reserved this window
        times_participated: u32,
    },
    Cover,
}

impl UserMsg {
    pub fn is_cover(&self) -> bool {
        match self {
            UserMsg::Cover => true,
            _ => false,
        }
    }
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserSubmissionReq {
    pub user_id: EntityId,
    pub anytrust_group_id: EntityId,
    pub round: u32,
    pub msg: UserMsg,
    /// A map from server KEM public key to sealed shared secret
    pub shared_secrets: SealedSharedSecretDb,
    /// A list of server public keys (can be verified using the included attestation)
    pub server_pks: Vec<ServerPubKeyPackage>,
}
