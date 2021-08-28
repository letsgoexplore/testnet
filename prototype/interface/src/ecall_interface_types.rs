use crate::sgx_protected_keys::SgxProtectedKeyPub;
use crate::user_request::EntityId;
use crate::DcMessage;
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::format;
use std::vec;
use std::vec::Vec;

macro_rules! impl_enum {
    (
        #[repr($repr:ident)]
        pub enum $name:ident {
            $($key:ident = $val:expr,)+
        }
    ) => (
        #[repr($repr)]
        #[derive(Debug,Copy,Clone)]
        pub enum $name {
            $($key = $val,)+
        }

        impl $name {
            pub fn from_repr(v: $repr) -> Option<Self> {
                match v {
                    $($val => Some($name::$key),)+
                    _ => None,
                }
            }
        }
    )
}

impl_enum! {
    #[repr(u8)]
    pub enum EcallId {
        EcallNewSgxKeypair = 1,
        EcallUnsealToPublicKey = 2,
        EcallRegisterUser = 3,
        EcallUserSubmit = 4,
        EcallAddToAggregate = 5,
        EcallRecvUserRegistration = 6,
        EcallUnblindAggregate = 7,
        EcallDeriveRoundOutput = 8,
        EcallRecvAggregatorRegistration = 9,
        EcallRecvServerRegistration = 10,
    }
}

impl EcallId {
    pub fn as_str(&self) -> &str {
        match *self {
            EcallId::EcallNewSgxKeypair => "EcallNewSgxKeypair",
            EcallId::EcallUnsealToPublicKey => "EcallUnsealToPublicKey",
            EcallId::EcallRegisterUser => "EcallRegisterUser",
            EcallId::EcallUserSubmit => "EcallUserSubmit",
            EcallId::EcallAddToAggregate => "EcallAddToAggregate",
            EcallId::EcallRecvUserRegistration => "EcallRecvUserRegistration",
            EcallId::EcallUnblindAggregate => "EcallUnblindAgg",
            EcallId::EcallDeriveRoundOutput => "EcallDeriveRoundOutput",
            EcallId::EcallRecvAggregatorRegistration => "EcallRecvAggregatorRegistration",
            EcallId::EcallRecvServerRegistration => "EcallRecvServerRegistration",
        }
    }
}

/// Describes a partial aggregate. It can consist of a single user's round message (i.e., the
/// output of `user_submit_round_msg`, or the XOR of multiple user's round messages (i.e., the
/// output of `finalize_aggregate`).
/// Inside an enclave this is deserialized to an AggregatedMessage
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Debug, Deserialize)]
pub struct MarshalledSignedUserMessage(pub Vec<u8>);

/// Contains a set of entity IDs along with the XOR of their round submissions. This is passed to
/// aggregators of all levels as well as anytrust nodes.
/// Inside an enclave this is deserialized to an AggregatedMessage
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Debug, Deserialize)]
pub struct RoundSubmissionBlob(pub Vec<u8>);

/// The unblinded aggregate output by a single anytrust node
/// This serialized to a UnblindedAggregateShare defined in enclave/message_types.rs
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Debug, Deserialize)]
pub struct UnblindedAggregateShareBlob(pub Vec<u8>);

/// The state of an aggregator. This can only be opened from within the enclave.
/// Inside an enclave this is deserialized to an AggregatedMessage
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Debug, Deserialize)]
pub struct SignedPartialAggregate(pub Vec<u8>);

/// Describes user registration information. This contains key encapsulations as well as a linkably
/// attested signature pubkey.
/// In enclave this is deserialized to an AttestedPublicKey (defined in enclave::crypto::keys).
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Debug, Deserialize)]
pub struct UserRegistrationBlob(pub AttestedPublicKey);

/// Describes aggregator registration information. This contains a linkably attested signature
/// pubkey.
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Debug, Deserialize)]
pub struct AggRegistrationBlob(pub AttestedPublicKey);

/// Describes anytrust server registration information. This contains two linkable attestations
/// for sig key and kem key.
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Debug, Deserialize)]
pub struct ServerRegistrationBlob {
    pub sig_key: AttestedPublicKey,
    pub kem_key: AttestedPublicKey,
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedFootprintTicket(pub Vec<u8>);

/// Enclave-protected secrets shared with a set of anytrust servers
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Default, Clone, Serialize, Deserialize)]
// TODO: Make this a map from entity ID to shared secret
pub struct SealedSharedSecretDb {
    pub db: BTreeMap<SgxProtectedKeyPub, Vec<u8>>,
}

impl SealedSharedSecretDb {
    pub fn anytrust_group_id(&self) -> EntityId {
        let keys: Vec<SgxProtectedKeyPub> = self.db.keys().cloned().collect();
        crate::compute_anytrust_group_id(&keys)
    }
}

impl Debug for SealedSharedSecretDb {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let pks: Vec<SgxProtectedKeyPub> = self.db.keys().cloned().collect();
        f.debug_struct("SealedSharedSecretDb")
            .field("pks", &pks)
            .finish()
    }
}

/// SgxProtectedKeyPair is pk + attestation
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AttestedPublicKey {
    pub pk: SgxProtectedKeyPub,
    pub role: std::string::String,
    /// role denotes the intended use of this key e.g., "aggregator" "client" "anytrust server"
    pub tee_linkable_attestation: std::vec::Vec<u8>, // binds this key to an enclave
}

impl Debug for AttestedPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SgxProtectedKeyPair")
            .field("pk", &self.pk)
            .field("role", &self.role)
            .field(
                "tee_linkable_attestation",
                &hex::encode(&self.tee_linkable_attestation),
            )
            .finish()
    }
}

/// An enclave-generated private signing key
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedKey {
    pub sealed_sk: Vec<u8>,
    pub attested_pk: AttestedPublicKey,
}

/// We implement Default for all Sealed* types
/// Invariant: default values are "ready to use" in ecall.
/// That usually means we have allocated enough memory for the enclave to write to.
impl Default for SealedKey {
    fn default() -> Self {
        SealedKey {
            sealed_sk: vec![0u8; 1024], // 1024 seems enough
            attested_pk: AttestedPublicKey::default(),
        }
    }
}

impl Debug for SealedKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedKey")
            .field("sealed_sk", &format!("{} bytes", self.sealed_sk.len()))
            .field("pk", &self.attested_pk)
            .finish()
    }
}

/// A signing keypair is an ECDSA keypair
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SealedSigPrivKey(pub SealedKey);

/// A KEM keypair is also ECDSA keypair
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SealedKemPrivKey(pub SealedKey);

impl AsRef<SealedKey> for SealedKemPrivKey {
    fn as_ref(&self) -> &SealedKey {
        &self.0
    }
}

/// SignedPubKeyDb is a signed mapping between entity id and public key
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Default, Serialize, Debug, Deserialize)]
pub struct SignedPubKeyDb {
    pub users: BTreeMap<EntityId, AttestedPublicKey>,
    pub servers: BTreeMap<EntityId, AttestedPublicKey>,
    pub aggregators: BTreeMap<EntityId, AttestedPublicKey>,
}

// TODO: Figure out what this should contain. Probably just a long bitstring.
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Default, Serialize, Debug, Deserialize)]
pub struct RoundOutput(pub DcMessage);
