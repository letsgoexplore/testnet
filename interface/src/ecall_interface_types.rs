use crate::sgx_protected_keys::{AttestedPublicKey, ServerPubKeyPackage, SgxProtectedKeyPub};
use crate::nosgx_protected_keys::{AttestedPublicKeyNoSGX, NoSgxProtectedKeyPub, SignatureNoSGX};
use crate::sgx_signature::Signature;
use crate::user_request::EntityId;
use crate::DcRoundMessage;
use crate::params::SHARED_SECRET_LENGTH;
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
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
        EcallNewUser = 3,
        EcallNewUserBatch = 16,
        EcallNewUserUpdated = 17,
        EcallNewUserBatchUpdated = 18,
        EcallNewServer = 4,
        EcallUserSubmit = 5,
        EcallUserSubmitUpdated = 19,
        EcallAddToAggregate = 6,
        EcallRecvUserRegistration =7,
        EcallRecvUserRegistrationBatch = 8,
        EcallUnblindAggregate = 9,
        EcallUnblindAggregatePartial = 10,
        EcallUnblindAggregateMerge = 11,
        EcallDeriveRoundOutput = 12,
        EcallRecvAggregatorRegistration = 13,
        EcallRecvServerRegistration = 14,
        EcallLeakDHSecrets = 15,
    }
}

impl EcallId {
    pub fn as_str(&self) -> &str {
        match *self {
            EcallId::EcallNewSgxKeypair => "EcallNewSgxKeypair",
            EcallId::EcallUnsealToPublicKey => "EcallUnsealToPublicKey",
            EcallId::EcallNewUser => "EcallNewUser",
            EcallId::EcallNewUserBatch => "EcallNewUserBatch",
            EcallId::EcallNewUserUpdated => "EcallNewUserUpdated",
            EcallId::EcallNewUserBatchUpdated => "EcallNewUserBatchUpdated",
            EcallId::EcallNewServer => "EcallNewServer",
            EcallId::EcallUserSubmit => "EcallUserSubmit",
            EcallId::EcallUserSubmitUpdated => "EcallUserSubmitUpdated",
            EcallId::EcallAddToAggregate => "EcallAddToAggregate",
            EcallId::EcallRecvUserRegistration => "EcallRecvUserRegistration",
            EcallId::EcallUnblindAggregate => "EcallUnblindAgg",
            EcallId::EcallUnblindAggregatePartial => "EcallUnblindAggPartial",
            EcallId::EcallUnblindAggregateMerge => "EcallUnblindAggMerge",
            EcallId::EcallDeriveRoundOutput => "EcallDeriveRoundOutput",
            EcallId::EcallRecvAggregatorRegistration => "EcallRecvAggregatorRegistration",
            EcallId::EcallRecvServerRegistration => "EcallRecvServerRegistration",
            EcallId::EcallRecvUserRegistrationBatch => "EcallRecvUserRegistrationBatch",
            EcallId::EcallLeakDHSecrets => "EcallLeakDHSecrets",
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

/// Contains the user's entity ID along with his submissions. This is passed to the base level
/// aggregators only.
pub type UserSubmissionBlob = crate::UserSubmissionMessage;

pub type UserSubmissionBlobUpdated = crate::UserSubmissionMessageUpdated;

/// Contains a set of entity IDs along with the XOR of their round submissions. This is passed to
/// aggregators of all levels as well as anytrust nodes.
pub type RoundSubmissionBlob = crate::AggregatedMessageObsolete;

/// The unblinded aggregate output by a single anytrust node
/// This serialized to a UnblindedAggregateShare defined in enclave/message_types.rs
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Debug, Deserialize)]
pub struct UnblindedAggregateShareBlob(pub Vec<u8>);

/// The state of an aggregator. This can only be opened from within the enclave.
pub type SignedPartialAggregate = crate::AggregatedMessageObsolete;

/// Describes user registration information. This contains key encapsulations as well as a linkably
/// attested signature pubkey.
pub type UserRegistrationBlob = AttestedPublicKey;

/// Describes user registration information. This contains key encapsulations as well as a linkably
/// attested signature pubkey.
pub type UserRegistrationBlobNew = AttestedPublicKeyNoSGX;

/// Describes aggregator registration information. This contains a linkably attested signature
/// pubkey.
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Debug, Deserialize)]
pub struct AggRegistrationBlob(pub AttestedPublicKey);

/// Describes anytrust server registration information. This contains two linkable attestations
/// for sig key and kem key.
pub type ServerRegistrationBlob = ServerPubKeyPackage;

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedFootprintTicket(pub Vec<u8>);

/// Enclave-protected secrets shared between anytrust servers and users.
/// This data structure is used by both users and servers.
/// On the user side, the key is server's signing key
/// On the client side, the key is user's signing key
/// TODO: protect the integrity of pks
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct SealedSharedSecretDb {
    pub round: u32,
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

/// Enclave-protected secrets shared between anytrust servers and users.
/// This data structure is use by users only
/// The key is server's public key
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct SealedSharedSecretsDbClient {
    pub round: u32,
    pub db: BTreeMap<NoSgxProtectedKeyPub, Vec<u8>>,
}

impl SealedSharedSecretsDbClient {
    pub fn anytrust_group_id(&self) -> EntityId {
        let keys: Vec<NoSgxProtectedKeyPub> = self.db.keys().cloned().collect();
        crate::compute_anytrust_group_id_spk(&keys)
    }
}

impl Debug for SealedSharedSecretsDbClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let pks: Vec<NoSgxProtectedKeyPub> = self.db.keys().cloned().collect();
        f.debug_struct("SealedSharedSecretsDbClient")
            .field("pks", &pks)
            .finish()
    }
}

/// A shared secret is the long-term secret shared between an anytrust server and this user
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct NewDiffieHellmanSharedSecret(pub [u8; SHARED_SECRET_LENGTH]);

impl AsRef<[u8]> for NewDiffieHellmanSharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for NewDiffieHellmanSharedSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

/// A signing keypair is an ECDSA keypair
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SealedSigPrivKeyNoSGX(pub Vec<u8>);

/// A signing keypair is an ECDSA keypair
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SealedSigPrivKey(pub Vec<u8>);

/// A KEM keypair is also an ECDSA keypair
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SealedKemPrivKey(pub Vec<u8>);

// impl AsRef<SealedKeyPair> for SealedKemPrivKey {
//     fn as_ref(&self) -> &SealedKeyPair {
//         &self.0
//     }
// }

/// SignedPubKeyDb is a signed mapping between entity id and public key
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Default, Serialize, Debug, Deserialize)]
pub struct SignedPubKeyDb {
    pub users: BTreeMap<EntityId, AttestedPublicKey>,
    pub servers: BTreeMap<EntityId, ServerPubKeyPackage>,
    pub aggregators: BTreeMap<EntityId, AttestedPublicKey>,
}

// TODO: Figure out what this should contain. Probably just a long bitstring.
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Default, Serialize, Debug, Deserialize)]
pub struct RoundOutput {
    pub round: u32,
    pub dc_msg: DcRoundMessage,
    pub server_sigs: Vec<Signature>,
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Default, Serialize, Debug, Deserialize)]
pub struct RoundOutputUpdated {
    pub round: u32,
    pub dc_msg: DcRoundMessage,
    pub server_sigs: Vec<SignatureNoSGX>,
}