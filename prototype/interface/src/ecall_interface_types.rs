use sgx_types::sgx_status_t;
use std::convert::TryFrom;
use std::string::String;
use std::vec::Vec;
use crate::user_request::EntityId;
use crate::sgx_protected_keys::SgxProtectedKeyPub;
use std::fmt::{Debug, Formatter};
use std::format;
use std::string::ToString;
use std::vec;

macro_rules! impl_enum {
    (
        #[repr($repr:ident)]
        pub enum $name:ident {
            $($key:ident = $val:expr,)+
        }
    ) => (
        #[repr($repr)]
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
        }
    }
}

/// Describes a partial aggregate. It can consist of a single user's round message (i.e., the
/// output of `user_submit_round_msg`, or the XOR of multiple user's round messages (i.e., the
/// output of `finalize_aggregate`).
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Debug, Deserialize)]
pub struct MarshalledSignedUserMessage(pub Vec<u8>);

/// The state of an aggregator. This can only be opened from within the enclave.
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Debug, Deserialize)]
pub struct MarshalledPartialAggregate(pub Vec<u8>);

/// Describes user registration information. This contains key encapsulations as well as a linkably
/// attested signature pubkey.
pub struct UserRegistrationBlob(pub Vec<u8>);

/// Describes aggregator registration information. This contains a linkably attested signature
/// pubkey.
pub struct AggRegistrationBlob(pub Vec<u8>);


#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedFootprintTicket(pub Vec<u8>);


/// Enclave-protected secrets shared with a set of anytrust servers
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedServerSecrets {
    /// The user and the anytrust_group that these keys belongs to.
    pub anytrust_group_id: EntityId,
    pub user_id: EntityId,
    /// Sealed server secrets. Specifically this is a serialization of SharedSecretsWithAnyTrustGroup in enclave/src/crypto/dining_crypto.rs
    pub sealed_server_secrets: Vec<u8>,
    pub server_public_keys: Vec<SgxProtectedKeyPub>,
}

impl Debug for SealedServerSecrets {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedServerSecrets")
            .field("user_id", &self.user_id)
            .field("anytrust_group_id", &self.anytrust_group_id)
            .field("num_of_servers", &self.server_public_keys.len())
            .field("server_pks", &self.server_public_keys)
            .field(
                "sealed_server_secrets",
                &format!("{} bytes", self.sealed_server_secrets.len()),
            )
            .finish()
    }
}

/// An enclave-generated private signing key
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedKey {
    pub sealed_sk: Vec<u8>,
    pub pk: SgxProtectedKeyPub,
    /// role denotes the intended use of this key e.g., "aggregator" "client" "anytrust server"
    pub role: String,
    pub tee_linkable_attestation: Vec<u8>, // binds this key to an enclave
}

/// We implement Default for all Sealed* types
/// Invariant: default values are "ready to use" in ecall.
/// That usually means we have allocated enough memory for the enclave to write to.
impl Default for SealedKey {
    fn default() -> Self {
        SealedKey {
            sealed_sk: vec![0u8; 1024], // 1024 seems enough
            pk: SgxProtectedKeyPub::default(),
            role: "".to_string(),
            tee_linkable_attestation: vec![], // TODO: implement this
        }
    }
}

impl Debug for SealedKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SgxProtectedKeyPair")
            .field("sealed_sk", &format!("{} bytes", self.sealed_sk.len()))
            .field("pk", &self.pk)
            .field("role", &self.role)
            .field(
                "tee_linkable_attestation",
                &hex::encode(&self.tee_linkable_attestation),
            )
            .finish()
    }
}
