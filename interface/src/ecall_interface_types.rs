use crate::params::SHARED_SECRET_LENGTH;
use crate::sgx_protected_keys::{AttestedPublicKey, OutputSignature, SgxProtectedKeyPub};
use crate::user_request::DcRoundMessage;
use crate::user_request::EntityId;
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
        EcallNewUser = 3,
        EcallNewUserBatch = 16,
        EcallUserSubmit = 5,
    }
}

impl EcallId {
    pub fn as_str(&self) -> &str {
        match *self {
            EcallId::EcallNewUser => "EcallNewUser",
            EcallId::EcallNewUserBatch => "EcallNewUserBatch",
            EcallId::EcallUserSubmit => "EcallUserSubmit",
        }
    }
}

/// Contains the user's entity ID along with his submissions. This is passed to the base level
/// aggregators only.
pub type UserSubmissionBlob = crate::UserSubmissionMessage;

/// Describes user registration information. This contains key encapsulations as well as a linkably
/// attested signature pubkey.
pub type UserRegistrationBlob = AttestedPublicKey;

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedFootprintTicket(pub Vec<u8>);

/// Enclave-protected secrets shared between anytrust servers and users.
/// This data structure is use by users only
/// The key is server's public key
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct SealedSharedSecretsDbClient {
    pub round: u32,
    pub db: BTreeMap<SgxProtectedKeyPub, Vec<u8>>,
}

impl SealedSharedSecretsDbClient {
    pub fn anytrust_group_id(&self) -> EntityId {
        let keys: Vec<SgxProtectedKeyPub> = self.db.keys().cloned().collect();
        crate::compute_anytrust_group_id(&keys)
    }
}

impl Debug for SealedSharedSecretsDbClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let pks: Vec<SgxProtectedKeyPub> = self.db.keys().cloned().collect();
        f.debug_struct("SealedSharedSecretsDbClient")
            .field("pks", &pks)
            .finish()
    }
}

/// A shared secret is the long-term secret shared between an anytrust server and this user
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiffieHellmanSharedSecret(pub [u8; SHARED_SECRET_LENGTH]);

impl AsRef<[u8]> for DiffieHellmanSharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for DiffieHellmanSharedSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

/// A signing keypair is an ECDSA keypair
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SealedSigPrivKey(pub Vec<u8>);

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Default, Serialize, Debug, Deserialize)]
pub struct RoundOutput {
    pub round: u32,
    pub dc_msg: DcRoundMessage,
    pub server_sigs: Vec<OutputSignature>,
}
