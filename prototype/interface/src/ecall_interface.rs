use crate::{EntityId, SealedKey};
use sgx_types::sgx_status_t;
use std::convert::TryFrom;
use std::string::String;
use std::vec::Vec;

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
