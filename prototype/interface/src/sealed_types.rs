use crate::params::SEALED_SGX_SIGNING_KEY_LENGTH;
use std::vec::Vec;

/// The state of an aggregator. This can only be opened from within the enclave.
pub struct MarshalledPartialAggregate(pub Vec<u8>);

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedFootprintTicket(pub Vec<u8>);

/// Enclave-generated secrets shared with a set of anytrust servers
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedServerSecrets(pub Vec<u8>);

/// An enclave-generated private signing key
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedSgxSigningKey(pub Vec<u8>);

use core::fmt::Formatter;
use std::fmt::Debug;
macro_rules! impl_debug_for_sealed {
    ($t: ty) => {
        impl Debug for $t {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", hex::encode(&self.0))
            }
        }
    };
}

impl_debug_for_sealed!(SealedServerSecrets);
impl_debug_for_sealed!(SealedSgxSigningKey);
