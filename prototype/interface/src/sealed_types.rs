use crate::params::SEALED_SGX_SIGNING_KEY_LENGTH;
use std::vec::Vec;

/// The state of an aggregator. This can only be opened from within the enclave.
pub struct MarshalledPartialAggregate(pub Vec<u8>);

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedFootprintTicket(pub Vec<u8>);

/// Enclave-generated secrets shared with a set of anytrust servers
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedServerSecrets(pub Vec<u8>);

/// An enclave-generated private signing key
#[derive(Clone)]
pub struct SealedSigningKey(pub [u8; SEALED_SGX_SIGNING_KEY_LENGTH]); // 512 should be more than enough

impl Default for SealedSigningKey {
    fn default() -> Self {
        SealedSigningKey([0; SEALED_SGX_SIGNING_KEY_LENGTH])
    }
}
