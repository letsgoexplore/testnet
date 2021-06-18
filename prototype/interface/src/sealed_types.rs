use std::vec::Vec;

/// The state of an aggregator. This can only be opened from within the enclave.
pub struct SealedPartialAggregate(pub Vec<u8>);

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedFootprintTicket(pub Vec<u8>);

/// Enclave-generated secrets shared with a set of anytrust servers
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedServerSecrets(pub Vec<u8>);

// TODO: Can make this a fixed size byte array if we know an upper bound on the size
/// An enclave-generated private signing key
#[derive(Clone)]
pub struct SealedSigningKey(pub Vec<u8>);
