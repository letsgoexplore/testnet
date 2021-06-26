use crate::params::SEALED_SGX_SIGNING_KEY_LENGTH;
use std::vec::Vec;

/// The state of an aggregator. This can only be opened from within the enclave.
pub struct MarshalledPartialAggregate(pub Vec<u8>);

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

use std::format;

impl Debug for SealedServerSecrets {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedServerSecrets")
            .field("user_id", &self.user_id)
            .field("anytrust_group_id", &self.anytrust_group_id)
            .field("num_of_servers", &self.server_public_keys.len())
            .field("server_pks", &self.server_public_keys)
            .field("sealed_server_secrets", &format!("{} bytes", self.sealed_server_secrets.len()))
            .finish()
    }
}

/// An enclave-generated private signing key
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedPrivateKey(pub Vec<u8>);

use core::fmt::Formatter;
use std::fmt::Debug;
use crate::{EntityId, SgxProtectedKeyPub};
macro_rules! impl_debug_for_sealed {
    ($t: ty) => {
        impl Debug for $t {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                f.write_str(&hex::encode(&self.0))
            }
        }
    };
}

impl_debug_for_sealed!(SealedPrivateKey);
