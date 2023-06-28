use ed25519_dalek::{
    SecretKey,
    PublicKey,
    SECRET_KEY_LENGTH,
    PUBLIC_KEY_LENGTH,
};

use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use std::vec::Vec;

use crate::user_request::EntityId;

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
pub struct NoSgxProtectedKeyPub(pub [u8; PUBLIC_KEY_LENGTH]);

impl Debug for NoSgxProtectedKeyPub {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        std::write!(f, "({})", hex::encode(&self.0))
    }
}

impl Display for NoSgxProtectedKeyPub {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        std::write!(f, "{}", hex::encode(self.0))
    }
}


impl NoSgxProtectedKeyPub {
    /// Computes the entity ID corresponding to this KEM pubkey
    pub fn get_entity_id(&self) -> EntityId {
        EntityId::from(self)
    }
}

/// AttestedPublicKey is pk + attestation
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AttestedPublicKeyNoSGX {
    pub pk: NoSgxProtectedKeyPub,
    pub role: std::string::String,
    /// role denotes the intended use of this key e.g., "aggregator" "client" "anytrust server"
    pub tee_linkable_attestation: std::vec::Vec<u8>, // binds this key to an enclave
}

impl Debug for AttestedPublicKeyNoSGX {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestedPublicKeyNoSGX")
            .field("pk", &self.pk)
            .field("role", &self.role)
            .field(
                "tee_linkable_attestation",
                &hex::encode(&self.tee_linkable_attestation)
            )
            .finish()
    }
}

