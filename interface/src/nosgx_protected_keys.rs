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
pub struct NoSgxPortectedKeyPub(pub [u8; PUBLIC_KEY_LENGTH]);

impl Debug for NoSgxPortectedKeyPub {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        std::write!(f, "({})", hex::encode(&self.0))
    }
}

impl Display for NoSgxPortectedKeyPub {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        std::write!(f, "{}", hex::encode(self.0))
    }
}


impl NoSgxPortectedKeyPub {
    /// Computes the entity ID corresponding to this KEM pubkey
    pub fn get_entity_id(&self) -> EntityId {
        EntityId::from(self)
    }
}


