extern crate sgx_types;

use crate::user_request::EntityId;

use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use std::vec::Vec;

use rand_core::RngCore;
use sgx_types::{sgx_ec256_public_t, SGX_ECP256_KEY_SIZE};

// A wrapper around sgx_ec256_public_t
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
pub struct SgxProtectedKeyPub {
    pub gx: [u8; SGX_ECP256_KEY_SIZE],
    pub gy: [u8; SGX_ECP256_KEY_SIZE],
}

impl Debug for SgxProtectedKeyPub {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "({},{})", hex::encode(&self.gx), hex::encode(&self.gy))
    }
}

impl Display for SgxProtectedKeyPub {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        std::write!(f, "({}, {})", hex::encode(self.gx), hex::encode(self.gy))
    }
}

impl From<sgx_ec256_public_t> for SgxProtectedKeyPub {
    fn from(sgx_ec_pubkey: sgx_ec256_public_t) -> Self {
        return Self {
            gx: sgx_ec_pubkey.gx,
            gy: sgx_ec_pubkey.gy,
        };
    }
}

impl Into<sgx_ec256_public_t> for SgxProtectedKeyPub {
    fn into(self) -> sgx_ec256_public_t {
        sgx_ec256_public_t {
            gx: self.gx,
            gy: self.gy,
        }
    }
}

impl Into<sgx_ec256_public_t> for &SgxProtectedKeyPub {
    fn into(self) -> sgx_ec256_public_t {
        sgx_ec256_public_t {
            gx: self.gx,
            gy: self.gy,
        }
    }
}

impl SgxProtectedKeyPub {
    /// Computes the entity ID corresponding to this KEM pubkey
    pub fn get_entity_id(&self) -> EntityId {
        EntityId::from(self)
    }

    // TODO: Make this generate valid pubkeys
    // Generates a random and NOT VALID pubkey
    pub fn rand_invalid_placeholder<R: RngCore>(rng: &mut R) -> Self {
        let mut gx = [0u8; SGX_ECP256_KEY_SIZE];
        let mut gy = [0u8; SGX_ECP256_KEY_SIZE];

        rng.fill_bytes(&mut gx);
        rng.fill_bytes(&mut gy);

        return Self { gx, gy };
    }
}

/// KemPubKey and SgxSigningPubKey are just aliases to SgxProtectedKeyPub
pub type KemPubKey = SgxProtectedKeyPub;
pub type SgxSigningPubKey = SgxProtectedKeyPub;
