extern crate sgx_types;

use crate::user_request::EntityId;

use core::fmt;
use core::fmt::{Debug, Display, Formatter};
#[allow(unused_imports)]
use sgx_types::sgx_status_t;
#[allow(unused_imports)]
use std::{convert::TryFrom, vec::Vec};

use rand_core::RngCore;
use sgx_types::{sgx_ec256_private_t, sgx_ec256_public_t, SGX_ECP256_KEY_SIZE};
use sha2::{Digest, Sha256};

// A wrapper around sgx_ec256_public_t
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct KemPubKey {
    pub gx: [u8; SGX_ECP256_KEY_SIZE],
    pub gy: [u8; SGX_ECP256_KEY_SIZE],
}

// TODO: Can make this a fixed size byte array if we know an upper bound on the size
/// An enclave-generated private signing key
#[derive(Clone)]
pub struct SealedSigningKey(pub Vec<u8>);

impl Debug for KemPubKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PK")
            .field("x", &hex::encode(&self.gx))
            .field("y", &hex::encode(&self.gx))
            .finish()
    }
}

impl Display for KemPubKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        std::write!(f, "({}, {})", hex::encode(self.gx), hex::encode(self.gy))
    }
}

impl From<sgx_ec256_public_t> for KemPubKey {
    fn from(sgx_ec_pubkey: sgx_ec256_public_t) -> Self {
        return Self {
            gx: sgx_ec_pubkey.gx,
            gy: sgx_ec_pubkey.gy,
        };
    }
}

#[cfg(feature = "trusted")]
impl TryFrom<&KemPrvKey> for KemPubKey {
    type Error = sgx_status_t;

    fn try_from(prv_key: &KemPrvKey) -> Result<Self, Self::Error> {
        sgx_tcrypto::rsgx_ecc256_pub_from_priv(&prv_key.into()).map(KemPubKey::from)
    }
}

impl Into<sgx_ec256_public_t> for KemPubKey {
    fn into(self) -> sgx_ec256_public_t {
        sgx_ec256_public_t {
            gx: self.gx,
            gy: self.gy,
        }
    }
}

impl KemPubKey {
    /// Computes the entity ID corresponding to this KEM pubkey
    pub fn get_entity_id(&self) -> EntityId {
        // The entity ID is just H("ent" || x || y).
        let mut hasher = Sha256::new();
        hasher.update(b"ent");
        hasher.update(self.gx);
        hasher.update(self.gy);
        let digest = hasher.finalize();

        let mut id = EntityId::default();
        id.0.copy_from_slice(&digest);

        id
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

// A wrapper around sgx_ec256_private_t
#[derive(Copy, Clone, Default)]
#[cfg_attr(feature = "trusted", derive(Rand))]
pub struct KemPrvKey {
    pub r: [u8; SGX_ECP256_KEY_SIZE],
}

#[cfg(feature = "trusted")]
unsafe impl sgx_types::marker::ContiguousMemory for KemPrvKey {}

#[cfg(test)]
impl KemPrvKey {
    pub fn gen_test(byte: u8) -> Self {
        return Self {
            r: [byte; SGX_ECP256_KEY_SIZE],
        };
    }
}

impl From<sgx_ec256_private_t> for KemPrvKey {
    fn from(sgx_prv_key: sgx_ec256_private_t) -> Self {
        return Self { r: sgx_prv_key.r };
    }
}

impl Into<sgx_ec256_private_t> for KemPrvKey {
    fn into(self) -> sgx_ec256_private_t {
        return sgx_ec256_private_t { r: self.r };
    }
}

impl Into<sgx_ec256_private_t> for &KemPrvKey {
    fn into(self) -> sgx_ec256_private_t {
        return sgx_ec256_private_t { r: self.r };
    }
}

#[derive(Copy, Clone, Default)]
pub struct KemKeyPair {
    pub prv_key: KemPrvKey,
    pub pub_key: KemPubKey,
}
