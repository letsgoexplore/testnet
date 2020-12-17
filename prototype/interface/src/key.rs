extern crate sgx_types;

use sgx_types::{
    sgx_ec256_private_t, sgx_ec256_public_t, sgx_ec256_signature_t, SGX_ECP256_KEY_SIZE,
    SGX_HMAC256_KEY_SIZE, SGX_NISTP_ECP256_KEY_SIZE,
};

use core::fmt;
use core::fmt::{Debug, Display, Formatter};
#[allow(unused_imports)]
use sgx_types::sgx_status_t;
#[allow(unused_imports)]
use std::convert::TryFrom;

use crate::params::*;

// use id is sha-256 of some public key (just like)
pub type UserId = [u8; USER_ID_LENGTH];

// A wrapper around sgx_ec256_public_t
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct PubKey {
    pub gx: [u8; SGX_ECP256_KEY_SIZE],
    pub gy: [u8; SGX_ECP256_KEY_SIZE],
}

impl Debug for PubKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PK")
            .field("x", &hex::encode(&self.gx))
            .field("y", &hex::encode(&self.gx))
            .finish()
    }
}

impl Display for PubKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        std::write!(f, "({}, {})", hex::encode(self.gx), hex::encode(self.gy))
    }
}

impl From<sgx_ec256_public_t> for PubKey {
    fn from(sgx_ec_pubkey: sgx_ec256_public_t) -> Self {
        return Self {
            gx: sgx_ec_pubkey.gx,
            gy: sgx_ec_pubkey.gy,
        };
    }
}

#[cfg(feature = "trusted")]
impl TryFrom<&PrvKey> for PubKey {
    type Error = sgx_status_t;

    fn try_from(prv_key: &PrvKey) -> Result<Self, Self::Error> {
        sgx_tcrypto::rsgx_ecc256_pub_from_priv(&prv_key.into()).map(PubKey::from)
    }
}

impl Into<sgx_ec256_public_t> for PubKey {
    fn into(self) -> sgx_ec256_public_t {
        sgx_ec256_public_t {
            gx: self.gx,
            gy: self.gy,
        }
    }
}

// A wrapper around sgx_ec256_private_t
#[derive(Copy, Clone, Default)]
#[cfg_attr(feature = "trusted", derive(Rand))]
pub struct PrvKey {
    pub r: [u8; SGX_ECP256_KEY_SIZE],
}

#[cfg(feature = "trusted")]
unsafe impl sgx_types::marker::ContiguousMemory for PrvKey {}

impl PrvKey {
    pub fn gen_test(byte: u8) -> Self {
        return Self {
            r: [byte; SGX_ECP256_KEY_SIZE],
        };
    }
}

impl From<sgx_ec256_private_t> for PrvKey {
    fn from(sgx_prv_key: sgx_ec256_private_t) -> Self {
        return Self { r: sgx_prv_key.r };
    }
}

impl Into<sgx_ec256_private_t> for PrvKey {
    fn into(self) -> sgx_ec256_private_t {
        return sgx_ec256_private_t { r: self.r };
    }
}

impl Into<sgx_ec256_private_t> for &PrvKey {
    fn into(self) -> sgx_ec256_private_t {
        return sgx_ec256_private_t { r: self.r };
    }
}

#[derive(Copy, Clone, Default)]
pub struct KeyPair {
    pub prv_key: PrvKey,
    pub pub_key: PubKey,
}
