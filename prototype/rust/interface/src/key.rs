extern crate sgx_types;

use sgx_types::{
    sgx_ec256_private_t, sgx_ec256_public_t, sgx_ec256_signature_t, SGX_ECP256_KEY_SIZE,
    SGX_HMAC256_KEY_SIZE, SGX_NISTP_ECP256_KEY_SIZE,
};

// A wrapper around sgx_ec256_public_t
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PubKey {
    pub gx: [u8; SGX_ECP256_KEY_SIZE],
    pub gy: [u8; SGX_ECP256_KEY_SIZE],
}

impl From<sgx_ec256_public_t> for PubKey {
    fn from(sgx_ec_pubkey: sgx_ec256_public_t) -> Self {
        return Self {
            gx: sgx_ec_pubkey.gx,
            gy: sgx_ec_pubkey.gy,
        };
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
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Debug, Serialize, Deserialize)]
pub struct PrvKey {
    pub r: [u8; SGX_ECP256_KEY_SIZE],
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

#[derive(Copy, Clone, Default)]
pub struct KeyPair {
    pub prv_key: PrvKey,
    pub pub_key: PubKey,
}

// A wrapper around sgx_ec256_signature_t
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub x: [u32; SGX_NISTP_ECP256_KEY_SIZE],
    pub y: [u32; SGX_NISTP_ECP256_KEY_SIZE],
}

impl Into<sgx_ec256_signature_t> for Signature {
    fn into(self) -> sgx_ec256_signature_t {
        return sgx_ec256_signature_t {
            x: self.x,
            y: self.y,
        };
    }
}

impl From<sgx_ec256_signature_t> for Signature {
    fn from(sig: sgx_ec256_signature_t) -> Self {
        Self { x: sig.x, y: sig.y }
    }
}

// secret shared by server & user
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Debug, Serialize, Deserialize)]
pub struct ServerSecret {
    pub secret: [u8; SGX_HMAC256_KEY_SIZE], // sgx_cmac_128bit_key_t
                                            // TODO: add server public key & signature
                                            // pubkey: PubKey,
                                            // sig: Signature,
}
