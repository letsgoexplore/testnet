use sgx_types::{sgx_ec256_signature_t, SGX_NISTP_ECP256_KEY_SIZE};

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
