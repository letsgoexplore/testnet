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

#[cfg(feature = "trusted")]
impl sgx_serialize::Serializable for Signature {
    fn encode<S: sgx_serialize::Encoder>(
        &self,
        s: &mut S,
    ) -> Result<(), <S as sgx_serialize::Encoder>::Error> {
        for elem in &self.x {
            s.emit_u32(*elem)?;
        }
        for elem in &self.y {
            s.emit_u32(*elem)?;
        }
        Ok(())
    }
}

#[cfg(feature = "trusted")]
impl sgx_serialize::DeSerializable for Signature {
    fn decode<D: sgx_serialize::Decoder>(
        d: &mut D,
    ) -> Result<Self, <D as sgx_serialize::Decoder>::Error> {
        let mut sig = Signature::default();
        for i in 0..sig.x.len() {
            sig.x[i] = d.read_u32()?
        }

        for i in 0..sig.y.len() {
            sig.y[i] = d.read_u32()?
        }

        Ok(sig)
    }
}
