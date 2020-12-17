use crate::interface::*;
use sgx_tcrypto;
use sgx_types::SgxResult;
use std::prelude::v1::*;

use super::CryptoError;
use super::CryptoResult;
use super::{SignMutable, Verifiable};

use byteorder::{ByteOrder, LittleEndian};

fn serialize_for_sign(msg: &SignedUserMessage) -> Vec<u8> {
    // pub user_id: UserId,
    // pub round: u32,
    // pub message: RawMessage,
    // pub tee_sig: Signature,
    // pub tee_pk: PubKey,

    let mut output = Vec::new();

    output.resize(4, 0);
    println!("output len {}", output.len());
    LittleEndian::write_u32(&mut output, msg.round);

    output.extend(&msg.user_id[..]);
    output.extend(&msg.message[..]);

    output
}

impl SignMutable for SignedUserMessage {
    fn sign(&mut self, tee_prv_key: &PrvKey) -> CryptoResult<()> {
        // serialize for signing
        let msg_hash = serialize_for_sign(self);

        let ecdsa_handler = sgx_tcrypto::SgxEccHandle::new();
        ecdsa_handler.open()?;

        self.tee_pk = sgx_tcrypto::rsgx_ecc256_pub_from_priv(&tee_prv_key.into())
            .map(PubKey::from)
            .map_err(CryptoError::SgxCryptoError)?;

        self.tee_sig = ecdsa_handler
            .ecdsa_sign_slice(&msg_hash, &tee_prv_key.into())
            .map(Signature::from)?;

        Ok(())
    }
}

impl Verifiable for SignedUserMessage {
    fn verify(&self) -> CryptoResult<bool> {
        let msg_hash = serialize_for_sign(self);

        let ecdsa_handler = sgx_tcrypto::SgxEccHandle::new();
        ecdsa_handler.open()?;

        ecdsa_handler
            .ecdsa_verify_slice(&msg_hash, &self.tee_pk.into(), &self.tee_sig.into())
            .map_err(CryptoError::from)
    }
}
