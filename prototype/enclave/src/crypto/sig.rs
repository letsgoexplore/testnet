use crate::interface::*;
use sgx_tcrypto;
use sgx_types::SgxResult;
use std::prelude::v1::*;

use super::*;

use byteorder::{ByteOrder, LittleEndian};

fn serialize_for_sign(msg: &SignedUserMessage) -> Vec<u8> {
    // pub user_id: UserId,
    // pub round: u32,
    // pub message: RawMessage,
    // pub tee_sig: Signature,
    // pub tee_pk: PubKey,

    let mut output = Vec::new();

    output.resize(4, 0);
    LittleEndian::write_u32(&mut output, msg.round);

    output.extend(&msg.user_id[..]);
    output.extend(&msg.message[..]);

    output
}

impl Signable for SignedUserMessage {
    fn digest(&self) -> Vec<u8> {
        // pub user_id: UserId,
        // pub round: u32,
        // pub message: RawMessage,
        // pub tee_sig: Signature,
        // pub tee_pk: PubKey,

        let mut output = Vec::new();

        output.resize(4, 0);
        LittleEndian::write_u32(&mut output, self.round);

        output.extend(&self.user_id[..]);
        output.extend(&self.message[..]);

        output
    }
}

impl SignMutable for SignedUserMessage {
    fn sign_mut(&mut self, tee_prv_key: &PrvKey) -> CryptoResult<()> {
        let (sig, pk) = self.sign(tee_prv_key)?;
        self.tee_sig = sig;
        self.tee_pk = pk;
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
