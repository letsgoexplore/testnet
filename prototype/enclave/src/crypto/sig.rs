use crate::interface::*;


use std::prelude::v1::*;

use super::*;

use byteorder::{ByteOrder, LittleEndian};

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

        output.extend(self.user_id.as_ref());
        output.extend(&self.message[..]);

        output
    }

    fn get_sig(&self) -> Signature {
        self.tee_sig
    }

    fn get_pk(&self) -> PubKey {
        self.tee_pk
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
