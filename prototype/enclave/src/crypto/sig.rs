use crate::interface::*;

use std::prelude::v1::*;

use super::*;

use byteorder::{ByteOrder, LittleEndian};
use messages_types::SignedUserMessage;

impl Signable for SignedUserMessage {
    fn digest(&self) -> Vec<u8> {
        // pub user_id: EntityId,
        // pub anytrust_group_id: EntityId,
        // pub round: u32,
        // pub msg: DcMessage,

        let mut output = Vec::new();

        output.resize(4, 0);
        LittleEndian::write_u32(&mut output, self.round);

        output.extend_from_slice(&self.user_id.0);
        output.extend_from_slice(&self.anytrust_group_id.0);
        output.extend_from_slice(&self.msg.0);

        output
    }

    fn get_sig(&self) -> SgxSignature {
        self.tee_sig
    }

    fn get_pk(&self) -> SgxSigningPubKey {
        self.tee_pk
    }
}

impl SignMutable for SignedUserMessage {
    fn sign_mut(&mut self, tee_prv_key: &SgxSigningKey) -> SgxError {
        let (sig, pk) = self.sign(tee_prv_key)?;
        self.tee_sig = sig;
        self.tee_pk = pk;
        Ok(())
    }
}
