use crate::interface::*;
use sgx_serialize::{Decoder, Encoder};
use std::prelude::v1::*;

#[derive(Clone)]
pub struct DCMessage {
    pub msg: [u8; DC_NET_MESSAGE_LENGTH],
}

impl sgx_serialize::Serializable for DCMessage {
    fn encode<S: sgx_serialize::Encoder>(
        &self,
        s: &mut S,
    ) -> Result<(), <S as sgx_serialize::Encoder>::Error> {
        s.emit_usize(self.msg.len())?;
        for elem in &self.msg {
            s.emit_u8(*elem)?;
        }
        Ok(())
    }
}

impl sgx_serialize::DeSerializable for DCMessage {
    fn decode<D: Decoder>(d: &mut D) -> Result<Self, <D as Decoder>::Error> {
        let mut msg = [0 as u8; DC_NET_MESSAGE_LENGTH];

        let len = d.read_usize()?;
        if len != DC_NET_MESSAGE_LENGTH {
            return Err(d.error("invalid len"));
        }

        for i in 0..len {
            msg[i] = d.read_u8()?;
        }

        Ok(DCMessage { msg })
    }
}

#[derive(Serializable, DeSerializable, Clone)]
pub struct AggregatedMessage {
    pub user_ids: Vec<UserId>,
    pub aggregated_msg: DCMessage,
    // pub tee_sig: Signature,
    // pub tee_pk: PubKey,
}
