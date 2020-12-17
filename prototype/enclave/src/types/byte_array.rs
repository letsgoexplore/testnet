use crate::interface::*;
use crate::types::*;
use sgx_serialize::{Decoder, Encoder};
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::ops::Deref;
use std::prelude::v1::*;

impl Zero for RawMessage {
    fn zero() -> Self {
        [0 as u8; DC_NET_MESSAGE_LENGTH]
    }
}

impl Xor for RawMessage {
    fn xor(&self, other: &Self) -> Self {
        let mut result = RawMessage::zero();
        let msg: Vec<u8> = self.iter().zip(other).map(|(x, y)| x ^ y).collect();
        for i in 0..msg.len() {
            result[i] = msg[i];
        }

        result
    }
}

impl Xor for Vec<u8> {
    fn xor(&self, other: &Self) -> Self {
        self.iter().zip(other).map(|(x, y)| x ^ y).collect()
    }
}

// a wrapper around RawMessage so that we can impl traits
#[derive(Clone)]
pub struct DCMessage {
    pub msg: RawMessage,
}

use crate::hex;

impl Debug for DCMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(&hex::encode(&self))
    }
}

impl Xor for DCMessage {
    fn xor(&self, other: &DCMessage) -> Self {
        DCMessage {
            msg: self.msg.xor(&other.msg),
        }
    }
}

impl From<RawMessage> for DCMessage {
    fn from(raw: [u8; 1024]) -> Self {
        return DCMessage { msg: raw };
    }
}

impl Deref for DCMessage {
    type Target = RawMessage;

    fn deref(&self) -> &Self::Target {
        &self.msg
    }
}

impl AsRef<[u8]> for DCMessage {
    fn as_ref(&self) -> &[u8] {
        &self.msg
    }
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
        let mut msg = RawMessage::zero();

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

impl Zero for DCMessage {
    fn zero() -> Self {
        DCMessage {
            msg: RawMessage::zero(),
        }
    }
}

use sgx_rand::{Rand, Rng};

impl Rand for DCMessage {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        let mut r = DCMessage::zero();
        rng.fill_bytes(&mut r.msg);

        r
    }
}

impl std::cmp::PartialEq for DCMessage {
    fn eq(&self, other: &Self) -> bool {
        self.msg.iter().zip(&other.msg).all(|(x, y)| x == y)
    }
}
