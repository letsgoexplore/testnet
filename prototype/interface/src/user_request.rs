use std::prelude::v1::*;

use crate::key::*;
use crate::params::*;
use crate::signature::*;
use sgx_types::SGX_HMAC256_KEY_SIZE;

big_array! { BigArray; }

// this is what a user wants to broadcast through DC net
pub type RawMessage = [u8; DC_NET_MESSAGE_LENGTH];

pub fn test_raw_msg() -> RawMessage {
    [0x9c; DC_NET_MESSAGE_LENGTH]
}
// secret shared by server & user
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Debug, Serialize, Deserialize)]
pub struct ServerSecret {
    pub secret: [u8; SGX_HMAC256_KEY_SIZE], // sgx_cmac_128bit_key_t
    pubkey: PubKey,
    sig: Signature,
}

impl ServerSecret {
    pub fn gen_test(byte: u8) -> Self {
        return ServerSecret {
            secret: [byte; SGX_HMAC256_KEY_SIZE],
            pubkey: PubKey::default(), // dummy values
            sig: Signature::default(), // dummy values
        };
    }
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Debug)]
pub struct SendRequest {
    pub user_id: UserId,
    pub round: u32,
    #[serde(with = "BigArray")]
    pub message: RawMessage,
    pub server_keys: Vec<ServerSecret>,
}

// TODO: do this
// impl Debug for SendRequest {
//     fn fmt(&self, f: &mut Formatter<'_>) -> Result {
//         f.debug_struct()
//     }
// }

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Debug)]
pub struct SignedUserMessage {
    pub user_id: UserId,
    pub round: u32,
    #[serde(with = "BigArray")]
    pub message: RawMessage,
    pub tee_sig: Signature,
    pub tee_pk: PubKey,
}

pub trait Size {
    fn size() -> usize;
    fn size_marshalled() -> usize;
}

impl<T> Size for T {
    fn size() -> usize {
        std::mem::size_of::<T>()
    }

    fn size_marshalled() -> usize {
        std::mem::size_of::<T>() * 2
    }
}

// a wrapper around RawMessage so that we can impl traits
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize)]
pub struct DCMessage {
    #[serde(with = "BigArray")]
    pub msg: RawMessage,
}

// return a reasonable zero value
pub trait Zero {
    fn zero() -> Self;
}

impl Zero for RawMessage {
    fn zero() -> Self {
        [0 as u8; DC_NET_MESSAGE_LENGTH]
    }
}

impl Zero for DCMessage {
    fn zero() -> Self {
        DCMessage {
            msg: RawMessage::zero(),
        }
    }
}

use std::ops::Deref;

#[cfg(feature = "trusted")]
use sgx_rand::{Rand, Rng};
#[cfg(feature = "trusted")]
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

use std::fmt::{Debug, Formatter, Result as FmtResult};

impl Debug for DCMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(&hex::encode(&self))
    }
}

impl From<RawMessage> for DCMessage {
    fn from(raw: RawMessage) -> Self {
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
