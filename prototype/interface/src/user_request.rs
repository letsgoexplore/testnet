use std::prelude::v1::*;

use crate::key::*;
use crate::params::*;
use crate::signature::*;
use sgx_types::SGX_HMAC256_KEY_SIZE;
use std::fmt::{Debug, Formatter, Result as FmtResult};

big_array! { BigArray; }

// this is what a user wants to broadcast through DC net
pub type RawMessage = [u8; DC_NET_MESSAGE_LENGTH];

pub fn test_raw_msg() -> RawMessage {
    [0x9c; DC_NET_MESSAGE_LENGTH]
}

// a wrapper around RawMessage so that we can impl traits
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize)]
pub struct DCMessage {
    #[serde(with = "BigArray")]
    msg: RawMessage,
}

#[cfg(feature = "trusted")]
use crate::traits::Zero;
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

impl AsRef<[u8]> for DCMessage {
    fn as_ref(&self) -> &[u8] {
        &self.msg
    }
}

impl AsRef<RawMessage> for DCMessage {
    fn as_ref(&self) -> &RawMessage {
        &self.msg
    }
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct UserId {
    raw: [u8; USER_ID_LENGTH],
}

impl Debug for UserId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(&hex::encode(self.raw))
    }
}

impl AsRef<[u8]> for UserId {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl From<[u8; USER_ID_LENGTH]> for UserId {
    fn from(raw: [u8; USER_ID_LENGTH]) -> Self {
        Self { raw }
    }
}

// secret shared by server & user
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Debug, Serialize, Deserialize)]
pub struct ServerSecret {
    pub secret: [u8; SGX_HMAC256_KEY_SIZE],
    // sgx_cmac_128bit_key_t
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
#[derive(Serialize, Deserialize)]
pub struct SendRequest {
    pub user_id: UserId,
    pub round: u32,
    #[serde(with = "BigArray")]
    pub message: RawMessage,
    pub server_keys: Vec<ServerSecret>,
}

impl Debug for SendRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendRequest")
            .field("userId", &self.user_id)
            .field("round", &self.round)
            .field("message", &hex::encode(self.message))
            .field("server", &self.server_keys)
            .finish()
    }
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize)]
pub struct SignedUserMessage {
    pub user_id: UserId,
    pub round: u32,
    #[serde(with = "BigArray")]
    pub message: RawMessage,
    pub tee_sig: Signature,
    pub tee_pk: PubKey,
}

impl Debug for SignedUserMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedUserMessage")
            .field("user_id", &self.user_id)
            .field("round", &self.round)
            .field("message", &hex::encode(self.message))
            .field("tee_sig", &self.tee_sig)
            .field("tee_pk", &self.tee_pk)
            .finish()
    }
}
