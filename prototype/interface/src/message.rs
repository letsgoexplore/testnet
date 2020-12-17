use std::prelude::v1::*;

use crate::key::*;
use crate::params::*;

big_array! { BigArray; }

// this is what a user wants to broadcast through DC net
pub type RawMessage = [u8; DC_NET_MESSAGE_LENGTH];

pub fn test_raw_msg() -> RawMessage {
    [0x9c; DC_NET_MESSAGE_LENGTH]
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
