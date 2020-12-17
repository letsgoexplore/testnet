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
