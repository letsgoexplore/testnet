use std::prelude::v1::*;

use crate::key;
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
    #[serde(with = "BigArray")]
    pub message: RawMessage,
    pub round: u32,
    pub server_keys: Vec<key::ServerSecret>,
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Debug)]
pub struct SignedUserMessage {
    pub round: u32,
    #[serde(with = "BigArray")]
    pub message: RawMessage,
    pub tee_sig: key::Signature,
    pub tee_pk: key::PubKey,
}

#[cfg(feature = "trusted")]
use byteorder::{ByteOrder, LittleEndian};
#[cfg(feature = "trusted")]
impl SignedUserMessage {
    pub fn serialize_for_sign(&self) -> Vec<u8> {
        let mut output = std::vec![0; 4 /* u32 */ + DC_NET_MESSAGE_LENGTH];
        LittleEndian::write_u32(&mut output, self.round);
        output[4..].clone_from_slice(&self.message);

        output
    }
}
