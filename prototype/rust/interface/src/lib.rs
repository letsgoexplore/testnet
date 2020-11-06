#![no_std]

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "untrusted")] {
        #[macro_use]
        extern crate serde;
        #[macro_use]
        extern crate serde_big_array;
        extern crate std;
    } else if #[cfg(feature = "trusted")] {
        #[macro_use]
        extern crate serde_sgx;
        #[macro_use]
        extern crate serde_big_array_sgx as serde_big_array;
        extern crate sgx_tstd as std;
    } else {
        compile_error!{"must be either trusted or untrusted"}
    }
}

use std::prelude::v1::*;

big_array! { BigArray; }

pub const DC_NET_MESSAGE_LENGTH: usize = 1024;
pub const SERVER_KEY_LENGTH: usize = DC_NET_MESSAGE_LENGTH;
pub const FOOTPRINT_BIT_SIZE: usize = 3;
pub const USER_ID_MAX_LEN: usize = 32;

pub struct Footprint {
    fp: [bool; FOOTPRINT_BIT_SIZE]
}

pub struct SchedulingState {
    round: u32,
    reservation_map: Vec<bool>,
    footprints: Vec<Footprint>,
    sig: Vec<u8>,
    finished: bool,
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    #[serde(with = "BigArray")]
    pub msg: [u8; DC_NET_MESSAGE_LENGTH]
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Debug)]
pub struct ServerKey {
    #[serde(with = "BigArray")]
    key: [u8; SERVER_KEY_LENGTH]
}

impl ServerKey {
    pub fn zero() -> ServerKey {
        return ServerKey {
            key: [0; SERVER_KEY_LENGTH]
        };
    }
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Debug)]
pub struct SendRequest {
    pub message: Message,
    pub round: u32,
    pub server_keys: Vec<ServerKey>,
}


#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Debug)]
pub struct UserId {
    id: [u8; USER_ID_MAX_LEN]
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Debug)]
pub struct SignedUserMessage {
    round: u32,
    user_id: UserId,
    message: Message,
    sig: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use crate::{UserId, USER_ID_MAX_LEN};

    #[test]
    fn it_works() {
        let uid = UserId {
            id: [8; USER_ID_MAX_LEN]
        };


        assert_eq!(2 + 2, 4);
    }
}
