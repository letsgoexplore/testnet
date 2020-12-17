use interface::*;

use std::prelude::v1::*;



use byteorder::{ByteOrder, LittleEndian};
use hkdf::Hkdf;
use sha2::Sha256;

use super::*;
use types::Xor;

pub struct RoundSecret {
    pub secret: [u8; DC_NET_MESSAGE_LENGTH],
}

impl Zero for RoundSecret {
    fn zero() -> Self {
        return RoundSecret {
            secret: [0; DC_NET_MESSAGE_LENGTH],
        };
    }
}

impl Xor for RoundSecret {
    fn xor(&self, other: &Self) -> Self {
        RoundSecret {
            secret: self.secret.xor(&other.secret),
        }
    }
}

impl RoundSecret {
    pub fn encrypt(&self, msg: &RawMessage) -> RawMessage {
        let raw: Vec<u8> = self.secret.iter().zip(msg).map(|(a, b)| a ^ b).collect();

        let mut output = [0; DC_NET_MESSAGE_LENGTH];

        for i in 0..DC_NET_MESSAGE_LENGTH {
            output[i] = raw[i];
        }

        output
    }
}

pub fn derive_round_secret(
    round: u32,
    server_secrets: &Vec<ServerSecret>,
) -> CryptoResult<RoundSecret> {
    // for each key, run KDF
    let server_round_keys = server_secrets
        .iter()
        .map(|s| {
            let hk = Hkdf::<Sha256>::new(None, &s.secret);

            let mut round_secret = RoundSecret::zero();

            // info denotes the input to HKDF
            // https://tools.ietf.org/html/rfc5869
            let mut info = [0; 32];
            LittleEndian::write_u32(&mut info, round);
            match hk.expand(&info, &mut round_secret.secret) {
                Ok(()) => Ok(round_secret),
                Err(e) => Err(CryptoError::Other(format!("HKDF {}", e))),
            }
        })
        .collect::<CryptoResult<Vec<RoundSecret>>>()?;

    // xor all keys
    Ok(server_round_keys
        .iter()
        .fold(RoundSecret::zero(), |acc, s| RoundSecret::xor(&acc, s)))
}
