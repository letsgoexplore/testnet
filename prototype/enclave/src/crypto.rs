use interface::*;
use sgx_types::{SGX_HMAC256_KEY_SIZE, SGX_HMAC256_MAC_SIZE};
use std::prelude::v1::*;

use error::*;
use std::convert::TryInto;

use byteorder::{ByteOrder, LittleEndian};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

pub fn xor(a: &[u8], b: &[u8]) -> CryptoResult<Vec<u8>> {
    if a.len() != b.len() {
        return Err(CryptoError::XorNotEqualLength);
    }
    return Ok(a.iter().zip(b).map(|(x, y)| x ^ y).collect());
}

pub type CryptoResult<T> = Result<T, CryptoError>;

pub struct RoundSecret {
    pub secret: [u8; DC_NET_MESSAGE_LENGTH],
}

impl RoundSecret {
    pub fn zero() -> Self {
        return RoundSecret {
            secret: [0; DC_NET_MESSAGE_LENGTH],
        };
    }

    pub fn xor(a: &RoundSecret, b: &RoundSecret) -> Self {
        let mut output = RoundSecret::zero();

        for i in 0..DC_NET_MESSAGE_LENGTH {
            output.secret[i] = a.secret[i] ^ b.secret[i]
        }

        output
    }

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
                Err(e) => Err(CryptoError::Other),
            }
        })
        .collect::<CryptoResult<Vec<RoundSecret>>>()?;

    // xor all keys
    Ok(server_round_keys
        .iter()
        .fold(RoundSecret::zero(), |acc, s| RoundSecret::xor(&acc, s)))
}

pub fn sign_dc_message(
    msg: &SignedUserMessage,
    tee_prv_key: &PrvKey,
) -> CryptoResult<SignedUserMessage> {
    let tee_pk = match sgx_tcrypto::rsgx_ecc256_pub_from_priv(&tee_prv_key.into()) {
        Ok(pk) => pk,
        Err(e) => return Err(CryptoError::SgxCryptoError(e)),
    };

    let msg_hash = msg.serialize_for_sign();

    let ecdsa_handler = sgx_tcrypto::SgxEccHandle::new();
    ecdsa_handler.open()?;
    let sig = ecdsa_handler.ecdsa_sign_slice(&msg_hash, &tee_prv_key.into())?;

    Ok(SignedUserMessage {
        round: msg.round,
        message: msg.message,
        tee_sig: Signature::from(sig),
        tee_pk: PubKey::from(tee_pk),
    })
}

pub fn verify_dc_message(msg: &SignedUserMessage) -> CryptoResult<bool> {
    let msg_hash = msg.serialize_for_sign();

    let ecdsa_handler = sgx_tcrypto::SgxEccHandle::new();
    ecdsa_handler.open()?;

    ecdsa_handler
        .ecdsa_verify_slice(&msg_hash, &msg.tee_pk.into(), &msg.tee_sig.into())
        .map_err(CryptoError::from)
}
