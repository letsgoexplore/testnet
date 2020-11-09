use crate::sgx_types::{SGX_HMAC256_KEY_SIZE, SGX_HMAC256_MAC_SIZE};
use crate::std::prelude::v1::*;
use interface::*;

use error::*;
use std::convert::TryInto;

pub fn xor(a: &[u8], b: &[u8]) -> CryptoResult<Box<[u8]>> {
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
}

// TODO: This is a very simplistic KDF. We should use a proper one like HKDF in the final version.
pub fn kdf_hmac(secret: &ServerSecret, round: u32) -> CryptoResult<RoundSecret> {
    let key_len = secret.secret.len();
    let chunk_size = SGX_HMAC256_MAC_SIZE;

    let mut result = Vec::with_capacity(key_len);

    let num_chunks = (key_len + chunk_size - 1) / chunk_size;
    for i in 0..num_chunks {
        // input to PRF: round || counter
        let counter = [round, i as u32];
        let buf = sgx_tcrypto::rsgx_hmac_sha256_slice(&secret.secret, &counter)?;
        result.extend_from_slice(&buf);
    }

    let mut output: RoundSecret = RoundSecret::zero();
    for i in 0..output.secret.len() {
        output.secret[i] = result[i];
    }

    Ok(output)
}

pub fn derive_round_secret(
    round: u32,
    server_secrets: &Vec<ServerSecret>,
) -> CryptoResult<RoundSecret> {
    // for each key, run KDF, then xor together all outputs
    match server_secrets
        .iter()
        .map(|s| kdf_hmac(s, round))
        .collect::<CryptoResult<Vec<RoundSecret>>>()
    {
        Ok(round_secrets) => Ok(round_secrets
            .iter()
            .fold(RoundSecret::zero(), |acc, s| RoundSecret::xor(&acc, s))),
        Err(e) => Err(e),
    }
}

pub fn sign_dc_message(
    msg: &SignedUserMessage,
    tee_prv_key: PrvKey,
) -> CryptoResult<SignedUserMessage> {
    let tee_pk = match sgx_tcrypto::rsgx_ecc256_pub_from_priv(&tee_prv_key.into()) {
        Ok(pk) => pk,
        Err(e) => return Err(CryptoError::SgxCryptoError(e)),
    };

    let sha256 = sgx_tcrypto::SgxShaHandle::new();

    sha256.init()?;
    sha256.update_msg(&msg.round)?;
    sha256.update_slice(&msg.message)?;

    let msg_hash = sha256.get_hash()?;

    let ecdsa_handler = sgx_tcrypto::SgxEccHandle::new();
    ecdsa_handler.open()?;

    let sig = ecdsa_handler.ecdsa_sign_slice(&msg_hash, &tee_prv_key.into())?;

    return Ok(SignedUserMessage {
        round: msg.round,
        message: msg.message,
        tee_sig: Signature::from(sig),
        tee_pk: PubKey::from(tee_pk),
    });
}

pub fn verify_dc_message(msg: &SignedUserMessage) -> CryptoResult<bool> {
    let sha256 = sgx_tcrypto::SgxShaHandle::new();
    sha256.init()?;

    sha256.update_msg(&msg.round)?;
    sha256.update_slice(&msg.message)?;

    let msg_hash = sha256.get_hash()?;

    let ecdsa_handler = sgx_tcrypto::SgxEccHandle::new();
    ecdsa_handler.open()?;

    return ecdsa_handler
        .ecdsa_verify_slice(&msg_hash, &msg.tee_pk.into(), &msg.tee_sig.into())
        .map_err(CryptoError::from);
}
