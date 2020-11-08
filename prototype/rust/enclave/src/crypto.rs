use crate::sgx_types::{SGX_HMAC256_KEY_SIZE, SGX_HMAC256_MAC_SIZE};
use crate::std::prelude::v1::*;
use interface::*;

use sgx_types::sgx_status_t;
use sgx_types::SgxResult;

use error::*;

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

pub fn kdf_hmac(secret: &ServerSecret, round: u32) -> CryptoResult<RoundSecret> {
    if secret.secret.len() != SGX_HMAC256_KEY_SIZE {
        return Err(CryptoError::KeyError);
    }

    let mut result = Vec::with_capacity(DC_NET_MESSAGE_LENGTH);

    let num_chunks = (DC_NET_MESSAGE_LENGTH + SGX_HMAC256_MAC_SIZE - 1) / SGX_HMAC256_MAC_SIZE;
    for i in 0..num_chunks {
        let counter = [round, i as u32];

        match sgx_tcrypto::rsgx_hmac_sha256_slice(&secret.secret, &counter) {
            Err(x) => return Err(CryptoError::SgxCryptoError(x)),
            Ok(buf) => result.extend_from_slice(&buf),
        }
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

    sha256
        .init()
        .or_else(|e| return Err(CryptoError::SgxCryptoError(e)));
    sha256
        .update_msg(&msg.round)
        .or_else(|e| return Err(CryptoError::SgxCryptoError(e)));
    sha256
        .update_slice(&msg.message)
        .or_else(|e| return Err(CryptoError::SgxCryptoError(e)));

    let msg_hash = match sha256.get_hash() {
        Ok(h) => h,
        Err(e) => return Err(CryptoError::SgxCryptoError(e)),
    };

    let ecdsa_handler = sgx_tcrypto::SgxEccHandle::new();
    ecdsa_handler
        .open()
        .or_else(|e| return Err(CryptoError::SgxCryptoError(e)));

    let sig = match ecdsa_handler.ecdsa_sign_slice(&msg_hash, &tee_prv_key.into()) {
        Ok(sig) => sig,
        Err(e) => return Err(CryptoError::SgxCryptoError(e)),
    };

    return Ok(SignedUserMessage {
        round: msg.round,
        message: msg.message,
        tee_sig: Signature::from(sig),
        tee_pk: PubKey::from(tee_pk),
    });
}

pub fn verify_dc_message(msg: &SignedUserMessage) -> CryptoResult<bool> {
    let sha256 = sgx_tcrypto::SgxShaHandle::new();
    sha256
        .init()
        .or_else(|e| return Err(CryptoError::SgxCryptoError(e)));
    sha256
        .update_msg(&msg.round)
        .or_else(|e| return Err(CryptoError::SgxCryptoError(e)));
    sha256
        .update_slice(&msg.message)
        .or_else(|e| return Err(CryptoError::SgxCryptoError(e)));

    let msg_hash = match sha256.get_hash() {
        Ok(h) => h,
        Err(e) => return Err(CryptoError::SgxCryptoError(e)),
    };

    let ecdsa_handler = sgx_tcrypto::SgxEccHandle::new();
    ecdsa_handler.open();

    match ecdsa_handler.ecdsa_verify_slice(&msg_hash, &msg.tee_pk.into(), &msg.tee_sig.into()) {
        Ok(verified) => Ok(verified),
        Err(e) => Err(CryptoError::SgxCryptoError(e)),
    }
}
