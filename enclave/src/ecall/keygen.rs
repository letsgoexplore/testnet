use core::convert::TryFrom;
use interface::*;
use sgx_rand::{Rand, Rng};
use sgx_types::sgx_status_t::SGX_ERROR_UNEXPECTED;
use sgx_types::SgxResult;
use std::string::ToString;
use std::vec;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;

use x25519_dalek::StaticSecret;
use x25519_dalek::PublicKey as xPublicKey;
use ed25519_dalek::SecretKey;
use ed25519_dalek::{Keypair, SECRET_KEY_LENGTH};
use crypto::ed25519pk_from_sk;
use crate::crypto::SgxPrivateKey;

pub fn new_keypair_ext_internal(role: &str) -> SgxResult<(SgxPrivateKey, AttestedPublicKey)> {
    let mut rand = sgx_rand::SgxRng::new().map_err(|e| {
        error!("can't create rand {}", e);
        SGX_ERROR_UNEXPECTED
    })?;

    // generate a random secret key
    let secret = SgxPrivateKey::rand(&mut rand);
    log::debug!("secret {}, len={}", hex::encode(secret.r), secret.r.len());

    let x_secret = StaticSecret::from(secret.r);
    let xpk = xPublicKey::from(&x_secret);

    let pk = ed25519pk_from_sk(&secret)?;
    log::debug!("sk to pk succeed");
    let attested_key = AttestedPublicKey {
        pk: SgxProtectedKeyPub(pk.to_bytes()),
        xpk: SgxProtectedKeyPub(xpk.to_bytes()),
        role: role.to_string(),
        tee_linkable_attestation: vec![0], // TODO: add attestation
    };

    Ok((secret, attested_key))
}
