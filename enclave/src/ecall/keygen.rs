use core::convert::TryFrom;
use interface::*;
use sgx_rand::{Rand, Rng};
use sgx_types::sgx_status_t::SGX_ERROR_UNEXPECTED;
use sgx_types::SgxResult;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::string::ToString;
use std::vec;

use crate::crypto::SgxPrivateKey;
use crypto::ed25519pk_from_secret;
use ed25519_dalek::SecretKey;
use ed25519_dalek::{Keypair, SECRET_KEY_LENGTH};
use x25519_dalek::PublicKey as xPublicKey;
use x25519_dalek::StaticSecret;

pub fn new_keypair_ext_internal(role: &str) -> SgxResult<(SgxPrivateKey, AttestedPublicKey)> {
    let mut rand = sgx_rand::SgxRng::new().map_err(|e| {
        error!("can't create rand {}", e);
        SGX_ERROR_UNEXPECTED
    })?;

    // generate a random secret key
    let secret = SgxPrivateKey::rand(&mut rand);

    let x_secret = StaticSecret::from(secret.r);
    let xpk = xPublicKey::from(&x_secret);
    let pk = ed25519pk_from_secret(&secret)?;

    log::debug!("new key pair created");
    log::debug!("xpk {}", hex::encode(xpk.to_bytes()));
    log::debug!(" pk {}", hex::encode(pk.to_bytes()));

    let attested_key = AttestedPublicKey {
        pk: SgxProtectedKeyPub(pk.to_bytes()),
        xpk: SgxProtectedKeyPub(xpk.to_bytes()),
        role: role.to_string(),
        tee_linkable_attestation: vec![0], // TODO: add attestation
    };

    Ok((secret, attested_key))
}
