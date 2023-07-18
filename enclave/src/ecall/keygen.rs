use core::convert::TryFrom;
use crypto::SgxPrivateKey;
use interface::*;
use sgx_rand::Rng;
use sgx_types::sgx_status_t::SGX_ERROR_UNEXPECTED;
use sgx_types::SgxResult;
use std::string::ToString;
use std::vec;

use x25519_dalek::{StaticSecret, PublicKey};

pub fn new_sgx_keypair_ext_internal(role: &str) -> SgxResult<(SgxPrivateKey, AttestedPublicKey)> {
    let mut rand = sgx_rand::SgxRng::new().map_err(|e| {
        error!("cant create rand {}", e);
        SGX_ERROR_UNEXPECTED
    })?;

    // generate a random secret key
    let sk = rand.gen::<SgxPrivateKey>();
    let attested_key = AttestedPublicKey {
        pk: SgxSigningPubKey::try_from(&sk)?,
        role: role.to_string(),
        tee_linkable_attestation: vec![0], // TODO: add attestation
    };

    Ok((sk, attested_key))
}

pub fn new_keypair_ext_internal(role: &str) -> SgxResult<(NoSgxPrivateKey, AttestedPublicKeyNoSGX)> {
    let mut rand = sgx_rand::SgxRng::new().map_err(|e| {
        error!("can't create rand {}", e);
        SGX_ERROR_UNEXPECTED
    })?;

    // generate a random secret key
    let sk = rand.gen::<NoSgxPrivateKey>();
    let secret = StaticSecret::from(sk.r);
    let xpk = PublicKey::from(&secret);
    let attested_key = AttestedPublicKeyNoSGX {
        pk: NoSgxProtectedKeyPub::try_from(&sk).map_err(|e| {
            error!("can't generate NoSgxProtectedKeyPub from NoSgxPrivateKey: {}", e);
            SGX_ERROR_UNEXPECTED
        })?,
        xpk: NoSgxProtectedKeyPub(xpk.to_bytes()),
        role: role.to_string(),
        tee_linkable_attestation: vec![0], // TODO: add attestation
    };

    debug!("[user new_keypair_ext_internal] sk: {:?}", sk);
    debug!("[user new_keypair_ext_internal] pk: {:?}", attested_key.pk);
    debug!("[user new_keypair_ext_internal] xpk: {:?}", attested_key.xpk);
    debug!("[user new_keypair_ext_internal] sk bytes: {:?}", sk.r.as_slice());
    debug!("[user new_keypair_ext_internal] pk bytes: {:?}", attested_key.pk.0.as_slice());
    debug!("[user new_keypair_ext_internal] xpk bytes: {:?}", attested_key.xpk.0);  

    Ok((sk, attested_key))
}
