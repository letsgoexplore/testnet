use crate::attestation::Attested;
use crate::crypto::{SharedSecretsDb, SharedSecretsDbClient};
use ecall::keygen::{
    new_sgx_keypair_ext_internal,
    new_keypair_ext_internal,
};

use interface::*;
use sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
use sgx_types::SgxResult;
use std::string::ToString;
use std::vec::Vec;
use std::collections::BTreeMap;
use unseal::SealInto;

use ed25519_dalek::PublicKey;

/// Derives shared secrets with all the given KEM pubkeys, and derives a new signing pubkey.
/// Returns sealed secrets, a sealed private key, and a registration message to send to an
/// anytrust node
pub fn new_user(
    anytrust_server_pks: &Vec<ServerPubKeyPackage>,
) -> SgxResult<(SealedSharedSecretDb, SealedSigPrivKey, UserRegistrationBlob)> {
    // 1. validate the input
    let mut kem_pks = vec![];
    for k in anytrust_server_pks {
        if !k.verify_attestation() {
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }

        kem_pks.push(k.kem);
    }

    let role = "user".to_string();

    // 2. generate a SGX protected key. used for both signing and round key derivation
    let (sk, pk) = new_sgx_keypair_ext_internal(&role)?;

    // 3. derive server secrets
    let server_secrets = SharedSecretsDb::derive_shared_secrets(&sk, &kem_pks)?;

    debug!("DH secrets {:?}", server_secrets);

    Ok((server_secrets.seal_into()?, sk.seal_into()?, pk))
}


pub fn new_user_batch(
    (anytrust_server_pks, n_user): &(Vec<ServerPubKeyPackage>, usize),
) -> SgxResult<Vec<(SealedSharedSecretDb, SealedSigPrivKey, UserRegistrationBlob)>> {
    let mut users = vec![];
    for _ in 0..*n_user {
        let u = new_user(anytrust_server_pks)?;
        users.push(u);
    }

    Ok(users)
}

/// Derives shared secrets with all the given KEM pubkeys, and derived a new signing pubkey.
/// Returns sealed secrets, a sealed private key, and a registration message to send to an
/// anytrust node
pub fn new_user_updated(
    anytrust_server_pks: &Vec<ServerPubKeyPackageNoSGX>,
) -> SgxResult<(SealedSharedSecretsDbClient, SealedSigPrivKeyNoSGX, UserRegistrationBlobNew)> {
    // 1. validate the input
    let mut kem_db: BTreeMap<NoSgxProtectedKeyPub, PublicKey> = BTreeMap::new();
    // let mut kem_pks = vec![];
    for k in anytrust_server_pks {
        // kem_pks.push(k.kem);
        kem_db.insert(k.xkem, k.kem);
    }

    let role = "user".to_string();

    // 2. generate a key pair. used for both signing and round key derivation
    let (sk, pk) = new_keypair_ext_internal(&role)?;

    // 3. derive server secrets
    let server_secrets = SharedSecretsDbClient::derive_shared_secrets(&sk, &kem_db)?;

    let (key, value) = server_secrets.db.first_key_value().unwrap();

    Ok((server_secrets.seal_into()?, sk.seal_into()?, pk))
}

pub fn new_user_batch_updated(
    (anytrust_server_pks, n_user): &(Vec<ServerPubKeyPackageNoSGX>, usize),
) -> SgxResult<Vec<(SealedSharedSecretsDbClient, SealedSigPrivKeyNoSGX, UserRegistrationBlobNew)>> {
    let mut users = vec![];
    for _ in 0..*n_user {
        let u = new_user_updated(anytrust_server_pks)?;
        users.push(u);
    }
    
    Ok(users)
}