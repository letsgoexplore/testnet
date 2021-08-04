use crate::crypto::{KemPrvKey, SgxPrivateKey, SharedSecretsDb, SignMutable, Signable};
use crate::utils;
use interface::*;
use sgx_types::sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
use sgx_types::SgxResult;
use std::borrow::ToOwned;
use std::collections::BTreeMap;
use std::{debug, vec};

/// This file implements ecalls used by an anytrust server

/// Verifies and adds the given user registration blob to the database of pubkeys and
/// shared secrets
/// Called by a server
pub fn recv_user_registration(
    input: &(
        SignedPubKeyDb,
        SealedSharedSecretDb,
        SealedKemPrivKey,
        UserRegistrationBlob,
    ),
) -> SgxResult<(SignedPubKeyDb, SealedSharedSecretDb)> {
    let (_, shared_secret_db, _my_kem_sk, user_pk) = input;
    let mut pk_db = input.0.clone();

    // verify user key
    let attested_pk = &user_pk.0;
    warn!("skipping verifying attestation for now");

    // add user key to pubkey db
    pk_db
        .db
        .insert(EntityId::from(&attested_pk.pk), attested_pk.to_owned());

    // Derive secrets
    let my_kem_sk: KemPrvKey = utils::unseal_vec_and_deser(&_my_kem_sk.0.sealed_sk)?;
    debug!("my_kem_sk {:?}", my_kem_sk);

    let mut others_kem_pks = vec![];
    for (_, k) in pk_db.db.iter() {
        others_kem_pks.push(k.pk);
    }

    debug!("others_kem_pks {:?}", others_kem_pks);

    let shared_secrets = SharedSecretsDb::derive_shared_secrets(&my_kem_sk, &others_kem_pks)?;

    Ok((pk_db, shared_secrets.to_sealed_db()?))
}
