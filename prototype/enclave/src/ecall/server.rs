use crate::crypto::{
    derive_round_secret, KemPrvKey, SgxPrivateKey, SharedSecretsDb, SignMutable, Signable,
};
use crate::types::{MarshallAs, Xor};
use crate::{messages_types, utils};
use interface::*;
use sgx_types::sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
use sgx_types::SgxResult;
use std::borrow::ToOwned;
use std::collections::BTreeMap;
use std::{debug, vec};

/// This file implements ecalls used by an anytrust server

/// Verifies and adds the given user registration blob to the database of pubkeys and
/// shared secrets
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

    let mut others_kem_pks = vec![];
    for (_, k) in pk_db.db.iter() {
        others_kem_pks.push(k.pk);
    }

    let shared_secrets = SharedSecretsDb::derive_shared_secrets(&my_kem_sk, &others_kem_pks)?;

    info!("shared_secrets {:?}", shared_secrets);

    Ok((pk_db, shared_secrets.to_sealed_db()?))
}

pub fn recv_aggregator_registration(
    input: &(SignedPubKeyDb, AggRegistrationBlob),
) -> SgxResult<SignedPubKeyDb> {
    let (pk_db, attested_pk) = input;
    let mut pk_db = pk_db.clone();

    // verify user key
    let attested_pk = &attested_pk.0;
    warn!("skipping verifying attestation for now");

    // add user key to pubkey db
    pk_db
        .db
        .insert(EntityId::from(&attested_pk.pk), attested_pk.to_owned());

    Ok(pk_db)
}

pub fn recv_server_registration(
    input: &(SignedPubKeyDb, ServerRegistrationBlob),
) -> SgxResult<SignedPubKeyDb> {
    let (pk_db, attested_pk) = input;
    let mut pk_db = pk_db.clone();

    // verify user key
    let attested_pk = &attested_pk.kem_key;
    warn!("skipping verifying attestation for now");

    // add user key to pubkey db
    pk_db
        .db
        .insert(EntityId::from(&attested_pk.pk), attested_pk.to_owned());

    Ok(pk_db)
}

use types::{UnmarshallableAs, UnsealableAs};

/// XORs the shared secrets into the given aggregate. Returns the server's share of the
/// unblinded aggregate
/// called by an anytrust server.
pub fn unblind_aggregate(
    input: &(RoundSubmissionBlob, SealedSigPrivKey, SealedSharedSecretDb),
) -> SgxResult<UnblindedAggregateShareBlob> {
    let round_msg = input.0.unmarshal()?;
    let sig_key = input.1.unseal()?;
    let secret_db = input.2.unseal()?;

    let round_secret = derive_round_secret(round_msg.round, &secret_db).map_err(|e| {
        error!("crypto error");
        SGX_ERROR_INVALID_PARAMETER
    })?;

    // XOR server's secrets
    // round_msg.aggregated_msg.xor_mut(&round_secret);

    let mut unblined_agg = messages_types::UnblindedAggregateShare {
        encrypted_msg: round_msg,
        key_share: round_secret,
        sig: Default::default(),
        pk: Default::default(),
    };

    // sign
    unblined_agg.sign_mut(&sig_key)?;

    Ok(unblined_agg.marshal()?)
}

use std::vec::Vec;

pub fn derive_round_output(shares: &Vec<UnblindedAggregateShareBlob>) -> SgxResult<RoundOutput> {
    if shares.is_empty() {
        error!("empty shares array");
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    // TODO: check all shares are for the same around & same message

    // Xor of all server secrets
    let mut final_msg = DcMessage::default();
    for s in shares.iter() {
        let share = s.unmarshal()?;
        final_msg.xor_mut(&share.key_share);
    }

    // Finally xor secrets with the message
    final_msg.xor_mut(&shares[0].unmarshal()?.encrypted_msg.aggregated_msg);

    Ok(RoundOutput(final_msg))
}
