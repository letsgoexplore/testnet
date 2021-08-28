use crate::crypto::{
    derive_round_secret, KemPrvKey, SgxPrivateKey, SharedSecretsDb, SignMutable, Signable,
};
use crate::types::{MarshallAs, Xor};
use crate::{messages_types, utils};
use interface::*;
use sgx_types::sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
use sgx_types::SgxResult;
use std::borrow::ToOwned;
use std::collections::{BTreeMap, BTreeSet};
use std::{debug, vec};
use types::{UnmarshallableAs, UnsealableAs};

/// This file implements ecalls used by an anytrust server

/// Verifies and adds the given user registration blob to the database of pubkeys and
/// shared secrets
/// TODO: the second input is currently not used. We always build a new SealedSharedSecretDb from SignedPubKeyDb.
pub fn recv_user_registration(
    input: &(
        SignedPubKeyDb,
        SealedSharedSecretDb,
        SealedKemPrivKey,
        UserRegistrationBlob,
    ),
) -> SgxResult<(SignedPubKeyDb, SealedSharedSecretDb)> {
    let mut pk_db = input.0.clone();

    // verify user key
    let user_pk = &input.3;
    let attested_pk = &user_pk.0;
    warn!("skipping verifying attested_pk for now");

    // add user key to pubkey db
    pk_db
        .users
        .insert(EntityId::from(&attested_pk.pk), attested_pk.to_owned());

    // Derive secrets
    let my_kem_sk: SgxPrivateKey = input.2.unseal()?;
    let mut others_kem_pks = vec![];
    for (_, k) in pk_db.users.iter() {
        others_kem_pks.push(k.pk);
    }

    let shared_secrets = SharedSecretsDb::derive_shared_secrets(&my_kem_sk, &others_kem_pks)?;

    debug!("shared_secrets {:?}", shared_secrets);

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
        .aggregators
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
        .servers
        .insert(EntityId::from(&attested_pk.pk), attested_pk.to_owned());

    Ok(pk_db)
}

use std::iter::FromIterator;

/// XORs the shared secrets into the given aggregate. Returns the server's share of the
/// unblinded aggregate
/// called by an anytrust server.
pub fn unblind_aggregate(
    input: &(RoundSubmissionBlob, SealedSigPrivKey, SealedSharedSecretDb),
) -> SgxResult<UnblindedAggregateShareBlob> {
    let round_msg = input.0.unmarshal()?;
    let sig_key = input.1.unseal()?;
    let secret_db = input.2.unseal()?;

    let user_ids_in_secret_db = BTreeSet::from_iter(secret_db.db.keys().map(EntityId::from));
    let user_ids_in_submission = BTreeSet::from_iter(round_msg.user_ids.iter().cloned());
    if !(user_ids_in_submission == user_ids_in_secret_db
        || user_ids_in_submission.is_subset(&user_ids_in_secret_db))
    {
        error!("submission.user_ids is not a subset of user_ids_in_secret_db. user_ids_in_submission = {:?}, user_ids_in_secret_db= {:?}",
        user_ids_in_submission,
        user_ids_in_secret_db);
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

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

    // We require all s in shares should have the same aggregated_msg
    let final_aggregation = shares[0].unmarshal()?.encrypted_msg.aggregated_msg;

    for s in shares.iter() {
        let share = s.unmarshal()?;
        if share.encrypted_msg.aggregated_msg != final_aggregation {
            error!("share {:?} has a different final agg", share);
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
        final_msg.xor_mut(&share.key_share);
    }

    // Finally xor secrets with the message
    final_msg.xor_mut(&final_aggregation);

    info!("final msg {}", hex::encode(&final_msg));

    Ok(RoundOutput(final_msg))
}
