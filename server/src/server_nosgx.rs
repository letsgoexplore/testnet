use std::{vec, vec::Vec};
use crate::util::{Result, ServerError};

use interface::{
    EntityId,
    UserRegistrationBlobNew,
    ServerPubKeyPackageNoSGX,
    RoundSecret,
    RoundOutputUpdated,
    DcRoundMessage,
    SignatureNoSGX,
    MultiSignableUpdated,
    NoSgxProtectedKeyPub,
};

use ed25519_dalek::{
    SecretKey,
    PublicKey,
    Signature,
};

use x25519_dalek::{
    PublicKey as xPublicKey,
    StaticSecret,
};

use rand::rngs::OsRng;

use std::time::Instant;

use common::types_nosgx::{
    SignMutableNoSGX,
    XorNoSGX,
    MarshallAsNoSGX,
    UnmarshalledAsNoSGX,
    SharedSecretsDbServer,
    SignedPubKeyDbNoSGX,
    AggRegistrationBlobNoSGX,
    ServerRegistrationBlobNoSGX,
    AggregatedMessage,
    UnblindedAggregateShareBlobNoSGX,
    RoundSubmissionBlobNoSGX,
    UnblindedAggregateSharedNoSGX,
};

use common::funcs_nosgx::{
    verify_user_attestation,
    derive_round_secret_server,
};

use log::{
    debug,
    info,
    error,
};

use std::collections::{BTreeSet, BTreeMap};
use itertools::Itertools;
use std::iter::FromIterator;
use std::sync::mpsc;
use std::thread;

pub fn new_server() -> Result<(SecretKey, SecretKey, EntityId, ServerPubKeyPackageNoSGX)> {
    let mut csprng = OsRng{};
    let sig_key = SecretKey::generate(&mut csprng);
    let kem_key = SecretKey::generate(&mut csprng);

    let kem_secret = StaticSecret::from(kem_key.to_bytes());

    // The standard hash function used for most ed25519 libraries is SHA-512
    let sig_key_pk: PublicKey = (&sig_key).into();
    let kem_key_pk: PublicKey = (&kem_key).into();
    let kem_key_xpk: xPublicKey = xPublicKey::from(&kem_secret);

    let reg = ServerPubKeyPackageNoSGX {
        sig: sig_key_pk,
        kem: kem_key_pk,
        xkem: NoSgxProtectedKeyPub(kem_key_xpk.to_bytes()),
    };

    Ok((sig_key, kem_key, EntityId::from(&reg), reg))
}

pub fn recv_user_registration_batch(
    pubkeys: &mut SignedPubKeyDbNoSGX,
    shared_secrets: &mut SharedSecretsDbServer,
    decap_key: &SecretKey,
    input_blob: &[UserRegistrationBlobNew],
) -> Result<()> {
    let (new_pubkey_db, new_secrets_db) = recv_user_reg_batch(
        (pubkeys, decap_key, &input_blob.to_vec()),
    )?;

    pubkeys.users = new_pubkey_db.users;
    shared_secrets.db = new_secrets_db.db;

    Ok(())
}

fn recv_user_reg_batch(
    input: (&SignedPubKeyDbNoSGX, &SecretKey, &Vec<UserRegistrationBlobNew>),
) -> Result<(SignedPubKeyDbNoSGX, SharedSecretsDbServer)> {
    let mut pk_db: SignedPubKeyDbNoSGX = input.0.clone();
    let my_kem_sk = input.1;

    for u in input.2.iter() {
        // verify user key
        match verify_user_attestation(&u) {
            Ok(()) => {
                debug!("verify user registration attestation succeeded");
            },
            Err(e) => {
                error!("cannot verify user registration attestation: {:?}", e);
                return Err(ServerError::UnexpectedError);
            }
        }

        // add user key to pubkey db
        pk_db.users.insert(EntityId::from(&u.pk), u.clone());
    }

    // Derive secrets
    // let mut others_kem_pks = vec![];
    let mut others_kem_db: BTreeMap<NoSgxProtectedKeyPub, NoSgxProtectedKeyPub> = BTreeMap::new();
    for (_, k) in pk_db.users.iter() {
        // others_kem_pks.push(k.pk);
        others_kem_db.insert(k.xpk, k.pk);
    }

    let shared_secrets = SharedSecretsDbServer::derive_shared_secrets(&my_kem_sk, &others_kem_db)
        .expect("failed to derive shared secrets for server");

    Ok((pk_db, shared_secrets))
}

pub fn recv_aggregator_registration(
    pubkeys: &mut SignedPubKeyDbNoSGX,
    input_blob: &AggRegistrationBlobNoSGX
) -> Result<()> {
    let mut new_db = pubkeys.clone();
    let agg_pk = input_blob;

    // add agg key to pubkey db
    new_db
        .aggregators
        .insert(EntityId::from(&agg_pk.pk), agg_pk.to_owned());

    pubkeys.aggregators.clear();
    pubkeys.aggregators.extend(new_db.aggregators);

    Ok(())
}

pub fn recv_server_registration(
    pubkeys: &mut SignedPubKeyDbNoSGX,
    input_blob: &ServerRegistrationBlobNoSGX
) -> Result<()> {
    let mut new_db = pubkeys.clone();
    let server_pk = input_blob;

    // add server key to pubkey db
    new_db
        .servers
        .insert(EntityId::from(&server_pk.kem), server_pk.clone());

    pubkeys.servers.clear();
    pubkeys.servers.extend(new_db.servers);

    Ok(())
}

pub fn unblind_aggregate(
    toplevel_agg: &AggregatedMessage,
    signing_key: &SecretKey,
    shared_secrets: &SharedSecretsDbServer,
) -> Result<(UnblindedAggregateShareBlobNoSGX, SharedSecretsDbServer)> {
    unblind_aggregate_mt(
        toplevel_agg,
        signing_key,
        shared_secrets,
        interface::N_THREADS_DERIVE_ROUND_SECRET,
    )
}

pub fn unblind_aggregate_mt(
    toplevel_agg: &AggregatedMessage,
    signing_key: &SecretKey,
    shared_secrets: &SharedSecretsDbServer,
    n_threads: usize,
) -> Result<(UnblindedAggregateShareBlobNoSGX, SharedSecretsDbServer)> {
    let start = Instant::now();
    let chunk_size = (toplevel_agg.user_ids.len() + n_threads - 1) / n_threads;
    assert_ne!(chunk_size, 0);

    let round = shared_secrets.round;

    // make a mpsc channel
    let (tx, rx) = mpsc::channel();

    // // partition the user ids into N batches
    let user_keys: Vec<EntityId> = toplevel_agg.user_ids.iter().cloned().collect();
    for uks in &user_keys.into_iter().chunks(chunk_size) {
        let uks_vec = uks.collect_vec();

        let db_cloned = shared_secrets.clone();
        let tx_cloned = mpsc::Sender::clone(&tx);

        thread::spawn(move || {
            info!("thread working on {} ids", uks_vec.len());
            let user_ids: BTreeSet<EntityId> = BTreeSet::from_iter(uks_vec.into_iter());
            let rs = 
                unblind_aggregate_partial(&(round, db_cloned, user_ids))
                .unwrap();
            tx_cloned.send(rs).unwrap();
        });
    }

    info!("========= set up threads after {:?}", start.elapsed());

    drop(tx);

    let round_secrets: Vec<RoundSecret> = rx.iter().collect();
    info!("========= threads join after {:?}", start.elapsed());

    let result = unblind_aggregate_merge(
        toplevel_agg, &round_secrets, signing_key, shared_secrets
    );

    info!(
        "========= {} round secrets merged after {:?}.",
        round_secrets.len(),
        start.elapsed()
    );

    result
}


pub fn unblind_aggregate_partial(
    input: &(u32, SharedSecretsDbServer, BTreeSet<EntityId>),
) -> Result<RoundSecret> {
    let round = input.0;
    let shared_secrets = input.1.clone();
    let user_ids_in_batch = &input.2;

    if round != shared_secrets.round {
        error!(
            "wrong round. round {} != shared_secrets.round {}",
            round, shared_secrets.round
        );
        return Err(ServerError::UnexpectedError);
    }

    // check that user ids in this batch is a subset of all known user ids
    let user_ids_in_secret_db = BTreeSet::from_iter(shared_secrets.db.keys().map(EntityId::from));
    if !(user_ids_in_batch.is_subset(&user_ids_in_secret_db)) {
        error!("user_ids_in_batch is not a subset of user_ids in sercret_db. user_ids_in_batch = {:?}, user_ids_in_secret_db = {:?}", 
        user_ids_in_batch,
        user_ids_in_secret_db);
        return Err(ServerError::UnexpectedError);
    }

    // decrypt key is derived from secret shares with users (identified by round_msg.user_ids)
    derive_round_secret_server(round, &shared_secrets, Some(&user_ids_in_batch)).map_err(|_| {
        error!("crypto error");
        ServerError::UnexpectedError
    })
}

pub fn unblind_aggregate_merge(
    toplevel_agg: &RoundSubmissionBlobNoSGX,
    round_secrets : &Vec<RoundSecret>,
    sig_key: &SecretKey,
    shared_secrets: &SharedSecretsDbServer,
) -> Result<(UnblindedAggregateShareBlobNoSGX, SharedSecretsDbServer)> {
    let mut round_secret = RoundSecret::default();
    for rs in round_secrets.iter() {
        round_secret.xor_mut_nosgx(rs);
    }

    let mut unblind_agg = UnblindedAggregateSharedNoSGX {
        encrypted_msg: toplevel_agg.clone(),
        key_share: round_secret,
        sig: Signature::from_bytes(&[0u8; 64]).expect("failed to generate Signature from bytes"),
        pk: PublicKey::default(),
    };

    // sign the final output and rachet the shared secrets
    let shared_secrets = shared_secrets.clone();

    // sign
    unblind_agg.sign_mut(sig_key).map_err(|e| {
        error!("sign the unblind aggregate message failed: {}", e);
        return ServerError::UnexpectedError;
    });

    Ok((
        unblind_agg.marshal_nosgx().expect("marshal unblind agg failed"),
        shared_secrets.ratchet()
    ))
}

pub fn derive_round_output(
    sig_sk: &SecretKey,
    server_aggs: &[UnblindedAggregateShareBlobNoSGX],
) -> Result<RoundOutputUpdated> {
    if server_aggs.is_empty() {
        error!("empty shares array");
        return Err(ServerError::UnexpectedError);
    }

    // Xor of all server secrets
    let mut final_msg = DcRoundMessage::default();

    // We require all s in shares should have the same aggregated_msg
    let first_msg = server_aggs[0].unmarshal_nosgx().expect("failed to unmarshal the unblinded aggregated share");
    let final_aggregation = first_msg.encrypted_msg.aggregated_msg;
    let round = first_msg.encrypted_msg.round;

    for s in server_aggs.iter() {
        let share = s.unmarshal_nosgx().expect("failed to unmarshal the unblinded aggregated share");
        if share.encrypted_msg.aggregated_msg != final_aggregation {
            error!("share {:?} has a different final agg", share);
            return Err(ServerError::UnexpectedError);
        }
        final_msg.xor_mut_nosgx(&share.key_share);
    }

    // Finally xor secrets with the message
    final_msg.xor_mut_nosgx(&final_aggregation);

    let mut round_output = RoundOutputUpdated {
        round,
        dc_msg: final_msg,
        server_sigs: vec![],
    };

    let (sig, pk) = round_output.sign(sig_sk).expect("failed to sign the round output");
    
    round_output.server_sigs.push(SignatureNoSGX {pk, sig});

    debug!(
        "⏰ round {} concluded with output {:?}",
        round, round_output
    );

    Ok(round_output)
}