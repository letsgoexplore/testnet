use std::{vec, vec::Vec};
use std::iter::FromIterator;
use std::sync::mpsc;
use std::thread;
use itertools::Itertools;

use ed25519_dalek::{
    SecretKey,
    PublicKey,
};
use rand::rngs::OsRng;
use sha2::Sha512;

use common::types_nosgx::{
    SharedSecretsDbServer,
    SignedPubKeyDbNoSGX,
    AggRegistrationBlobNoSGX,
    AggregatedMessage,
    RoundSubmissionBlobUpdate,
    Sealed
};
use common::user_request::{
    RoundSecret,
};

use common::funcs_nosgx::{
    verify_user_attestation,
    derive_round_secret_server,
};
use common::error::{
    DCError,
};
use common::nosgx_protected_keys::{
    SignatureNoSGX
}

use crate::util::{Result, ServerError};

use interface::{
    EntityId,
    UserRegistrationBlob,
    ServerPubKeyPackageNoSGX,
    SealedSigPrivKeyNoSGX,
    SealedSharedSecretsDbClient,
};

use log::{
    debug,
    error,
};



pub fn new_server() -> Result<(SecretKey, SecretKey, EntityId, ServerPubKeyPackageNoSGX)> {
    let mut csprng = OsRng::new()?;
    let sig_key = SecretKey::generate(&mut csprng);
    let kem_key = SecretKey::generate(&mut csprng);

    // The standard hash function used for most ed25519 libraries is SHA-512
    let sig_key_pk = PublicKey::from_secret::<Sha512>(&sig_key);
    let kem_key_pk = PublicKey::from_secret::<Sha512>(&kem_key);

    let reg = ServerPubKeyPackageNoSGX {
        sig: sig_key_pk,
        kem: kem_key_pk,
    };

    Ok((sig_key, kem_key, EntityId::from(&reg), reg))
}

pub fn recv_user_registration_batch(
    pubkeys: &mut SignedPubKeyDbNoSGX,
    shared_secrets: &mut SharedSecretsDbServer,
    decap_key: &SecretKey,
    input_blob: &[UserRegistrationBlob],
) -> Result<()> {
    let (new_pubkey_db, new_secrets_db) = recv_user_reg_batch(
        (pubkeys, decap_key, input_blob),
    )?;

    pubkeys.users = new_pubkey_db.users;
    shared_secrets.db = new_secrets_db.db;

    Ok(())
}

fn recv_user_reg_batch(
    input: (&SignedPubKeyDbNoSGX, &SecretKey, &Vec<UserRegistrationBlob>),
) -> Result<(SignedPubKeyDb, SharedSecretsDbServer)> {
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

        pk_db.users.insert(EntityId::from(&u.pk), u.clone());
    }

    // Derive secrets
    let mut others_kem_pks = vec![];
    for (_, k) in pk_db.users.iter() {
        others_kem_pks.push(k.pk);
    }

    // TODO: derive shared secrets

}

/// Registers an aggregator with this server
pub fn recv_aggregator_registration(
    pubkeys: &mut SignedPubKeyDbNoSGX,
    input_blob: &AggRegistrationBlobNoSGX,
) -> Result<()> {

    let pk_db = pubkeys;
    let attested_pk = input_blob;

    // add user key to pubkey db
    pk_db
        .aggregators
        .insert(EntityId::from(&attested_pk.pk), attested_pk.to_owned())?;

    pk_db.aggregators.clear();
    pk_db.aggregators.extend(pk_db.aggregators)?;

    Ok(())
}

pub fn recv_server_registration(
    pubkeys: &mut SignedPubKeyDbNoSGX,
    input_blob: &ServerPubKeyPackageNoSGX,
) -> Result<()> {
    // Input the registration and increment the size of the group
    let pk_db = pubkeys;
    let attested_pk = input_blob;

    if !attested_pk.verify_attestation() {
        return Err(DCError::Error_invalid_parameter);
    }

    // add server's key package to pubkey db
    pk_db
        .servers
        .insert(EntityId::from(&attested_pk.kem), attested_pk.clone())?;

    pubkeys.servers.clear();
    pubkeys.servers.extend(pk_db.servers)?;

    Ok(())
}


pub fn unblind_aggregate(
    toplevel_agg: &AggregatedMessage,
    signing_key: &SealedSigPrivKeyNoSGX,
    shared_secrets: &SealedSharedSecretsDbClient,
    //Question: UnblindedAggregateShareBlob don't need to change?
) -> Result<(UnblindedAggregateShareBlob, SealedSharedSecretsDbClient)> {
    pub fn unblind_aggregate_partial(
        input: &(u32, SealedSharedSecretsDbClient, BTreeSet<EntityId>),
    ) -> Result<RoundSecret> {
        let round = input.0;
        let shared_secrets = input.1.unseal_into()?;
        let user_ids_in_batch = &input.2;
    
        if round != shared_secrets.round {
            error!(
                "wrong round. round {} != shared_secrets.round {}",
                round, shared_secrets.round
            );
            return Err(DCError::Error_invalid_parameter);
        }
    
        // check that user ids in this batch is a subset of all known user ids
        let user_ids_in_secret_db = BTreeSet::from_iter(shared_secrets.db.keys().map(EntityId::from));
        if !(user_ids_in_batch.is_subset(&user_ids_in_secret_db)) {
            error!("user_ids_in_batch is not a subset of user_ids_in_secret_db. user_ids_in_batch = {:?}, user_ids_in_secret_db = {:?}",
            user_ids_in_batch,
            user_ids_in_secret_db);
            return Err(DCError::Error_invalid_parameter);
        }
    
        // decrypt key is derived from secret shares with users (identified by round_msg.user_ids)
        derive_round_secret_server(round, &shared_secrets, Some(&user_ids_in_batch)).map_err(|_| {
            error!("crypto error");
            DCError::Error_invalid_parameter
        })
    }

    pub fn unblind_aggregate_merge(
        input: &(
            RoundSubmissionBlobUpdate,
            Vec<RoundSecret>,
            SealedSigPrivKeyNoSGX,
            SealedSharedSecretsDbClient,
        ),
    ) -> Result<(UnblindedAggregateShareBlob, SealedSharedSecretsDbClient)> {
        let mut round_secret = RoundSecret::default();
        for rs in input.1.iter() {
            round_secret.xor_mut(rs);
        }
    
        let mut unblined_agg = messages_types::UnblindedAggregateShare {
            encrypted_msg: input.0.clone(),
            key_share: round_secret,
            sig: Default::default(),
            pk: Default::default(),
        };
    
        // sign the final output and rachet the shared secrets
        let sig_key = input.2.unseal_into()?;
        let shared_secrets = input.3.unseal_into()?;
    
        // sign
        unblined_agg.sign_mut(&sig_key)?;
    
        Ok((
            unblined_agg.marshal()?,
            shared_secrets.ratchet().seal_into()?,
        ))
    }


    let n_threads = interface::N_THREADS_DERIVE_ROUND_SECRET;
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
                unblind_aggregate_partial((round, &db_cloned, &user_ids))
                    .unwrap();
            ///
            
            /// 
            tx_cloned.send(rs).unwrap();
        });
    }

    info!("========= set up threads after {:?}", start.elapsed());

    drop(tx);

    let round_secrets: Vec<RoundSecret> = rx.iter().collect();
    info!("========= threads join after {:?}", start.elapsed());

    let result = unblind_aggregate_merge(
        (toplevel_agg, &round_secrets, signing_key, shared_secrets),
    );

    info!(
        "========= {} round secrets merged after {:?}.",
        round_secrets.len(),
        start.elapsed()
    );

    result   
}

/// Derives the final round output given all the shares of the unblinded aggregates
pub fn derive_round_output(
    sealed_sig_sk: &SealedSigPrivKeyNoSGX, 
    //Question:目前没有NoSgx版本
    server_aggs: &[UnblindedAggregateShareBlob],
    //Question:Result需要定义枚举类嘛
) -> Result<()> {
    let signing_sk = sealed_sig_sk;
    let shares = server_aggs;
    if shares.is_empty() {
        error!("empty shares array");
        return Err(DCError::Error_invalid_parameter);
    }

    // TODO: check all shares are for the same around & same message

    // Xor of all server secrets
    //origin: interface::user_request
    let mut final_msg = DcRoundMessage::default();

    // We require all s in shares should have the same aggregated_msg
    let first_msg = shares[0].unmarshal()?;
    let final_aggregation = first_msg.encrypted_msg.aggregated_msg;
    let round = first_msg.encrypted_msg.round;

    for s in shares.iter() {
        let share = s.unmarshal()?;
        if share.encrypted_msg.aggregated_msg != final_aggregation {
            error!("share {:?} has a different final agg", share);
            return Err("invalid parameter");
        }
        final_msg.xor_mut(&share.key_share);
    }

    // Finally xor secrets with the message
    final_msg.xor_mut(&final_aggregation);

    let mut round_output = RoundOutputUpdated {
        round,
        dc_msg: final_msg,
        server_sigs: vec![],
    };

    let (sig, pk) = round_output.sign(&signing_sk.unseal_into()?)?;

    round_output.server_sigs.push(SignatureNoSGX { pk, sig });

    debug!(
        "⏰ round {} concluded with output {:?}",
        round, round_output
    );

    Ok(round_output)
    
}

