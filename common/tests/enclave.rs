// Ecalls

const TEST_ENCLAVE_PATH: &'static str = "/sgxdcnet/lib/enclave.signed.so";

use common::enclave::DcNetEnclave;

extern crate base64;
extern crate hex;
extern crate hexdump;
extern crate interface;
extern crate sgx_types;

use env_logger::{Builder, Env};
use interface::{DcMessage, EntityId, UserSubmissionReq, DC_NET_MESSAGE_LENGTH};
use log::*;
use std::time::Instant;
use std::{collections::BTreeSet, vec};

fn init_logger() {
    let env = Env::default()
        .filter_or("RUST_LOG", "debug")
        .write_style_or("RUST_LOG_STYLE", "always");

    let _ = Builder::from_env(env).try_init();
    let _ = env_logger::builder().is_test(true).try_init();
}

/// create n server public keys
fn create_server_pubkeys(enc: &DcNetEnclave, n: i32) -> Vec<ServerPubKeyPackage> {
    let mut pks = Vec::new();

    for _ in 0..n {
        let s = enc.new_server().unwrap();
        pks.push(s.3);
    }

    pks
}

#[test]
fn user_submit_round_msg() {
    init_logger();
    let enc = DcNetEnclave::init(TEST_ENCLAVE_PATH).unwrap();

    // create server public keys
    let spks = create_server_pubkeys(&enc, 10);
    let (user_reg_shared_secrets, user_reg_sealed_key, user_reg_uid, _) =
        enc.new_user(&spks).unwrap();

    let msg = UserMsg::TalkAndReserve {
        msg: DcMessage(vec![1u8; DC_NET_MESSAGE_LENGTH]),
        prev_round_output: RoundOutput::default(),
        times_participated: 0,
    };

    let req_1 = UserSubmissionReq {
        user_id: user_reg_uid,
        anytrust_group_id: user_reg_shared_secrets.anytrust_group_id(),
        round: 0,
        msg,
        shared_secrets: user_reg_shared_secrets,
        server_pks: spks,
    };

    let (_resp_1, _) = enc
        .user_submit_round_msg(&req_1, &user_reg_sealed_key)
        .unwrap();

    // if we set round to 1, this should fail because the previous round output is empty
    let mut req_round_1 = req_1.clone();
    req_round_1.round = 1;

    assert!(enc
        .user_submit_round_msg(&req_round_1, &user_reg_sealed_key)
        .is_err());

    enc.destroy();
}

#[test]
fn user_reserve_slot() {
    init_logger();
    let enc = DcNetEnclave::init(TEST_ENCLAVE_PATH).unwrap();

    // create server public keys
    let spks = create_server_pubkeys(&enc, 10);
    let (user_reg_shared_secrets, user_reg_sealed_key, user_reg_uid, _) =
        enc.new_user(&spks).unwrap();

    let msg = UserMsg::Reserve {
        times_participated: 0,
    };

    let req_1 = UserSubmissionReq {
        user_id: user_reg_uid,
        anytrust_group_id: user_reg_shared_secrets.anytrust_group_id(),
        round: 0,
        msg,
        shared_secrets: user_reg_shared_secrets,
        server_pks: spks,
    };

    let (_resp_1, _) = enc
        .user_submit_round_msg(&req_1, &user_reg_sealed_key)
        .unwrap();

    enc.destroy();
}

#[test]
fn aggregation() {
    init_logger();
    let enc = DcNetEnclave::init(TEST_ENCLAVE_PATH).unwrap();

    // create server public keys
    let num_of_servers = 10;
    let server_pks = create_server_pubkeys(&enc, num_of_servers);
    log::info!("created {} server keys", num_of_servers);

    // create a fake user
    let (user_reg_shared_secrets, user_reg_sealed_key, user_reg_uid, _) =
        enc.new_user(&server_pks).unwrap();

    log::info!("user {:?} created", user_reg_uid);

    let msg1 = UserMsg::TalkAndReserve {
        msg: DcMessage(vec![1u8; DC_NET_MESSAGE_LENGTH]),
        prev_round_output: RoundOutput::default(),
        times_participated: 0,
    };

    let req_1 = UserSubmissionReq {
        user_id: user_reg_uid,
        anytrust_group_id: user_reg_shared_secrets.anytrust_group_id(),
        round: 0,
        msg: msg1,
        shared_secrets: user_reg_shared_secrets,
        server_pks: server_pks.clone(),
    };

    log::info!("submitting for user {:?}", req_1.user_id);

    let (resp_1, _) = enc
        .user_submit_round_msg(&req_1, &user_reg_sealed_key)
        .unwrap();

    // SealedSigPrivKey, EntityId, AggRegistrationBlob
    let agg = enc.new_aggregator().expect("agg");

    log::info!("aggregator {:?} created", agg.1);

    let mut empty_agg = enc.new_aggregate(0, &EntityId::default()).unwrap();
    let mut observed_nonces = Some(BTreeSet::new());
    enc.add_to_aggregate(&mut empty_agg, &mut observed_nonces, &resp_1, &agg.0)
        .unwrap();

    // this should error because user is already in
    assert!(enc
        .add_to_aggregate(&mut empty_agg, &mut observed_nonces, &resp_1, &agg.0)
        .is_err());

    log::info!("error expected");

    let user_2 = enc.new_user(&server_pks).unwrap();

    let msg2 = UserMsg::TalkAndReserve {
        msg: DcMessage(vec![2u8; DC_NET_MESSAGE_LENGTH]),
        prev_round_output: RoundOutput::default(),
        times_participated: 0,
    };

    let req_2 = UserSubmissionReq {
        user_id: user_2.2,
        anytrust_group_id: user_2.0.anytrust_group_id(),
        round: 0,
        msg: msg2,
        shared_secrets: user_2.0,
        server_pks,
    };
    let (resp_2, _) = enc.user_submit_round_msg(&req_2, &user_2.1).unwrap();

    enc.add_to_aggregate(&mut empty_agg, &mut observed_nonces, &resp_2, &agg.0)
        .unwrap();

    // Ensure we saw two distinct nonces
    assert_eq!(observed_nonces.unwrap().len(), 2);

    enc.destroy();
}

#[test]
fn new_user() {
    init_logger();

    let enc = DcNetEnclave::init(TEST_ENCLAVE_PATH).unwrap();
    let pks = create_server_pubkeys(&enc, 2);
    let (_, user_reg_sealed_key, user_reg_uid, _) = enc.new_user(&pks).unwrap();

    let pk = enc
        .unseal_to_public_key_on_p256(&user_reg_sealed_key.0)
        .unwrap();
    assert_eq!(EntityId::from(&pk), user_reg_uid);

    enc.destroy();
}

#[test]
fn new_aggregator() {
    let enc = DcNetEnclave::init(TEST_ENCLAVE_PATH).unwrap();

    let (agg_sealed_key, agg_id, _) = enc.new_aggregator().unwrap();

    let pk = enc.unseal_to_public_key_on_p256(&agg_sealed_key.0).unwrap();
    assert_eq!(EntityId::from(&pk), agg_id);

    enc.destroy();
}

use interface::*;

fn create_n_servers(
    n: usize,
    enclave: &DcNetEnclave,
) -> Vec<(
    SealedSigPrivKey,
    SealedKemPrivKey,
    EntityId,
    ServerRegistrationBlob,
)> {
    let mut servers = Vec::new();
    for _ in 0..n {
        servers.push(enclave.new_server().unwrap());
    }

    servers
}

#[test]
fn server_recv_user_reg() {
    init_logger();

    let enc = DcNetEnclave::init(TEST_ENCLAVE_PATH).unwrap();
    let servers = create_n_servers(2, &enc);

    let mut server_pks = Vec::new();
    for (_, _, _, k) in servers.iter().cloned() {
        server_pks.push(k)
    }

    let user = enc.new_user(&server_pks).expect("user");

    info!("user created {:?}", user.2);

    let server_1 = &servers[0];

    let mut pk_db = Default::default();
    let mut secret_db = Default::default();

    enc.recv_user_registration(&mut pk_db, &mut secret_db, &server_1.1, &user.3)
        .unwrap();
}

enum UnblindMethod {
    SingleThreadUnblind,
    MultiThreadUnblind(usize),
    OutOfEnclaveMultiThreadUnblind(usize),
}

fn many_user_one_server() {
    init_logger();

    let enc = DcNetEnclave::init(TEST_ENCLAVE_PATH).unwrap();

    let num_of_users = interface::DC_NET_N_SLOTS;

    // create server public keys
    let servers = create_n_servers(1, &enc);
    let mut server_pks = Vec::new();
    for (_, _, _, k) in servers.iter().cloned() {
        server_pks.push(k)
    }

    info!("created a server");

    // create a bunch of fake user
    let users = (0..num_of_users)
        .map(|_| enc.new_user(&server_pks).unwrap())
        .collect::<Vec<_>>();
    let user_pks = (0..num_of_users)
        .map(|i| users[i].3.clone())
        .collect::<Vec<_>>();

    info!("{} user created", num_of_users);

    // create aggregator
    let aggregator = enc.new_aggregator().expect("agg");
    let mut empty_agg = enc.new_aggregate(0, &EntityId::default()).unwrap();
    let mut observed_nonces = Some(BTreeSet::new());

    info!("🏁 aggregator {:?} created", aggregator.1);

    // server state
    let mut server_pk_db = vec![SignedPubKeyDb::default(); server_pks.len()];
    let mut server_shared_db = vec![SealedSharedSecretDb::default(); server_pks.len()];

    // register users
    info!("============== registering users");
    let start = Instant::now();

    for (i, s) in servers.iter().enumerate() {
        let mut pk_db = SignedPubKeyDb::default();
        let mut shared_db = SealedSharedSecretDb::default();

        // register the aggregator
        enc.recv_aggregator_registration(&mut pk_db, &aggregator.2)
            .unwrap();

        enc.recv_user_registration_batch(&mut pk_db, &mut shared_db, &s.1, &user_pks)
            .unwrap();

        info!("========= registration done at server {}", i);

        server_pk_db[i] = pk_db;
        server_shared_db[i] = shared_db;
    }

    info!(
        "============== all user have registered. used {:?}",
        start.elapsed()
    );
    let start = Instant::now();

    for i in 0..2 {
        let user = &users[i];

        let dc_msg = DcMessage(vec![(i + 1) as u8; DC_NET_MESSAGE_LENGTH]);
        let msg0 = UserMsg::TalkAndReserve {
            msg: dc_msg.clone(),
            prev_round_output: RoundOutput::default(),
            times_participated: 0,
        };

        let req_0 = UserSubmissionReq {
            user_id: user.2,
            anytrust_group_id: user.0.anytrust_group_id(),
            round: 0,
            msg: msg0,
            shared_secrets: user.0.clone(),
            server_pks: server_pks.clone(),
        };

        let (resp_0, _) = enc.user_submit_round_msg(&req_0, &user.1).unwrap();

        log::info!("🏁 user {} submitted", i);

        enc.add_to_aggregate(&mut empty_agg, &mut observed_nonces, &resp_0, &aggregator.0)
            .unwrap();
    }

    info!("========= all user submitted. Took {:?}", start.elapsed());

    // finalize the aggregate
    // let final_agg_0 = enc.finalize_aggregate(&empty_agg).unwrap();

    // fake a lot of user ids
    let final_agg_0 = RoundSubmissionBlob {
        round: 0,
        anytrust_group_id: empty_agg.anytrust_group_id,
        user_ids: server_shared_db[0].db.keys().map(EntityId::from).collect(),
        rate_limit_nonce: None,
        aggregated_msg: empty_agg.aggregated_msg,
        tee_sig: Default::default(),
        tee_pk: Default::default(),
    };

    for unblind_func in &[
        UnblindMethod::SingleThreadUnblind,
        UnblindMethod::MultiThreadUnblind(10),
        UnblindMethod::OutOfEnclaveMultiThreadUnblind(10),
    ] {
        info!("========= decryption begins");
        let start = Instant::now();

        // decryption
        let mut decryption_shares = Vec::new();
        for (i, s) in servers.iter().enumerate() {
            // unblind
            let (unblined_agg, _new_secrets) = match unblind_func {
                UnblindMethod::SingleThreadUnblind => {
                    info!("========= decryption using a single thread");
                    enc.unblind_aggregate_single_thread(&final_agg_0, &s.0, &server_shared_db[i])
                }
                UnblindMethod::MultiThreadUnblind(nt) => {
                    info!("========= decryption using {} threads", nt);
                    enc.unblind_aggregate_mt(&final_agg_0, &s.0, &server_shared_db[i], *nt)
                }
                UnblindMethod::OutOfEnclaveMultiThreadUnblind(nt) => {
                    info!(
                        "========= decryption outside of enclave using {} threads",
                        nt
                    );
                    enc.unblind_aggregate_insecure(&final_agg_0, &s.0, &server_shared_db[i], *nt)
                }
            }
            .unwrap();

            decryption_shares.push(unblined_agg);
        }

        info!(
            "🏁 {} decryption shares obtained. Each {} bytes. Took {:?}",
            decryption_shares.len(),
            decryption_shares[0].0.len(),
            start.elapsed(),
        );

        // aggregate final shares
        // suppose the first server is the leader
        let _round_output_r0 = enc
            .derive_round_output(&servers[0].0, &decryption_shares)
            .unwrap();
        // info!("✅ round_output {:?}", round_output_r0);
        info!("✅ round_output");
    }

    // let msg1 = UserMsg::TalkAndReserve {
    //     msg: dc_msg,
    //     prev_round_output: round_output_r0,
    //     times_participated: 1,
    // };
    // let mut req_r1 = req_0.clone();
    // req_r1.msg = msg1;

    // info!("🏁 starting round 1");
    // let (resp_1, _) = enc.user_submit_round_msg(&req_r1, &user.1).unwrap();
}

#[test]
fn whole_thing() {
    many_user_one_server();
}
