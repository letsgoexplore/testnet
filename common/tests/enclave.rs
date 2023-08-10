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

    let msg = UserMsg::TalkAndReserveUpdated {
        msg: DcMessage(vec![1u8; DC_NET_MESSAGE_LENGTH]),
        prev_round_output: RoundOutputUpdated::default(),
        times_participated: 0,
    };

    let req_1 = UserSubmissionReqUpdated {
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

    let req_1 = UserSubmissionReqUpdated {
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

