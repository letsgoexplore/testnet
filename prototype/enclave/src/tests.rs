use crypto;
use types::*;

use crate::sgx_tunittest::*;
use crate::sgx_types;
use crate::std::prelude::v1::*;

use sgx_types::sgx_status_t;

use hkdf::Hkdf;
use sha2::Sha256;

use crate::interface::*;
use crypto::{SignMutable, Signable};

use crate::ecall;
use crate::types::*;
use serde_cbor;
use sgx_rand::Rng;

pub fn test_all() -> sgx_status_t {
    // rsgx_unit_tests!(test_agg_msg);
    // rsgx_unit_tests!(scheduler_tests);
    // rsgx_unit_tests!(test_dc_msg);
    rsgx_unit_tests!(xor, sign, hkdf, aggregate, serde_dc_message);
    sgx_status_t::SGX_SUCCESS
}

fn hkdf() {
    // copied from the original test vectors found at
    // https://github.com/bl4ck5un/KDFs/blob/v0.8.0-sgx/hkdf/examples/main.rs
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), &ikm);
    let mut okm = [0u8; 42];
    hk.expand(&info, &mut okm)
        .expect("42 is a valid length for Sha256 to output");

    let expected =
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
    assert_eq!(hex::encode(&okm[..]), expected);
}

fn xor() {
    let a: Vec<u8> = vec![1, 2, 3];

    assert_eq!(a, a.xor(&vec![0, 0, 0]).to_vec());

    let b: Vec<u8> = vec![5, 6, 7];
    let c: Vec<u8> = vec![1 ^ 5, 2 ^ 6, 3 ^ 7];

    let d = a.xor(&b);

    assert_eq!(c, d);

    // xor returns the shortest
    let b = vec![4, 5];
    assert_eq!(a.xor(&b), vec![1 ^ 4, 2 ^ 5]);

    let mut b_mut: Vec<u8> = vec![4, 5];
    b_mut.xor_mut(&a);

    assert_eq!(b_mut, vec![1 ^ 4, 2 ^ 5]);
}

fn test_keypair() -> crypto::CryptoResult<KeyPair> {
    let handle = sgx_tcrypto::SgxEccHandle::new();
    handle.open().unwrap();
    match handle.create_key_pair() {
        Ok(pair) => Ok(KeyPair {
            prv_key: PrvKey::from(pair.0),
            pub_key: PubKey::from(pair.1),
        }),
        Err(e) => Err(CryptoError::SgxCryptoError(e)),
    }
}

fn sign() -> (KeyPair, SignedUserMessage) {
    let keypair = test_keypair().unwrap();

    let mut mutable = SignedUserMessage {
        user_id: [0 as u8; 32],
        round: 0,
        message: test_raw_msg(),
        tee_sig: Default::default(),
        tee_pk: Default::default(),
    };

    mutable.sign_mut(&keypair.prv_key).expect("sign");

    assert_eq!(mutable.tee_pk, keypair.pub_key);
    assert!(mutable.verify().expect("verify"));

    (keypair, mutable)
}

fn aggregate() {
    let (keypair, signed_msg) = sign();

    let agg =
        ecall::aggregate(&signed_msg, &AggregatedMessage::zero(), &keypair.prv_key).expect("agg");
    assert!(agg.verify().expect("ver"));

    // should not change since we agg in a zero message
    assert_eq!(agg.aggregated_msg, DCMessage::from(signed_msg.message));

    // aggregate again the same message should error
    assert!(ecall::aggregate(&signed_msg, &agg, &keypair.prv_key).is_err());

    // let's use a different user id and submit again
    let mut new_msg = signed_msg;
    new_msg.user_id = [1 as u8; 32];
    new_msg.sign_mut(&keypair.prv_key).expect("sig");
    // aggregate same message twice so we should get zero.
    let agg = ecall::aggregate(&new_msg, &agg, &keypair.prv_key).expect("agg");
    assert!(agg.verify().expect("ver"));
    assert_eq!(agg.aggregated_msg, DCMessage::zero());
}

fn serde_dc_message() {
    let mut rand = sgx_rand::SgxRng::new().unwrap();

    for _i in 0..1000 {
        let sample = rand.gen::<DCMessage>();

        let data = serde_cbor::to_vec(&sample).expect("ser");
        let c: DCMessage = serde_cbor::from_slice(&data).expect("de");

        assert_eq!(c, sample);
    }
}