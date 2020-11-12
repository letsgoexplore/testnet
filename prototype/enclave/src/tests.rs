use crypto;
use error::CryptoError;

use crate::interface::*;
use crate::sgx_tunittest::*;
use crate::sgx_types;
use crate::std::prelude::v1::*;

use sgx_types::sgx_status_t;

use hkdf::Hkdf;
use sha2::Sha256;

pub fn test_all() -> sgx_status_t {
    // rsgx_unit_tests!(test_agg_msg);
    // rsgx_unit_tests!(scheduler_tests);
    // rsgx_unit_tests!(test_dc_msg);
    rsgx_unit_tests!(xor);
    rsgx_unit_tests!(sign);
    rsgx_unit_tests!(hkdf);
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

    assert_eq!(a, crypto::xor(&a, &vec![0, 0, 0]).unwrap().to_vec());

    let b: Vec<u8> = vec![5, 6, 7];
    let c: Vec<u8> = vec![1 ^ 5, 2 ^ 6, 3 ^ 7];

    let d = crypto::xor(&a, &b).unwrap();

    assert_eq!(c, d);

    let b = vec![4, 5];
    assert!(crypto::xor(&a, &b).is_err());
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

fn sign() {
    let keypair = test_keypair().unwrap();

    let mutable = SignedUserMessage {
        round: 100,
        message: test_raw_msg(),
        tee_sig: Default::default(),
        tee_pk: Default::default(),
    };

    let signed = crypto::sign_dc_message(&mutable, &keypair.prv_key).unwrap();

    assert_eq!(signed.tee_pk, keypair.pub_key);
    assert!(crypto::verify_dc_message(&signed).unwrap());
}

fn round() {
    // xor in server's key and xor them out
    unimplemented!()
}
