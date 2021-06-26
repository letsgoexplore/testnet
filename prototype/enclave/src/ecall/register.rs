use interface::*;
use sgx_types::{sgx_get_quote, sgx_get_target_info, sgx_qe_get_target_info, SgxResult};
use std::vec::Vec;
use utils::{ser_and_seal_to_ptr, ser_and_seal_to_vec, serialize_to_ptr};

use sgx_types::{sgx_sealed_data_t, sgx_status_t};

use sgx_rand::Rng;
use sgx_tseal::SgxSealedData;
use std::slice;

use core::convert::TryFrom;
use crypto::{KemKeyPair, SgxProtectedKeyPrivate, SharedServerSecret};

use sgx_types::sgx_status_t::{
    SGX_ERROR_FAAS_BUFFER_TOO_SHORT, SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED,
    SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED, SGX_SUCCESS,
};

use utils;

pub fn new_p256_secret_key() -> SgxResult<(SgxProtectedKeyPrivate, SgxProtectedKeyPub)> {
    let mut rand = sgx_rand::SgxRng::new().map_err(|e| {
        println!("cant create rand {}", e);
        SGX_ERROR_UNEXPECTED
    })?;
    // generate a random secret key
    let sk = rand.gen::<SgxProtectedKeyPrivate>();

    // make sure sk is a valid private key
    let pk = SgxSigningPubKey::try_from(&sk)?;

    Ok((sk, pk))
}

#[no_mangle]
pub extern "C" fn ecall_new_sgx_signing_key(output: *mut u8, output_cap: u32) -> sgx_status_t {
    let sk = match new_p256_secret_key() {
        Ok((sk, _)) => sk,
        Err(e) => return e,
    };

    match unsafe { ser_and_seal_to_ptr(&sk, "keypair".as_bytes(), output, output_cap as usize) } {
        Ok(_) => SGX_SUCCESS,
        Err(e) => {
            println!("can't seal {}", e);
            e
        }
    }
}

#[no_mangle]
pub extern "C" fn ecall_unseal_to_pubkey(
    inp: *mut u8,
    inp_len: u32,
    out_x: *mut u8,
    out_y: *mut u8,
) -> sgx_status_t {
    let sk = unseal_or_abort!(SgxProtectedKeyPrivate, inp, inp_len as usize);
    let pk = unwrap_or_abort!(SgxSigningPubKey::try_from(&sk), SGX_ERROR_INVALID_PARAMETER);
    unsafe {
        out_x.copy_from(pk.gx.as_ptr(), pk.gx.len());
        out_y.copy_from(pk.gy.as_ptr(), pk.gy.len());
    }

    SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ecall_create_test_sealed_server_secrets(
    num_of_keys: u32,
    out_buf: *mut u8,
    out_buf_cap: u32,
) -> sgx_status_t {
    let mut shared_keys: Vec<SharedServerSecret> = Vec::new();
    for i in 0..num_of_keys {
        // create a bunch of keys from static seeds
        shared_keys.push(SharedServerSecret::gen_test(i as u8))
    }

    unsafe {
        match ser_and_seal_to_ptr(&shared_keys, &[0; 0], out_buf, out_buf_cap as usize) {
            Ok(v) => SGX_SUCCESS,
            Err(e) => e,
        }
    }
}

#[no_mangle]
pub extern "C" fn ecall_register_user(
    marshalled_server_pks_ptr: *const u8,
    marshalled_server_pks_len: usize,
    output_buf: *mut u8,
    output_buf_cap: usize,
    output_buf_used: *mut usize,
) -> sgx_status_t {
    let anytrust_server_pks = unmarshal_or_abort!(
        Vec<KemPubKey>,
        marshalled_server_pks_ptr,
        marshalled_server_pks_len
    );

    let user_reg = match register_user_internal(&anytrust_server_pks) {
        Ok(r) => r,
        Err(e) => return e,
    };

    match serialize_to_ptr(&user_reg, output_buf, output_buf_cap, output_buf_used) {
        Ok(_) => SGX_SUCCESS,
        Err(e) => e,
    }
}

/// Derives shared secrets with all the given KEM pubkeys, and derives a new signing pubkey.
/// Returns sealed secrets, a sealed private key, and a registration message to send to an
/// anytrust node
pub fn register_user_internal(anytrust_server_pks: &[KemPubKey]) -> SgxResult<UserRegistration> {
    // 1. generate a SGX protected key. used for both signing and round key derivation
    let (user_sk, user_pk) = new_p256_secret_key()?;

    // 2. derive shared keys
    let shared_server_secrets_result: SgxResult<Vec<_>> = anytrust_server_pks
        .iter()
        .map(|pk| SharedServerSecret::derive_shared_server_secret(&user_sk, pk))
        .collect();

    let shared_server_secrets = match shared_server_secrets_result {
        Ok(sss) => sss,
        Err(e) => {
            println!("can't derived shared server secrets {}", e);
            return Err(e);
        }
    };

    // serialize
    let sealed_shared_server_secrets =
        ser_and_seal_to_vec(&shared_server_secrets, "shared secrets".as_bytes())?;

    Ok(UserRegistration {
        user_id: EntityId::from(&user_pk),
        sealed_shared_server_secrets: SealedServerSecrets(sealed_shared_server_secrets),
        anytrust_group_id: interface::compute_anytrust_group_id(anytrust_server_pks),
        sealed_sk: SealedSgxSigningKey(utils::ser_and_seal_secret_key(&user_sk)?),
        attestation: vec![], // TODO: add attestation
        anytrust_group_pks: anytrust_server_pks.iter().cloned().collect(),
    })
}
