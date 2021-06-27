use interface::*;
use sgx_types::{sgx_get_quote, sgx_get_target_info, sgx_qe_get_target_info, SgxResult};
use std::vec::Vec;
use utils::{ser_and_seal_to_ptr, ser_and_seal_to_vec, serialize_to_ptr};

use sgx_types::{sgx_sealed_data_t, sgx_status_t};

use sgx_rand::Rng;
use sgx_tseal::SgxSealedData;
use std::slice;
use std::string::ToString;

use core::convert::TryFrom;
use crypto::{KemKeyPair, SgxPrivateKey, SharedSecretsWithAnyTrustGroup, SharedServerSecret};

use sgx_types::sgx_status_t::{
    SGX_ERROR_FAAS_BUFFER_TOO_SHORT, SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED,
    SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED, SGX_SUCCESS,
};

use utils;
use std::string::String;

fn new_sgx_keypair_internal(role: String) -> SgxResult<(SgxPrivateKey, SgxProtectedKeyPub, SealedKey)> {
    let mut rand = sgx_rand::SgxRng::new().map_err(|e| {
        println!("cant create rand {}", e);
        SGX_ERROR_UNEXPECTED
    })?;
    // generate a random secret key
    let sk = rand.gen::<SgxPrivateKey>();

    // make sure sk is a valid private key by computing its public key
    let pk = SgxSigningPubKey::try_from(&sk)?;

    let tee_linkable_attestation = vec![];
    Ok((sk, pk, SealedKey {
        sealed_sk: ser_and_seal_to_vec(&sk, "key".as_bytes())?,
        pk,
        role,
        tee_linkable_attestation,
    }))
}


pub fn new_sgx_keypair_internal_2(
    i: &EcallNewSgxKeypairInput
) -> SgxResult<EcallNewSgxKeypairOutput> {
    println!("[IN] unmarshalled input {:?}", i);
    let o = EcallNewSgxKeypairOutput {
        sk: new_sgx_keypair_internal(i.role.clone())?.2,
    };
    println!("[IN] output {:?}", o);
    Ok(o)
}

#[no_mangle]
pub extern "C" fn ecall_new_sgx_keypair(
    inp: *const u8,
    inp_len: usize,
    output: *mut u8,
    output_cap: usize,
    output_used: *mut usize,
) -> sgx_status_t {
    println!("================[IN]");
    let i = unmarshal_or_abort!(EcallNewSgxKeypairInput, inp, inp_len);
    println!("[IN] unmarshalled input {:?}", i);
    let o = EcallNewSgxKeypairOutput {
        sk: unwrap_or_abort!(new_sgx_keypair_internal(i.role), SGX_ERROR_UNEXPECTED).2
    };
    println!("[IN] output {:?}", o);

    match unsafe { serialize_to_ptr(&o, output, output_cap, output_used) } {
        Ok(_) => SGX_SUCCESS,
        Err(e) => {
            println!("[IN] can't write to untrusted land {}", e);
            e
        }
    }
}

#[no_mangle]
pub extern "C" fn ecall_unseal_to_pubkey(
    inp: *const u8,
    inp_len: usize,
    output: *mut u8,
    output_cap: usize,
    output_used: *mut usize,
) -> sgx_status_t {
    let sealed_sk: SealedKey = unmarshal_or_abort!(SealedKey, inp, inp_len as usize);
    let sk = unseal_vec_or_abort!(SgxPrivateKey, &sealed_sk.sealed_sk);
    let pk = unwrap_or_abort!(SgxSigningPubKey::try_from(&sk), SGX_ERROR_INVALID_PARAMETER);

    match unsafe { serialize_to_ptr(&pk, output, output_cap, output_used) } {
        Ok(_) => SGX_SUCCESS,
        Err(e) => {
            println!("[IN] can't write to untrusted land {}", e);
            e
        }
    }
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
    let (sk, pk, sealed_key) = new_sgx_keypair_internal("user".to_string())?;

    // 2. derive server secrets
    let server_secrets =
        SharedSecretsWithAnyTrustGroup::derive_server_secrets(&sk, anytrust_server_pks)?;


    Ok(UserRegistration::new(
        sealed_key,
        SealedServerSecrets {
            user_id: EntityId::from(&pk),
            anytrust_group_id: server_secrets.anytrust_group_id(),
            server_public_keys: server_secrets
                .anytrust_group_pairwise_keys
                .keys()
                .cloned()
                .collect(),
            sealed_server_secrets: ser_and_seal_to_vec(
                &server_secrets,
                "shared secrets".as_bytes(),
            )?,
        },
    ))
}
