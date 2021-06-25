use sgx_types::{sgx_sealed_data_t, sgx_status_t};

use sgx_rand::Rng;
use sgx_tseal::SgxSealedData;

use core::convert::TryFrom;
use crypto::{KemKeyPair, SharedServerSecret};
use interface::SgxSigningPubKey;
use utils::{ser_and_seal_to_ptr, unseal_from_ptr_and_deser};

use sgx_types::sgx_status_t::{
    SGX_ERROR_FAAS_BUFFER_TOO_SHORT, SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED,
    SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED, SGX_SUCCESS,
};

#[no_mangle]
pub extern "C" fn ecall_new_sgx_signing_key(output: *mut u8, output_size: u32) -> sgx_status_t {
    let mut rand = match sgx_rand::SgxRng::new() {
        Ok(r) => r,
        Err(e) => {
            println!("Can't open rand {}", e);
            return SGX_ERROR_UNEXPECTED;
        }
    };

    // generate a random secret key
    let prv_key = rand.gen::<SgxSigningKey>();

    let pk = match SgxSigningPubKey::try_from(&prv_key) {
        Ok(pk) => pk,
        Err(e) => {
            println!("err {}", e);
            return SGX_ERROR_INVALID_PARAMETER;
        }
    };

    let result = unsafe {
        ser_and_seal_to_ptr(&prv_key, "keypair".as_bytes(), output, output_size as usize)
    };

    if result.is_err() {
        println!("can't seal: {}", result.expect_err("not error"));
        SGX_ERROR_INVALID_PARAMETER
    } else {
        SGX_SUCCESS
    }
}

use crypto::SgxSigningKey;
use interface::KemPubKey;

#[no_mangle]
pub extern "C" fn ecall_unseal_to_pubkey(
    inp: *mut u8,
    inp_len: u32,
    out_x: *mut u8,
    out_y: *mut u8,
) -> sgx_status_t {
    let sk = match unsafe { unseal_from_ptr_and_deser::<SgxSigningKey>(inp, inp_len as usize) } {
        Ok(sk) => sk,
        Err(e) => return SGX_ERROR_INVALID_PARAMETER,
    };

    let pk = unwrap_or_abort!(SgxSigningPubKey::try_from(&sk), SGX_ERROR_INVALID_PARAMETER);
    unsafe {
        out_x.copy_from(pk.gx.as_ptr(), pk.gx.len());
        out_y.copy_from(pk.gy.as_ptr(), pk.gy.len());
    }

    SGX_SUCCESS
}

use std::vec::Vec;

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
