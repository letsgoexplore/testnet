use sgx_types::{sgx_sealed_data_t, sgx_status_t};

use sgx_rand::Rng;
use sgx_tseal::SgxSealedData;

use core::convert::TryFrom;
use crypto::KemKeyPair;
use ecall::seal_unseal::{deser_unseal_from_ptr, ser_seal_to_ptr};
use interface::SgxSigningPubKey;

use sgx_types::sgx_status_t::{
    SGX_ERROR_FAAS_BUFFER_TOO_SHORT, SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED, SGX_SUCCESS,
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

    let result =
        unsafe { ser_seal_to_ptr(&prv_key, "keypair".as_bytes(), output, output_size as usize) };

    if result.is_err() {
        println!("can't seal: {}", result.expect_err("not error"));
        SGX_ERROR_INVALID_PARAMETER
    } else {
        SGX_SUCCESS
    }
}

use crypto::SgxSigningKey;
use ecall::seal_unseal::unseal_data;
use interface::KemPubKey;

#[no_mangle]
pub extern "C" fn ecall_unseal_to_pubkey(
    inp: *mut u8,
    inp_len: u32,
    out_x: *mut u8,
    out_y: *mut u8,
) -> sgx_status_t {
    let sk = match unsafe { deser_unseal_from_ptr::<SgxSigningKey>(inp, inp_len as usize) } {
        Ok(sk) => sk,
        Err(e) => return SGX_ERROR_INVALID_PARAMETER,
    };

    let pk = unwrap_or_return!(SgxSigningPubKey::try_from(&sk), SGX_ERROR_INVALID_PARAMETER);
    unsafe {
        out_x.copy_from(pk.gx.as_ptr(), pk.gx.len());
        out_y.copy_from(pk.gy.as_ptr(), pk.gy.len());
    }

    SGX_SUCCESS

    // let unsealed = match unseal_data::<SgxSigningKey>(inp, inp_len) {
    //     Ok(u) => u,
    //     Err(e) => return e,
    // };
    //
    // let prv_key = unsealed.get_decrypt_txt();
    // let pk = unwrap_or_return!(KemPubKey::try_from(prv_key), SGX_ERROR_INVALID_PARAMETER);
    // println!("PK: {}", pk);
    // SGX_SUCCESS
}
