use sgx_types::{
    sgx_ec256_private_t, sgx_sealed_data_t, sgx_status_t, SgxResult, SGX_ECP256_KEY_SIZE,
};

use std::mem::size_of;

use sgx_rand::Rng;
use sgx_tseal::{SgxSealedData, SgxUnsealedData};

use core::convert::TryFrom;
use interface::{PrvKey, PubKey};
use sgx_types::marker::ContiguousMemory;
use sgx_types::sgx_status_t::{
    SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_INVALID_STATE, SGX_ERROR_UNEXPECTED, SGX_SUCCESS,
};

#[no_mangle]
pub extern "C" fn new_tee_signing_key(
    output: *mut u8,
    output_size: u32,
    output_bytes_written: *mut u32,
) -> sgx_status_t {
    let mut rand = match sgx_rand::SgxRng::new() {
        Ok(r) => r,
        Err(e) => {
            println!("Can't open rand {}", e);
            return SGX_ERROR_UNEXPECTED;
        }
    };
    let prv_key = rand.gen::<PrvKey>();

    let pk = unwrap_or_return!(PubKey::try_from(&prv_key));
    println!("PK: {}", pk);

    // TODO: use a reasonable associated data
    let ad = [1, 2, 3, 4];
    let sealed = match SgxSealedData::<PrvKey>::seal_data(&ad, &prv_key) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sealed_len = SgxSealedData::<PrvKey>::calc_raw_sealed_data_size(
        sealed.get_add_mac_txt_len(),
        sealed.get_encrypt_txt_len(),
    );

    println!("sealed len={}", sealed_len);

    unsafe {
        match sealed.to_raw_sealed_data_t(output as *mut sgx_sealed_data_t, output_size as u32) {
            Some(_) => {}
            None => return SGX_ERROR_INVALID_PARAMETER,
        }
        *output_bytes_written = sealed_len;
    }

    SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn unseal_to_pubkey(inp: *mut u8, inp_len: u32) -> sgx_status_t {
    let unsealed = match unseal_data::<PrvKey>(inp, inp_len) {
        Ok(u) => u,
        Err(e) => return e,
    };

    let prv_key = unsealed.get_decrypt_txt();
    let pk = unwrap_or_return!(PubKey::try_from(prv_key));
    println!("PK: {}", pk);
    SGX_SUCCESS
}

// unseal
// TODO: move this to a better place
pub fn unseal_data<'a, T: Copy + ContiguousMemory>(
    sealed_log: *mut u8,
    sealed_log_size: u32,
) -> SgxResult<SgxUnsealedData<'a, T>> {
    let sealed = unsafe {
        SgxSealedData::<T>::from_raw_sealed_data_t(
            sealed_log as *mut sgx_sealed_data_t,
            sealed_log_size,
        )
    }
    .ok_or(SGX_ERROR_INVALID_PARAMETER)?;

    sealed.unseal_data()
}
