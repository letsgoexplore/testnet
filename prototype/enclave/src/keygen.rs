use sgx_types::{
    sgx_ec256_private_t, sgx_sealed_data_t, sgx_status_t, SgxResult, SGX_ECP256_KEY_SIZE,
};

use std::mem::size_of;

extern crate sgx_rand;
extern crate sgx_tseal;
use self::sgx_rand::Rng;

use interface::PrvKey;
use sgx_types::marker::ContiguousMemory;
use sgx_types::sgx_status_t::{
    SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_INVALID_STATE, SGX_ERROR_UNEXPECTED, SGX_SUCCESS,
};

use self::sgx_tseal::SgxSealedData;

#[no_mangle]
pub extern "C" fn new_fresh_signing_key(
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

    println!("rand generated");

    let priv_key = rand.gen::<PrvKey>();
    // TODO: use a reasonable associated data
    let ad = [1, 2, 3, 4];
    let sealed = match SgxSealedData::<PrvKey>::seal_data(&ad, &priv_key) {
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
