use serde::de::DeserializeOwned;
use serde::Serialize;
use sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
use sgx_tseal::SgxSealedData;

use sgx_types::{sgx_sealed_data_t, SgxError, SgxResult};

use std::vec::Vec;

pub fn ser_and_seal_to_vec<T: Serialize>(a: &T, ad: &[u8]) -> SgxResult<Vec<u8>> {
    let bin = match serde_cbor::ser::to_vec(a) {
        Ok(b) => b,
        Err(e) => {
            println!("can't serialize {}", e);
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
    };

    let sealed = SgxSealedData::<[u8]>::seal_data(ad, &bin)?;
    let mut sealed_bin = vec![0u8; (sealed.get_payload_size() + 1024) as usize];
    match unsafe {
        sealed.to_raw_sealed_data_t(
            sealed_bin.as_mut_ptr() as *mut sgx_sealed_data_t,
            sealed_bin.len() as u32,
        )
    } {
        Some(_) => Ok(sealed_bin),
        None => {
            println!("can't seal. cap {}", sealed_bin.len());
            Err(SGX_ERROR_INVALID_PARAMETER)
        }
    }
}

pub unsafe fn ser_and_seal_to_ptr<T: Serialize>(
    a: &T,
    ad: &[u8],
    output: *mut u8,
    output_cap: usize,
) -> SgxError {
    let bin = match serde_cbor::ser::to_vec(a) {
        Ok(b) => b,
        Err(e) => {
            println!("can't serialize {}", e);
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
    };

    let sealed = SgxSealedData::<[u8]>::seal_data(ad, &bin)?;
    match sealed.to_raw_sealed_data_t(output as *mut sgx_sealed_data_t, output_cap as u32) {
        Some(_) => Ok(()),
        None => {
            println!("can't seal. cap {}", output_cap);
            Err(SGX_ERROR_INVALID_PARAMETER)
        }
    }
}

// TODO: make input generic AsRef<[u8]>
pub fn unseal_vec_and_deser<T: DeserializeOwned + Default>(input: &Vec<u8>) -> SgxResult<T> {
    let mut bin = input.clone();
    unsafe { unseal_ptr_and_deser(bin.as_mut_ptr(), bin.len()) }
}

pub unsafe fn unseal_ptr_and_deser<T: DeserializeOwned + Default>(
    input: *mut u8,
    input_len: usize,
) -> SgxResult<T> {
    if input_len == 0 {
        warn!("empty sealed data");
        return Ok(Default::default());
    }

    let sealed_data = match SgxSealedData::<[u8]>::from_raw_sealed_data_t(
        input as *mut sgx_sealed_data_t,
        input_len as u32,
    ) {
        Some(t) => t,
        None => {
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
    };

    let unsealed = sealed_data.unseal_data()?;
    let unsealed_slice = unsealed.get_decrypt_txt();
    Ok(match serde_cbor::de::from_slice(unsealed_slice) {
        Ok(t) => t,
        Err(_e) => {
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
    })
}