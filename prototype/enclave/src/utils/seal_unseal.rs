use crypto::{KemPrvKey, SgxSigningKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
use sgx_tseal::{SgxSealedData, SgxUnsealedData};
use sgx_types::marker::ContiguousMemory;
use sgx_types::{sgx_sealed_data_t, SgxError, SgxResult};
use std::boxed::Box;
use std::error::Error;
use std::vec::Vec;

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
    unsafe {
        match sealed.to_raw_sealed_data_t(output as *mut sgx_sealed_data_t, output_cap as u32) {
            Some(_) => Ok(()),
            None => {
                println!("can't seal. cap {}", output_cap);
                Err(SGX_ERROR_INVALID_PARAMETER)
            }
        }
    }
}

pub unsafe fn unseal_from_vec_and_deser<T: DeserializeOwned>(mut input: Vec<u8>) -> SgxResult<T> {
    unseal_from_ptr_and_deser(input.as_mut_ptr(), input.len())
}

pub unsafe fn unseal_from_ptr_and_deser<T: DeserializeOwned>(
    input: *mut u8,
    input_len: usize,
) -> SgxResult<T> {
    let sealed_data = unsafe {
        match SgxSealedData::<[u8]>::from_raw_sealed_data_t(
            input as *mut sgx_sealed_data_t,
            input_len as u32,
        ) {
            Some(t) => t,
            None => {
                return Err(SGX_ERROR_INVALID_PARAMETER);
            }
        }
    };

    let unsealed = sealed_data.unseal_data()?;
    let unsealed_slice = unsealed.get_decrypt_txt();
    Ok(match serde_cbor::de::from_slice(unsealed_slice) {
        Ok(t) => t,
        Err(e) => {
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
    })
}

// unseal
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

pub fn unseal_prv_key(
    sealed_tee_prv_key_ptr: *mut u8,
    sealed_tee_prv_key_len: usize,
) -> SgxResult<SgxSigningKey> {
    let tee_prv_key_unsealed =
        unseal_data::<SgxSigningKey>(sealed_tee_prv_key_ptr, sealed_tee_prv_key_len as u32)?;

    Ok(*tee_prv_key_unsealed.get_decrypt_txt())
}
