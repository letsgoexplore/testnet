use sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
use sgx_tseal::{SgxSealedData, SgxUnsealedData};
use sgx_types::marker::ContiguousMemory;
use sgx_types::{sgx_sealed_data_t, SgxResult};

// unseal
// TODO: move this to a better place
// TODO: lose the `mut` in sealed_log (this is a bug in SGX SDK being fixed)
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

use interface::PrvKey;
use utils;

pub fn unseal_prv_key(
    sealed_tee_prv_key_ptr: *mut u8,
    sealed_tee_prv_key_len: usize,
) -> SgxResult<PrvKey> {
    let tee_prv_key_unsealed =
        utils::unseal_data::<PrvKey>(sealed_tee_prv_key_ptr, sealed_tee_prv_key_len as u32)?;

    Ok(*tee_prv_key_unsealed.get_decrypt_txt())
}
