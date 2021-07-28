use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_cbor;
use sgx_types::sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED};
use sgx_types::SgxError;

use std::vec::Vec;

pub fn serialize_to_vec<T: Serialize>(v: &T) -> SgxResult<Vec<u8>> {
    serde_cbor::to_vec(v).map_err(|e| {
        println!("can't serialize_to_vec {}", e);
        SGX_ERROR_UNEXPECTED
    })
}

/// serialize v to outbuf. Return error if outbuf_cap is too small.
pub fn serialize_to_ptr<T: Serialize>(
    v: &T,
    outbuf: *mut u8,
    outbuf_cap: usize,
    outbuf_used: *mut usize,
) -> SgxError {
    let serialized = serde_cbor::to_vec(v).map_err(|e| {
        println!("[IN] error serializing: {}", e);
        SGX_ERROR_INVALID_PARAMETER
    })?;

    if serialized.len() > outbuf_cap {
        println!(
            "[IN] not enough output to write serialized message. need {} got {}",
            serialized.len(),
            outbuf_cap,
        );
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    unsafe {
        // write serialized output to outbuf
        outbuf.copy_from(serialized.as_ptr(), serialized.len());
        *outbuf_used = serialized.len();
    }

    Ok(())
}

use sgx_types::SgxResult;
use std::slice::from_raw_parts;

pub fn deserialize_from_ptr<T: DeserializeOwned>(inp: *const u8, inp_len: usize) -> SgxResult<T> {
    let bin = unsafe { from_raw_parts(inp, inp_len) };
    serde_cbor::from_slice::<T>(bin).map_err(|e| {
        println!("can't deserialize_from_ptr {}", e);
        SGX_ERROR_INVALID_PARAMETER
    })
}

pub fn deserialize_from_vec<T: DeserializeOwned>(bin: &[u8]) -> SgxResult<T> {
    serde_cbor::from_slice::<T>(bin).map_err(|e| {
        println!("can't deserialize_from_vec {}", e);
        SGX_ERROR_INVALID_PARAMETER
    })
}