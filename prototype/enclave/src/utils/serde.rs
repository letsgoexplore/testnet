use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_cbor;
use sgx_types::sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
use sgx_types::SgxError;

pub fn serialize_to_ptr<T: Serialize>(
    v: &T,
    outbuf: *mut u8,
    outbuf_cap: usize,
    outbuf_used: *mut usize,
) -> SgxError {
    // serialize SignedUserMessage
    let serialized = serde_cbor::to_vec(v).map_err(|e| {
        println!("error serializing: {}", e);
        SGX_ERROR_INVALID_PARAMETER
    })?;

    if serialized.len() > outbuf_cap {
        println!(
            "not enough output to write serialized message. need {} got {}",
            serialized.len(),
            outbuf_cap,
        );
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }

    unsafe {
        outbuf.copy_from(serialized.as_ptr(), serialized.len());
        *outbuf_used = serialized.len();
    }

    Ok(())
}

use sgx_types::SgxResult;
use std::slice::from_raw_parts;

pub fn deserialize_from_ptr<T: DeserializeOwned>(inp: *const u8, inp_len: usize) -> SgxResult<T> {
    let bin = unsafe { from_raw_parts(inp, inp_len) };
    serde_cbor::from_slice::<T>(bin).map_err(|e| SGX_ERROR_INVALID_PARAMETER)
}
