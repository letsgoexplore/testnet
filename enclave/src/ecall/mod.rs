mod keygen;
mod submit;
mod user;

use interface::*;
use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_SUCCESS};
use sgx_types::{sgx_status_t, SgxResult};

use std::collections::BTreeSet;
use std::slice;

macro_rules! match_ecall_ids {
    (
        $ecall_id:ident,$inp:ident,$inp_len:ident,$out:ident,$out_cap:ident,$out_used:ident,
        $(($name:ident, $type_i:ty, $type_o: ty, $impl:expr), )+
    ) => {
        match $ecall_id {
            $(EcallId::$name => generic_ecall::<$type_i,$type_o>($ecall_id,$inp,$inp_len,$out,$out_cap,$out_used,$impl),)+
        }
    }
}

use std::vec::Vec;

#[no_mangle]
pub extern "C" fn ecall_entrypoint(
    ecall_id_raw: u8,
    inp: *const u8,
    inp_len: usize,
    output: *mut u8,
    output_cap: usize,
    output_used: *mut usize,
) -> sgx_status_t {
    // let start = Instant::now();

    let env = Env::default()
        .filter_or("ENCLAVE_LOG_LEVEL", interface::ENCLAVE_LOG_LEVEL)
        .write_style_or("ENCLAVE_LOG_STYLE", "always");
    let _ = Builder::from_env(env).try_init();

    let ecall_id = match EcallId::from_repr(ecall_id_raw) {
        Some(i) => i,
        None => {
            error!("wrong ecall id {}", ecall_id_raw);
            return SGX_ERROR_INVALID_PARAMETER;
        }
    };

    // make sure this matches exact with that in enclave_wrapper.rs
    let r = match_ecall_ids! {
        ecall_id, inp, inp_len, output, output_cap, output_used,
        (
            EcallNewUser,
            // input
            Vec < ServerPubKeyPackage >,
            // output
            (SealedSharedSecretsDbClient, SealedSigPrivKey, UserRegistrationBlob),
            user::new_user
        ),
        (
            EcallNewUserBatch,
            // input
            (Vec < ServerPubKeyPackage >, usize),
            // output
            Vec<(SealedSharedSecretsDbClient, SealedSigPrivKey, UserRegistrationBlob)>,
            user::new_user_batch
        ),
        (
            EcallUserSubmit,
            (UserSubmissionReq, SealedSigPrivKey),
            (UserSubmissionBlob, SealedSharedSecretsDbClient),
            submit::user_submit_internal
        ),
    };
    //
    // warn!("{:?} finished after {:?}", ecall_id, start.elapsed());

    r
}

macro_rules! unmarshal_or_abort {
    ( $T:ty, $ptr:expr,$len:expr ) => {
        match serde_cbor::from_slice::<$T>(unsafe { slice::from_raw_parts($ptr, $len) }) {
            Ok(x) => x,
            Err(e) => {
                error!("Err unmarshal: {}", e);
                return SGX_ERROR_INVALID_PARAMETER;
            }
        }
    };
}

use env_logger::{Builder, Env};
use serde::Serialize;
use sgx_types::SgxError;

/// serialize v to outbuf. Return error if outbuf_cap is too small.
fn serialize_to_ptr<T: Serialize>(
    v: &T,
    outbuf: *mut u8,
    outbuf_cap: usize,
    outbuf_used: *mut usize,
) -> SgxError {
    let serialized = serde_cbor::to_vec(v).map_err(|e| {
        error!("error serializing: {}", e);
        SGX_ERROR_INVALID_PARAMETER
    })?;

    if serialized.len() > outbuf_cap {
        error!(
            "not enough output to write serialized message. need {} got {}",
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

use std::untrusted::time::InstantEx; // get time for perf test

fn generic_ecall<I, O>(
    ecall_id: EcallId,
    inp: *const u8,
    inp_len: usize,
    output: *mut u8,
    output_cap: usize,
    output_used: *mut usize,
    internal_fn: fn(&I) -> SgxResult<O>,
) -> sgx_status_t
where
    I: serde::de::DeserializeOwned,
    O: serde::Serialize,
{
    let start_time = std::time::Instant::now();

    debug!("serving {}", ecall_id.as_str());

    let input: I = unmarshal_or_abort!(I, inp, inp_len);

    debug!("input unmarshalled. {} bytes", inp_len);

    let result = match internal_fn(&input) {
        Ok(o) => o,
        Err(e) => return e,
    };

    let ret = match serialize_to_ptr(&result, output, output_cap, output_used) {
        Ok(_) => SGX_SUCCESS,
        Err(e) => {
            error!("[IN] can't write to untrusted land {}", e);
            e
        }
    };
    debug!(
        "done serving {}. took {} us",
        ecall_id.as_str(),
        start_time.elapsed().as_micros()
    );

    ret
}
