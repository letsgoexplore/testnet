mod aggregation;
mod register;
mod submit;

use interface::*;
use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_SUCCESS};
use sgx_types::{sgx_status_t, SgxResult};

use std::slice;
use utils::serialize_to_ptr;


macro_rules! match_ecall_ids {
    (
        $ecall_id_raw:ident,$inp:ident,$inp_len:ident,$out:ident,$out_cap:ident,$out_used:ident,
        $(($name:ident, $type_i:ty, $type_o: ty, $impl:expr), )+
    ) => {
        let ecall_id = match EcallId::from_repr($ecall_id_raw) {
            Some(i) => i,
            None => return SGX_ERROR_INVALID_PARAMETER,
        };
        match ecall_id {
            $(EcallId::$name => generic_ecall::<$type_i,$type_o>(ecall_id,$inp,$inp_len,$out,$out_cap,$out_used,$impl),)+
        }
    }
}

use std::string::String;
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
    match_ecall_ids! {
        ecall_id_raw, inp, inp_len, output, output_cap, output_used,
        (EcallNewSgxKeypair,
            String,
            SealedKey,
            register::new_sgx_keypair_internal),

        (EcallUnsealToPublicKey,
            SealedKey,
            SgxProtectedKeyPub,
            register::unseal_to_pubkey_internal),

        (EcallRegisterUser,
            Vec<SgxProtectedKeyPub>,
            UserRegistration,
            register::register_user_internal),

        (EcallUserSubmit,
            (UserSubmissionReq,SealedKey),
            MarshalledSignedUserMessage,
            submit::user_submit_internal),

        (EcallAddToAggregate,
            (MarshalledSignedUserMessage,MarshalledPartialAggregate,SealedKey),
            MarshalledPartialAggregate,
            aggregation::add_to_aggregate_internal),
    }
}

macro_rules! unwrap_or_abort {
    ( $e:expr, $return: expr ) => {
        match $e {
            Ok(x) => x,
            Err(e) => {
                println!("Err {}", e);
                return $return;
            }
        }
    };
}

macro_rules! unmarshal_or_abort {
    ( $T:ty, $ptr:expr,$len:expr ) => {
        match serde_cbor::from_slice::<$T>(unsafe { slice::from_raw_parts($ptr, $len) }) {
            Ok(x) => x,
            Err(e) => {
                println!("Err {}", e);
                return SGX_ERROR_INVALID_PARAMETER;
            }
        }
    };
}

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
    println!("================== IN ENCLAVE {} ==================", ecall_id.as_str());
    let input: I = unmarshal_or_abort!(I, inp, inp_len);
    let result = match internal_fn(&input) {
        Ok(o) => o,
        Err(e) => return e,
    };

    let ret = match serialize_to_ptr(&result, output, output_cap, output_used) {
        Ok(_) => SGX_SUCCESS,
        Err(e) => {
            println!("[IN] can't write to untrusted land {}", e);
            e
        }
    };
    println!("================== LEAVING ENCLAVE {} ==================", ecall_id.as_str());

    ret
}

pub use self::aggregation::*;

