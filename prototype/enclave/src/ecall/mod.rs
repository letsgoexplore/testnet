mod aggregation;
mod register;
mod server;
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
            None => {
                error!("wrong ecall id {}", $ecall_id_raw);
                return SGX_ERROR_INVALID_PARAMETER
            },
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
    let env = Env::default()
        .filter_or("ENCLAVE_LOG_LEVEL", "debug")
        .write_style_or("ENCLAVE_LOG_STYLE", "always");
    let _ = Builder::from_env(env).target(Target::Stdout).try_init();

    // make sure this matches exact with that in enclave_wrapper.rs
    match_ecall_ids! {
        ecall_id_raw, inp, inp_len, output, output_cap, output_used,
        (
            EcallNewSgxKeypair,
            String,
            SealedKey,
            register::new_sgx_keypair_internal
        ),
        (
            EcallUnsealToPublicKey,
            SealedKey,
            SgxProtectedKeyPub,
            register::unseal_to_pubkey_internal
        ),
        (
            EcallRegisterUser,
            Vec<SgxProtectedKeyPub>,
            UserRegistration,
            register::register_user
        ),
        (
            EcallUserSubmit,
            (UserSubmissionReq, SealedSigPrivKey),
            RoundSubmissionBlob,
            submit::user_submit_internal
        ),
        (
            EcallAddToAggregate,
            (RoundSubmissionBlob,SignedPartialAggregate,SealedSigPrivKey),
            SignedPartialAggregate,
            aggregation::add_to_aggregate_internal
        ),
        (
            EcallRecvUserRegistration,
            // input:
            (SignedPubKeyDb, SealedSharedSecretDb, SealedKemPrivKey, UserRegistrationBlob),
            // output: updated SignedPubKeyDb, SealedSharedSecretDb
            (SignedPubKeyDb, SealedSharedSecretDb),
            server::recv_user_registration
        ),
        (
            EcallUnblindAggregate,
            (RoundSubmissionBlob,SealedSigPrivKey,SealedSharedSecretDb),
            UnblindedAggregateShareBlob,
            server::unblind_aggregate),
        (
            EcallDeriveRoundOutput,
            Vec<UnblindedAggregateShareBlob>,
            RoundOutput,
            server::derive_round_output
        ),
        (
            EcallRecvAggregatorRegistration,
            (SignedPubKeyDb, AggRegistrationBlob),
            SignedPubKeyDb,
            server::recv_aggregator_registration
        ),
        (
            EcallRecvServerRegistration,
            (SignedPubKeyDb, ServerRegistrationBlob),
            SignedPubKeyDb,
            server::recv_server_registration
        ),
    }
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

use env_logger::{Builder, Env, Target};

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
    debug!("starting {}", ecall_id.as_str());

    let input: I = unmarshal_or_abort!(I, inp, inp_len);
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
    debug!("done ecall {}", ecall_id.as_str());

    ret
}
