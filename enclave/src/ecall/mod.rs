mod aggregation;
mod keygen;
mod server;
mod submit;
mod user;

use interface::*;
use sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_SUCCESS};
use sgx_types::{sgx_status_t, SgxResult};
use unseal::{SealInto, UnsealableInto};

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

use std::convert::TryFrom;
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
            EcallNewSgxKeypair,
            String,
            (Vec<u8>, AttestedPublicKey), // (sealed sk, public key)
            |role: &String| {
                let (sk, pk) = keygen::new_sgx_keypair_ext_internal(role)?;
                let sealed_sk: SealedSigPrivKey = sk.seal_into()?;
                Ok((sealed_sk.0, pk))
            }
        ),
        (
            EcallUnsealToPublicKey,
           Vec<u8>, // sealed sk
            SgxProtectedKeyPub,
            |sealed_sk: &Vec<u8>| {
                let sk: SgxPrivateKey = SealedSigPrivKey(sealed_sk.to_vec()).unseal_into()?;

                SgxProtectedKeyPub::try_from(&sk)
            }
        ),
        (
            EcallNewUser,
            // input
            Vec < ServerPubKeyPackage >,
            // output
            (SealedSharedSecretDb, SealedSigPrivKey, UserRegistrationBlob),
            user::new_user
        ),
        (
            EcallNewUserBatch,
            // input
            (Vec < ServerPubKeyPackage >, usize),
            // output
            Vec<(SealedSharedSecretDb, SealedSigPrivKey, UserRegistrationBlob)>,
            user::new_user_batch
        ),
        (
            EcallNewUserUpdated,
            // input
            Vec < ServerPubKeyPackageNoSGX >,
            // output
            (SealedSharedSecretsDbClient, SealedSigPrivKeyNoSGX, UserRegistrationBlobNew),
            user::new_user_updated
        ),
        (
            EcallNewUserBatchUpdated,
            // input
            (Vec < ServerPubKeyPackageNoSGX >, usize),
            // output
            Vec<(SealedSharedSecretsDbClient, SealedSigPrivKeyNoSGX, UserRegistrationBlobNew)>,
            user::new_user_batch_updated
        ),
        (
            EcallNewServer,
            // input
            (),
            // output
            (SealedSigPrivKey, SealedKemPrivKey, ServerRegistrationBlob),
            server::new_server
        ),
        (
            EcallUserSubmit,
            (UserSubmissionReq, SealedSigPrivKey),
            (UserSubmissionBlob, SealedSharedSecretDb),
            submit::user_submit_internal
        ),
        (
            EcallUserSubmitUpdated,
            (UserSubmissionReqUpdated, SealedSigPrivKeyNoSGX),
            (UserSubmissionBlobUpdated, SealedSharedSecretsDbClient),
            submit::user_submit_internal_updated
        ),
        (
            EcallAddToAggregate,
            (
                RoundSubmissionBlob,
                SignedPartialAggregate,
                Option<BTreeSet<RateLimitNonce>>,
                SealedSigPrivKey
            ),
            (SignedPartialAggregate, Option<BTreeSet<RateLimitNonce>>),
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
            EcallRecvUserRegistrationBatch,
            // input:
            (SignedPubKeyDb, SealedKemPrivKey, Vec<UserRegistrationBlob>),
            // output: updated SignedPubKeyDb, SealedSharedSecretDb
            (SignedPubKeyDb, SealedSharedSecretDb),
            server::recv_user_registration_batch
        ),
        (
            EcallUnblindAggregate,
            (RoundSubmissionBlob,SealedSigPrivKey,SealedSharedSecretDb),
            (UnblindedAggregateShareBlob, SealedSharedSecretDb),
            server::unblind_aggregate
        ),
        (
            EcallUnblindAggregatePartial,
            (u32,SealedSharedSecretDb,BTreeSet<EntityId>),
            RoundSecret,
            server::unblind_aggregate_partial
        ),
        (
            EcallUnblindAggregateMerge,
            (RoundSubmissionBlob,Vec<RoundSecret>, SealedSigPrivKey,SealedSharedSecretDb),
            (UnblindedAggregateShareBlob, SealedSharedSecretDb),
            server::unblind_aggregate_merge
        ),
        (
            EcallDeriveRoundOutput,
            (SealedSigPrivKey, Vec < UnblindedAggregateShareBlob >),
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
        (
            EcallLeakDHSecrets,
            SealedSharedSecretDb,
            SealedSharedSecretDb,
            server::leak_dh_secrets
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

use crypto::SgxPrivateKey;
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

    // debug!("output serialized to {} bytes", serialized.len());

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
