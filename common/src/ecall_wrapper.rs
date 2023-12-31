use sgx_status_t::SGX_SUCCESS;
use sgx_types;
use sgx_types::sgx_status_t;
use sgx_types::*;

// Ecalls
extern "C" {
    fn ecall_entrypoint(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        ecall_id_raw: u8,
        inp: *const u8,
        inp_len: usize,
        output: *mut u8,
        output_cap: usize,
        output_used: *mut usize,
    ) -> sgx_status_t;
}

const ENCLAVE_OUTPUT_BUF_SIZE: usize = 30 * 1024000; // 5MB buffer should be enough?

macro_rules! gen_ecall_stub {
    ( $name:expr, $type_i:ty, $type_o: ty, $fn_name: ident) => {
        pub fn $fn_name(
            enclave_id: crate::ecall_wrapper::sgx_enclave_id_t,
            inp: $type_i,
        ) -> crate::EnclaveResult<$type_o> {
            let very_begining = std::time::Instant::now();
            let mut start = std::time::Instant::now();

            let marshaled_input = serde_cbor::to_vec(&inp)?;

            let time_marshal_input = start.elapsed();
            start = std::time::Instant::now();

            let mut ret = crate::ecall_wrapper::SGX_SUCCESS;
            let mut out_buf = vec![0u8; crate::ecall_wrapper::ENCLAVE_OUTPUT_BUF_SIZE];
            let mut outbuf_used = 0usize;

            let time_allocate_out_buf = start.elapsed();
            start = std::time::Instant::now();

            // Call FFI
            let call_ret = unsafe {
                crate::ecall_wrapper::ecall_entrypoint(
                    enclave_id,
                    &mut ret,
                    $name as u8,
                    marshaled_input.as_ptr(),
                    marshaled_input.len(),
                    out_buf.as_mut_ptr(),
                    out_buf.len(),
                    &mut outbuf_used,
                )
            };

            let time_ecall = start.elapsed();
            start = std::time::Instant::now();

            // Check for errors
            if call_ret != crate::ecall_wrapper::sgx_status_t::SGX_SUCCESS {
                return Err(crate::enclave::EnclaveError::SgxError(call_ret));
            }
            if ret != crate::ecall_wrapper::sgx_status_t::SGX_SUCCESS {
                return Err(crate::enclave::EnclaveError::EnclaveLogicError(ret));
            }

            let output: $type_o = serde_cbor::from_slice(&out_buf[..outbuf_used]).map_err(|e| {
                log::error!("can't unmarshal: {}", e);
                crate::enclave::EnclaveError::MarshallError(e)
            })?;

            let time_unmarshal = start.elapsed();
            let total = very_begining.elapsed();

            // print time only if ecall took more than 100ms
            if total > std::time::Duration::from_millis(100) {
                info!(
                    "Ecall {:?} took {:?}. MAR={:?}({}B), ALLOC={:?}, EC={:?}, UNMAR={:?}({}B)",
                    $name,
                    total,
                    time_marshal_input,
                    marshaled_input.len(),
                    time_allocate_out_buf,
                    time_ecall,
                    time_unmarshal,
                    outbuf_used
                );
            }

            Ok(output)
        }
    };
}

/// This macro generates a bunch of functions that will check the ecall is given the right types
macro_rules! match_ecall_ids {
    (
        $(($name:ident, $type_i:ty, $type_o: ty, $fn_name: ident),)+
    ) => {
            $(
                gen_ecall_stub! {$name, $type_i, $type_o, $fn_name}
            )+
        }
}

pub mod ecall_allowed {
    use interface::*;
    use EcallId::*;

    match_ecall_ids! {
        (
            EcallNewUser,
            &[ServerPubKeyPackage],
            (SealedSharedSecretsDbClient, SealedSigPrivKey, UserRegistrationBlob),
            new_user
        ),
        (
            EcallNewUserBatch,
            (&[ServerPubKeyPackage], usize), // input
            Vec<(SealedSharedSecretsDbClient, SealedSigPrivKey, UserRegistrationBlob)>, // output
            new_user_batch
        ),
        (
            EcallUserSubmit,
            (&UserSubmissionReq, &SealedSigPrivKey),
            (UserSubmissionBlob, SealedSharedSecretsDbClient),
            user_submit
        ),
    }
}
