use sgx_status_t::SGX_SUCCESS;
use sgx_types;
use sgx_types::*;
use sgx_urts;
use sgx_urts::SgxEnclave;
use std::collections::BTreeSet;
use std::path::PathBuf;

use interface::*;
use std::time::Instant;

// error type for enclave operations
use quick_error::quick_error;
use sgx_types::sgx_status_t;

quick_error! {
    #[derive(Debug)]
    pub enum EnclaveError {
        SgxError(err: sgx_status_t) {
            from(sgx_status_t)
        }
        EnclaveLogicError(err: sgx_status_t) {
            from(sgx_status_t)
        }
        MarshallError(e: serde_cbor::Error) {
            from(e: serde_cbor::Error) -> (e)
        }
    }
}

pub type EnclaveResult<T> = Result<T, EnclaveError>;

#[derive(Clone, Debug)]
pub struct DcNetEnclave {
    enclave: sgx_urts::SgxEnclave,
}

use itertools::Itertools;
use std::iter::FromIterator;
use std::sync::mpsc;
use std::thread;

use crate::ecall_wrapper::ecall_allowed;

impl DcNetEnclave {
    pub fn init(enclave_file: &'static str) -> EnclaveResult<Self> {
        let enclave_path = PathBuf::from(enclave_file);

        let mut launch_token: sgx_launch_token_t = [0; 1024];
        let mut launch_token_updated: i32 = 0;
        // call sgx_create_enclave to initialize an enclave instance
        // Debug Support: set 2nd parameter to 1
        let debug = 1;
        let mut misc_attr = sgx_misc_attribute_t {
            secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
            misc_select: 0,
        };

        let start_time = std::time::Instant::now();
        let enclave = SgxEnclave::create(
            enclave_path,
            debug,
            &mut launch_token,
            &mut launch_token_updated,
            &mut misc_attr,
        )
        .map_err(EnclaveError::SgxError)?;

        debug!(
            "enclave initiated. took {}us",
            start_time.elapsed().as_micros()
        );
        Ok(Self { enclave })
    }

    pub fn destroy(self) {
        self.enclave.destroy();
        debug!("enclave destroyed.");
    }

    /// Returns the public key corresponding to the sealed secret key
    pub fn unseal_to_public_key_on_p256(
        &self,
        sealed_private_key: &Vec<u8>,
    ) -> EnclaveResult<SgxProtectedKeyPub> {
        Ok(ecall_allowed::unseal_to_public_key(
            self.enclave.geteid(),
            sealed_private_key,
        )?)
    }

    /// Given a message, constructs a round message for sending to an aggregator
    /// SGX will
    ///     1. Check the signature on the preivous round output against a signing key (might have to change API a bit for that)
    ///     2. Check that the current round is prev_round+1
    ///     3. Use the derived slot for the given message
    ///     4. Make a new footprint reservation for this round
    ///
    /// This function returns the message as well as the ratcheted shared secrets.
    ///
    /// Error handling:
    ///
    /// If scheduling failed (e.g., due to collision) this will return
    /// Err(EnclaveLogicError(SGX_ERROR_SERVICE_UNAVAILABLE)). Higher level application should
    /// retry, for example, in the next round.
    pub fn user_submit_round_msg(
        &self,
        submission_req: &UserSubmissionReqUpdated,
        sealed_usk: &SealedSigPrivKeyNoSGX,
    ) -> EnclaveResult<(UserSubmissionBlob, SealedSharedSecretsDbClient)> {
        Ok(ecall_allowed::user_submit(
            self.enclave.geteid(),
            (submission_req, sealed_usk),
        )?)
    }

    /// Create a new TEE protected secret key. Derives shared secrets with all the given KEM pubkeys.
    /// This function
    /// 1. Verify the enclave attestations on the packages
    /// 2. Use the KEM pubkeys to derive the shared secrets.
    /// TODO: what should it do with the signing keys?
    pub fn new_user(
        &self,
        server_pks: &[ServerPubKeyPackage],
    ) -> EnclaveResult<(
        SealedSharedSecretsDbClient,
        SealedSigPrivKeyNoSGX,
        EntityId,
        UserRegistrationBlobNew,
    )> {
        let u = ecall_allowed::new_user(self.enclave.geteid(), server_pks)?;
        Ok((u.0, u.1, EntityId::from(&u.2), u.2))
    }

    pub fn new_user_batch(
        &self,
        server_pks: &[ServerPubKeyPackage],
        n_users: usize,
    ) -> EnclaveResult<Vec<(
        SealedSharedSecretsDbClient,
        SealedSigPrivKeyNoSGX,
        UserRegistrationBlobNew,
    )>> {
        ecall_allowed::new_user_batch(self.enclave.geteid(), (server_pks, n_users))
    }

    pub fn run_enclave_tests(&self) -> SgxError {
        let mut retval = SGX_SUCCESS;
        unsafe {
            test_main_entrance(self.enclave.geteid(), &mut retval);
        }
        if retval != SGX_SUCCESS {
            return Err(retval);
        }
        Ok(())
    }
}

extern "C" {
    fn test_main_entrance(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
}
