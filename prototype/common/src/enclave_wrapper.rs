use sgx_types;
use sgx_urts;

use sgx_status_t::SGX_SUCCESS;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::path::PathBuf;

use interface::*;

// error type for enclave operations
use sgx_types::sgx_status_t;
use std::error::Error;
use std::fmt::{Display, Formatter};

use rand::Rng;
use sgx_types::sgx_status_t::SGX_ERROR_INVALID_PARAMETER;

#[derive(Debug)]
pub struct EnclaveError {
    e: sgx_status_t,
}

impl From<sgx_status_t> for EnclaveError {
    fn from(e: sgx_status_t) -> Self {
        return EnclaveError { e };
    }
}

impl Display for EnclaveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.e.as_str())
    }
}

impl Error for EnclaveError {}

pub type EnclaveResult<T> = Result<T, EnclaveError>;

/// Describes a partial aggregate. It can consist of a single user's round message (i.e., the
/// output of `user_submit_round_msg`, or the XOR of multiple user's round messages (i.e., the
/// output of `finalize_aggregate`).
pub struct AggregateBlob(pub Vec<u8>);

/// Describes user registration information. This contains key encapsulations as well as a linkably
/// attested signature pubkey.
pub struct UserRegistrationBlob(pub Vec<u8>);

/// Describes aggregator registration information. This contains a linkably attested signature
/// pubkey.
pub struct AggRegistrationBlob(pub Vec<u8>);

// E calls
extern "C" {
    fn ecall_new_sgx_signing_key(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        output: *mut u8,
        output_size: u32,
    ) -> sgx_status_t;

    fn ecall_unseal_to_pubkey(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        inp: *mut u8,
        inp_len: u32,
        out_x: *mut u8,
        out_y: *mut u8,
    ) -> sgx_status_t;

    fn ecall_user_submit(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        send_request: *const u8,
        send_request_len: usize,
        sealed_tee_prv_key: *const u8,
        sealed_tee_prv_key_len: usize,
        output: *mut u8,
        output_size: usize,
        bytes_written: *mut usize,
    ) -> sgx_status_t;

    fn ecall_aggregate(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        new_input_ptr: *const u8,
        new_input_len: usize,
        current_aggregation_ptr: *const u8,
        current_aggregation_len: usize,
        sealed_tee_prv_ptr: *const u8,
        sealed_tee_prv_len: usize,
        output_aggregation_ptr: *mut u8,
        output_size: usize,
        output_bytes_written: *mut usize,
    ) -> sgx_status_t;

    fn test_main_entrance(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;

    fn ecall_create_test_sealed_server_secrets(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        num_of_keys: u32,
        out_buf: *mut u8,
        out_buf_cap: u32,
    ) -> sgx_status_t;

    fn ecall_register_user(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        marshalled_server_pks_ptr: *const u8,
        marshalled_server_pks_len: usize,
        output_buf: *mut u8,
        output_buf_cap: usize,
        output_buf_used: *mut usize,
    ) -> sgx_status_t;
}

#[derive(Debug, Default)]
pub struct DcNetEnclave {
    enclave: sgx_urts::SgxEnclave,
}

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

        let enclave = SgxEnclave::create(
            enclave_path,
            debug,
            &mut launch_token,
            &mut launch_token_updated,
            &mut misc_attr,
        )?;

        Ok(Self { enclave })
    }

    pub fn destroy(self) {
        self.enclave.destroy();
    }

    pub fn get_eid(&self) -> sgx_types::sgx_enclave_id_t {
        self.enclave.geteid()
    }

    /// new_sgx_protected_key creates a new key pair on P-256 and returns the sealed secret key.
    /// This method can be used for creating signing keys and KEM private keys.
    /// Use unseal_to_pubkey to unseal the key and compute its public key.
    pub fn new_sgx_protected_secret_key(&self) -> EnclaveResult<SealedPrivateKey> {
        // TODO: Ensure that 1024 is large enough for any sealed privkey
        let mut ret = SGX_SUCCESS;

        let mut sealed_signing_key = vec![0u8; 1024];

        // Call keygen through FFI
        let call_ret = unsafe {
            ecall_new_sgx_signing_key(
                self.enclave.geteid(),
                &mut ret,
                sealed_signing_key.as_mut_ptr(),
                sealed_signing_key.len() as u32,
            )
        };

        // Check for errors
        if call_ret != SGX_SUCCESS {
            return Err(EnclaveError::from(call_ret));
        }
        if ret != SGX_SUCCESS {
            return Err(EnclaveError::from(ret));
        }

        // Package the output in the correct type
        Ok(SealedPrivateKey(sealed_signing_key))
    }

    // unseal the key to see its public key
    pub fn unseal_to_public_key_on_p256(
        &self,
        sealed_private_key: &SealedPrivateKey,
    ) -> EnclaveResult<SgxProtectedKeyPub> {
        let mut ret = SGX_SUCCESS;

        // make a copy since (for reasons that I don't understand yet) unseal takes a mutable pointer as input
        // TODO: figure out why.
        let mut privkey_copy = sealed_private_key.clone();

        let mut pubkey = SgxProtectedKeyPub::default();

        // Call unseal_to_pubkey through FFI
        let call_ret = unsafe {
            ecall_unseal_to_pubkey(
                self.enclave.geteid(),
                &mut ret,
                privkey_copy.0.as_mut_ptr(),
                privkey_copy.0.len() as u32,
                pubkey.gx.as_mut_ptr(),
                pubkey.gy.as_mut_ptr(),
            )
        };

        // Check for errors
        if call_ret != SGX_SUCCESS {
            return Err(EnclaveError::from(call_ret));
        }
        if ret != SGX_SUCCESS {
            return Err(EnclaveError::from(ret));
        }

        Ok(pubkey)
    }

    /// Given a message and the relevant scheduling ticket, constructs a round message for sending
    /// to an aggregator
    pub fn user_submit_round_msg(
        &self,
        submission_req: &UserSubmissionReq,
        sealed_usk: &SealedPrivateKey,
    ) -> EnclaveResult<AggregateBlob> {
        let marshaled_req = serde_cbor::to_vec(&submission_req).map_err(|e| {
            println!("Error marshaling request {}", e);
            EnclaveError {
                e: SGX_ERROR_INVALID_PARAMETER,
            }
        })?;

        let mut output = Vec::new();
        const RESERVED_LEN: usize = 5120;
        output.resize(RESERVED_LEN, 0); // TODO: estimate AggregateBlob size more intelligently
        let mut output_bytes_written: usize = 0;

        // Call user_submit through FFI
        let mut ret = sgx_status_t::default();
        let call_ret = unsafe {
            ecall_user_submit(
                self.enclave.geteid(),
                &mut ret,
                marshaled_req.as_ptr(),
                marshaled_req.len(),
                sealed_usk.0.as_ptr(),
                sealed_usk.0.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut output_bytes_written,
            )
        };

        // Check for errors
        if call_ret != SGX_SUCCESS {
            return Err(call_ret.into());
        }
        if ret != SGX_SUCCESS {
            return Err(ret.into());
        }

        output.resize(output_bytes_written, 0);

        Ok(AggregateBlob(output))
    }

    /// Makes an empty aggregation state for the given round and wrt the given anytrust nodes
    pub fn new_aggregate(
        &self,
        round: u32,
        anytrust_group_id: &EntityId,
    ) -> EnclaveResult<MarshalledPartialAggregate> {
        // The partial aggregate MUST store set of anytrust nodes
        Ok(MarshalledPartialAggregate(Vec::new()))
    }

    /// Adds the given input from a user to the given partial aggregate
    /// Note: if marshalled_current_aggregation is empty (len = 0), an empty aggregation is created
    //  and the signed message is aggregated into that.
    pub fn add_to_aggregate(
        &self,
        agg: &mut MarshalledPartialAggregate,
        new_input: &AggregateBlob,
        sealed_tee_signing_key: &SealedPrivateKey,
    ) -> EnclaveResult<()> {
        // This MUST check that the input blob is made wrt the same set of anytrust nodes

        // todo: make sure this is big enough
        let mut output = vec![0; 10240];
        let mut output_bytes_written: usize = 0;

        let mut ret = sgx_status_t::default();

        // Call aggregate through FFI
        let ecall_ret = unsafe {
            ecall_aggregate(
                self.get_eid(),
                &mut ret,
                new_input.0.as_ptr(),
                new_input.0.len(),
                agg.0.as_ptr(),
                agg.0.len(),
                sealed_tee_signing_key.0.as_ptr(),
                sealed_tee_signing_key.0.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut output_bytes_written,
            )
        };

        // Check for errors
        if ecall_ret != SGX_SUCCESS {
            return Err(ecall_ret.into());
        }
        if ret != SGX_SUCCESS {
            return Err(ret.into());
        }

        // update agg
        output.resize(output_bytes_written, 0);
        agg.0.clear();
        agg.0.extend_from_slice(&output);

        Ok(())
    }

    /// Constructs an aggregate message from the given state. The returned blob is to be sent to
    /// the parent aggregator or an anytrust server.
    /// TODO: 1) what is this supposed to achieve? i.e., no why just send partial aggregate to the any trust server?
    /// TODO: 2) should AggregateBlob contain all of the user ids? If so, AggregateBlob is also the result of user_submit which contains only one user id.
    pub fn finalize_aggregate(
        &self,
        agg: &MarshalledPartialAggregate,
    ) -> EnclaveResult<AggregateBlob> {
        unimplemented!()
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

    /// Create a new TEE protected secret key. Derives shared secrets with all the given KEM pubkeys.
    /// Returns UserRegistration that contains sealed secrets, a sealed private key, and attestation
    /// information to send to anytrust nodes.
    pub fn register_user(&self, pubkeys: &[KemPubKey]) -> EnclaveResult<UserRegistration> {
        let marshaled_pubkeys = serde_cbor::to_vec(&pubkeys.to_vec()).map_err(|e| {
            println!("Error marshaling request {}", e);
            EnclaveError {
                e: SGX_ERROR_INVALID_PARAMETER,
            }
        })?;

        // todo: make sure this is big enough
        let mut output = vec![0; 10240];
        let mut output_bytes_written: usize = 0;

        let mut ret = sgx_status_t::default();

        // Call aggregate through FFI
        let ecall_ret = unsafe {
            ecall_register_user(
                self.get_eid(),
                &mut ret,
                marshaled_pubkeys.as_ptr(),
                marshaled_pubkeys.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut output_bytes_written,
            )
        };

        // Check for errors
        if ecall_ret != SGX_SUCCESS {
            return Err(ecall_ret.into());
        }
        if ret != SGX_SUCCESS {
            return Err(ret.into());
        }

        output.resize(output_bytes_written, 0);

        Ok(serde_cbor::from_slice(&output).map_err(|e| {
            println!("Error marshaling request {}", e);
            EnclaveError {
                e: SGX_ERROR_INVALID_PARAMETER,
            }
        })?)
    }

    /// Create a new TEE protected secret key. Derives shared secrets with all the given KEM pubkeys.
    /// Returns UserRegistration that contains sealed secrets, a sealed private key, and attestation
    /// information to send to anytrust nodes.
    /// Derives a new signing pubkey. Returns a sealed private key and a registration message to
    /// send to an anytrust node
    pub fn register_aggregator(
        &self,
    ) -> EnclaveResult<(SealedPrivateKey, EntityId, AggRegistrationBlob)> {
        unimplemented!()
    }

    // TODO: Write anytrust node function that receives registration blobs and processes them
}

#[cfg(test)]
mod enclave_tests {
    const TEST_ENCLAVE_PATH: &'static str = "/sgxdcnet/lib/enclave.signed.so";

    use super::DcNetEnclave;

    extern crate base64;
    extern crate hex;
    extern crate hexdump;
    extern crate interface;
    extern crate sgx_types;

    use hex::FromHex;
    use interface::{
        DcMessage, EntityId, SealedFootprintTicket, SealedPrivateKey, SealedServerSecrets,
        SgxProtectedKeyPub, UserSubmissionReq, DC_NET_MESSAGE_LENGTH,
        SEALED_SGX_SIGNING_KEY_LENGTH, USER_ID_LENGTH,
    };
    use sgx_types::SGX_ECP256_KEY_SIZE;

    fn test_signing_key() -> SealedPrivateKey {
        SealedPrivateKey(base64::decode(
            "BAACAAAAAABIIPM3auay8gNNO3pLSKd4CwAAAAAAAP8AAAAAAAAAAN7O/UiywRKvGykkz2d1n86F3Ee9cYG212zsM6mkzty2AAAA8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABDAAAAAAAAAAAAAAAAAAAASgAAAAAAAAAAAAAAAAAAALwYU8Fi7XsACgg9uG5vb1hPA5sGF2ssQZdAtstmyMyTfqMwk1r3GLx56xkE8hhFL1DD2jqtzybkJYTrkNoJMvSAxfETQxmA4X5nzQGOT2cj/3GTa2V5cGFpcgAAAAAAAA==")
            .unwrap())
    }

    #[test]
    fn key_seal_unseal() {
        let enc = DcNetEnclave::init(TEST_ENCLAVE_PATH).unwrap();
        let sealed = enc.new_sgx_protected_secret_key().unwrap();
        assert!(sealed.0.len() > 0);
        let encoded = base64::encode(&sealed.0);
        enc.unseal_to_public_key_on_p256(&sealed).unwrap();

        let test_sealed = test_signing_key();
        let test_pk = enc
            .unseal_to_public_key_on_p256(&test_sealed)
            .expect("unseal");
        let expected_x = "394b6c980dddb2ad9cc4e6403d433a06b17ab8994343751fc402e786ca584c5d";
        let expected_y = "0c32869de9005c8a1cc1cfdd0e53d0a530cc31a6585a8784369a6490a124df9f";
        assert_eq!(
            test_pk.gx,
            <[u8; SGX_ECP256_KEY_SIZE]>::from_hex(expected_x).expect("unhex x")
        );
        assert_eq!(
            test_pk.gy,
            <[u8; SGX_ECP256_KEY_SIZE]>::from_hex(expected_y).expect("unhex y")
        );
    }

    #[test]
    fn user_submit_round_msg() {
        let enc = DcNetEnclave::init(TEST_ENCLAVE_PATH).unwrap();

        // create server public keys
        let spks = create_server_pubkeys(&enc, 10);
        let user_reg = enc.register_user(&spks).unwrap();

        let req_1 = UserSubmissionReq {
            user_id: user_reg.get_user_id(),
            anytrust_group_id: user_reg.get_anygroup_id(),
            round: 0u32,
            msg: DcMessage([0u8; DC_NET_MESSAGE_LENGTH]),
            ticket: SealedFootprintTicket(vec![0; 1]),
            shared_secrets: user_reg.get_sealed_server_secrets().to_owned(),
        };
        let sgx_key_sealed = test_signing_key();
        let resp_1 = enc.user_submit_round_msg(&req_1, &sgx_key_sealed).unwrap();
        enc.destroy();
    }

    fn create_server_pubkeys(enc: &DcNetEnclave, num_of_servers: i32) -> Vec<SgxProtectedKeyPub> {
        let mut pks = Vec::new();
        for i in 0..num_of_servers {
            let sk = enc.new_sgx_protected_secret_key().expect("key");
            pks.push(enc.unseal_to_public_key_on_p256(&sk).expect("pk"));
        }

        pks
    }

    #[test]
    fn aggregation() {
        let enc = DcNetEnclave::init(TEST_ENCLAVE_PATH).unwrap();

        // create server public keys
        let spks = create_server_pubkeys(&enc, 10);
        let user_reg = enc.register_user(&spks).unwrap();
        print!("user reg {:?}", user_reg);

        let req_1 = UserSubmissionReq {
            user_id: user_reg.get_user_id(),
            anytrust_group_id: user_reg.get_anygroup_id(),
            round: 0u32,
            msg: DcMessage([0u8; DC_NET_MESSAGE_LENGTH]),
            ticket: SealedFootprintTicket(vec![0; 1]),
            shared_secrets: user_reg.get_sealed_server_secrets().to_owned(),
        };

        let sealed_agg_tee_key = test_signing_key();

        let resp_1 = enc
            .user_submit_round_msg(&req_1, &sealed_agg_tee_key)
            .unwrap();

        let mut empty_agg = enc.new_aggregate(0, &EntityId::default()).unwrap();
        enc.add_to_aggregate(&mut empty_agg, &resp_1, &sealed_agg_tee_key)
            .unwrap();

        // this should error because user is already in
        assert!(enc
            .add_to_aggregate(&mut empty_agg, &resp_1, &sealed_agg_tee_key)
            .is_err());

        let user_reg_2 = enc.register_user(&spks).unwrap();
        print!("user reg 2 {:?}", user_reg_2);

        let req_2 = UserSubmissionReq {
            user_id: user_reg_2.get_user_id(),
            anytrust_group_id: user_reg_2.get_anygroup_id(),
            round: 0u32,
            msg: DcMessage([1u8; DC_NET_MESSAGE_LENGTH]),
            ticket: SealedFootprintTicket(vec![0; 1]),
            shared_secrets: user_reg_2.get_sealed_server_secrets().to_owned(),
        };
        let resp_2 = enc
            .user_submit_round_msg(&req_2, &sealed_agg_tee_key)
            .unwrap();

        enc.add_to_aggregate(&mut empty_agg, &resp_2, &sealed_agg_tee_key)
            .unwrap();

        enc.destroy();
    }

    use rand;

    #[test]
    fn register() {
        let enc = DcNetEnclave::init(TEST_ENCLAVE_PATH).unwrap();

        let mut pks = Vec::new();
        for i in 0..10 {
            let sk = enc.new_sgx_protected_secret_key().expect("key");
            pks.push(enc.unseal_to_public_key_on_p256(&sk).expect("pk"));
        }

        let user_reg = enc.register_user(&pks).unwrap();
        print!("user reg {:?}", user_reg);

        enc.destroy();
    }

    #[test]
    fn enclave_tests() {
        println!("===begin enclave tests");
        let enc = DcNetEnclave::init(TEST_ENCLAVE_PATH).unwrap();

        enc.run_enclave_tests().unwrap();

        enc.destroy();
        println!("===end enclave tests");
    }
}
