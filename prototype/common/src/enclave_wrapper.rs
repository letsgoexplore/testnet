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
    pub fn new_sgx_protected_secret_key(&self) -> EnclaveResult<SealedSgxSigningKey> {
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
        Ok(SealedSgxSigningKey(sealed_signing_key))
    }

    // unseal the key to see its public key
    pub fn unseal_to_public_key_on_p256(
        &self,
        sealed_private_key: &SealedSgxSigningKey,
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

    /// get shared server keys
    /// XXX: for testing purposes only
    pub fn create_testing_shared_server_secrets(
        &self,
        num_of_keys: u32,
    ) -> EnclaveResult<SealedServerSecrets> {
        let mut output = Vec::new();
        output.resize(150 * num_of_keys as usize, 0); // TODO: estimate AggregateBlob size more intelligently
        println!("output cap {}", output.len());

        // Call user_submit through FFI
        let mut ret = sgx_status_t::default();
        let call_ret = unsafe {
            ecall_create_test_sealed_server_secrets(
                self.enclave.geteid(),
                &mut ret,
                num_of_keys,
                output.as_mut_ptr(),
                output.len() as u32,
            )
        };

        // Check for errors
        if call_ret != SGX_SUCCESS {
            return Err(call_ret.into());
        }
        if ret != SGX_SUCCESS {
            return Err(ret.into());
        }

        Ok(SealedServerSecrets(output))
    }

    /// Given a message and the relevant scheduling ticket, constructs a round message for sending
    /// to an aggregator
    pub fn user_submit_round_msg(
        &self,
        submission_req: &UserSubmissionReq,
        sealed_usk: &SealedSgxSigningKey,
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
        sealed_tee_signing_key: &SealedSgxSigningKey,
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

    /// Derives shared secrets with all the given KEM pubkeys, and derives a new signing pubkey.
    /// Returns sealed secrets, a sealed private key, and a registration message to send to an
    /// anytrust node
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

    /// Derives a new signing pubkey. Returns a sealed private key and a registration message to
    /// send to an anytrust node
    pub fn register_aggregator(
        &self,
        pubkeys: &[KemPubKey],
    ) -> EnclaveResult<(SealedSgxSigningKey, EntityId, AggRegistrationBlob)> {
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
        DcMessage, EntityId, SealedFootprintTicket, SealedServerSecrets, SealedSgxSigningKey,
        UserSubmissionReq, DC_NET_MESSAGE_LENGTH, SEALED_SGX_SIGNING_KEY_LENGTH, USER_ID_LENGTH,
    };
    use sgx_types::SGX_ECP256_KEY_SIZE;

    fn test_signing_key() -> SealedSgxSigningKey {
        SealedSgxSigningKey(base64::decode(
            "BAACAAAAAABIIPM3auay8gNNO3pLSKd4CwAAAAAAAP8AAAAAAAAAAN7O/UiywRKvGykkz2d1n86F3Ee9cYG212zsM6mkzty2AAAA8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABDAAAAAAAAAAAAAAAAAAAASgAAAAAAAAAAAAAAAAAAALwYU8Fi7XsACgg9uG5vb1hPA5sGF2ssQZdAtstmyMyTfqMwk1r3GLx56xkE8hhFL1DD2jqtzybkJYTrkNoJMvSAxfETQxmA4X5nzQGOT2cj/3GTa2V5cGFpcgAAAAAAAA==")
            .unwrap())
    }

    fn test_shared_server_secrets() -> SealedServerSecrets {
        // created by create_testing_shared_server_secrets(10)
        SealedServerSecrets(hex::decode("04000200000000004820f3376ae6b2f2034d3b7a4b48a7780b000000000000ff0000000000000000bdd2616ea22efab3d32f46466a9c6cd538bf46a8c98db5e0437b0c1d0a257148000000f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005d0300000000000000000000000000005d030000000000000000000000000000ced52eba72745007790b35d748276c6257469e881d5c8587b1560c3d29781b23d6aacc8a525bcf88d756ebee98759b9f581b5b0519b0a545a04e7b4f160438e7e77e5c520745f6b1744fe17a8a235e58bdfedc6f4c3b176611cdf69356123861d1b4abc11cdfe0fb3ab7e20b2114f55ebcb5a26086791f16e4cb5386db908a4ccc36eba2f6790eb7abc104b365d7a66dd0154d5c56e91f65c932dafaf9a5eb28e0d026f4def2cb5ec0708288055e4ea0a772369343f93b0f37596f10bad8882484f9f0b77ab9947374ec8db320faf70db602a38085bfe53c9c172c47b61dc024a9b94b0efe5279c31bf7fec66c2a8b4c544f75675e57c3e161cdbed35a8cac573a6f7e715ecae7bc6d434ad37e0f42c31618c18875d134c3df5cb7b496c74b2c5b5daf8d1070ca287f16e0f3acdf57408ce5a4586a0d70ac3f3898fd2d3d2ca8f14d442d13b7ad98c338bdc31f7fd267f7d116aeb667a0530fbedee25e96e96b2c6459f7ca7843d8ce70fff6c38170b6afe43716826b413b2056300e23edd37c56bf9832fdc94acefeb036136b3be251a8f56b810d686f3e56b484c225e5ce0c2f99309b8e46f0328140a64fa2aa12ffe6e85c0e1e5c34ed9ae1743961e2c5180ea272592c970aa3e8e463312f10cfe535df6bc8cb74d402c360d30b4f7c26cc76c6d3acb3ea3e5118f2243eaa1c091cff5cae8a7d3b674f73a41342031821dd5370c30edfe262a1a99e74bfe0dd8e93e62d2a102d969a54c457daec3f32c0a3a1b47f083f6a40562b563fb646630bb2fafa8c8a556a165e8d077ee8e79e3272a13df9790147d95af439809ee457bf8de0e2392e385856dd5aaf7482c86aae4bd342c907b111f8a8922293a8085864c6a7c23e32549cf827c3b5cd730c5bf0f3bf455daeefc70d0ff7829e4ac8b4ff09d237c69e87bf85e75f68d3534ff0ca86da7662a5e746038c72ea5d30e04144b0dd1ea8f6e27fece080e34217e6e1c98e77a14d089efbcd12d77b082a6e0057abb980f2b33a31c63c249adcae073315670f56b1bba1020e0774b0499b66614a98b39b51c05444342bb13f754bd2d685dabb6bcc5647d653b91508aa7e329595f253e6b97c9f5d9ef6cb39b1845daf9ccc789cc5f55c883f0ec197225a4517207973e6134298357b4e311ceb333ca6149df00504ee39595ef50b0ae675c84c69ffd9dd5771ec027b46f54b790fb0c22c84270bfadd302288586d09e6cda700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap())
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
        let req_1 = UserSubmissionReq {
            user_id: EntityId::default(),
            anytrust_group_id: EntityId::default(),
            round: 0u32,
            msg: DcMessage([0u8; DC_NET_MESSAGE_LENGTH]),
            ticket: SealedFootprintTicket(vec![0; 1]),
            shared_secrets: test_shared_server_secrets(),
        };
        let sgx_key_sealed = test_signing_key();
        let resp_1 = enc.user_submit_round_msg(&req_1, &sgx_key_sealed).unwrap();
        enc.destroy();
    }

    #[test]
    fn aggregation() {
        let enc = DcNetEnclave::init(TEST_ENCLAVE_PATH).unwrap();

        let req_1 = UserSubmissionReq {
            user_id: EntityId::default(),
            anytrust_group_id: EntityId::default(),
            round: 0u32,
            msg: DcMessage([0u8; DC_NET_MESSAGE_LENGTH]),
            ticket: SealedFootprintTicket(vec![0; 1]),
            shared_secrets: test_shared_server_secrets(),
        };
        let sgx_key_sealed = test_signing_key();

        let resp_1 = enc.user_submit_round_msg(&req_1, &sgx_key_sealed).unwrap();

        let mut empty_agg = enc.new_aggregate(0, &EntityId::default()).unwrap();
        enc.add_to_aggregate(&mut empty_agg, &resp_1, &sgx_key_sealed)
            .unwrap();

        // this should error because user is already in
        assert!(enc
            .add_to_aggregate(&mut empty_agg, &resp_1, &sgx_key_sealed)
            .is_err());

        let req_2 = UserSubmissionReq {
            user_id: EntityId::from([0xffu8; USER_ID_LENGTH]),
            anytrust_group_id: EntityId::default(),
            round: 0u32,
            msg: DcMessage([1u8; DC_NET_MESSAGE_LENGTH]),
            ticket: SealedFootprintTicket(vec![0; 1]),
            shared_secrets: test_shared_server_secrets(),
        };
        let resp_2 = enc.user_submit_round_msg(&req_2, &sgx_key_sealed).unwrap();
        enc.add_to_aggregate(&mut empty_agg, &resp_2, &sgx_key_sealed)
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
