use sgx_types;
use sgx_urts;

use sgx_types::*;
use sgx_urts::SgxEnclave;

use interface::*;

extern "C" {
    fn new_tee_signing_key(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        output: *mut u8,
        output_size: u32,
        bytewritten: *mut u32,
    ) -> sgx_status_t;

    fn unseal_to_pubkey(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        inp: *mut u8,
        inp_len: u32,
    ) -> sgx_status_t;

    fn client_submit(
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

    fn test_main_entrance(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
}

pub struct DcNetEnclave {
    enclave: sgx_urts::SgxEnclave,
}

use sgx_status_t::SGX_SUCCESS;
use std::path::PathBuf;

#[allow(dead_code)]
impl DcNetEnclave {
    pub fn init(enclave_file: &'static str) -> SgxResult<Self> {
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

        println!("{:?}", std::env::current_dir().unwrap());

        let enclave = SgxEnclave::create(
            enclave_path,
            debug,
            &mut launch_token,
            &mut launch_token_updated,
            &mut misc_attr,
        )?;

        Ok(Self { enclave: enclave })
    }

    pub fn destroy(self) {
        self.enclave.destroy();
    }

    pub fn geteid(&self) -> sgx_types::sgx_enclave_id_t {
        self.enclave.geteid()
    }

    // return sealed key
    pub fn new_tee_signing_key(&self) -> SgxResult<Vec<u8>> {
        // 100 byte should be enough?
        let mut ret = SGX_SUCCESS;
        let mut output = vec![0; 1024];
        let mut output_bytes_written: u32 = 0;

        let call_ret = unsafe {
            new_tee_signing_key(
                self.enclave.geteid(),
                &mut ret,
                output.as_mut_ptr(),
                output.len() as u32,
                &mut output_bytes_written,
            )
        };

        if call_ret != SGX_SUCCESS {
            return Err(call_ret);
        }

        if ret != SGX_SUCCESS {
            return Err(ret);
        }

        output.truncate(output_bytes_written as usize);

        Ok(output)
    }

    // unseal the key to see its public key
    pub fn unseal_to_pubkey(&self, sealed_key: &Vec<u8>) -> SgxError {
        let mut ret = SGX_SUCCESS;
        let mut sealed_key_copy = sealed_key.clone();
        let call_ret = unsafe {
            unseal_to_pubkey(
                self.enclave.geteid(),
                &mut ret,
                sealed_key_copy.as_mut_ptr(),
                sealed_key_copy.len() as u32,
            )
        };

        if call_ret != SGX_SUCCESS {
            return Err(call_ret);
        }

        if ret != SGX_SUCCESS {
            return Err(ret);
        }

        Ok(())
    }

    // TODO: sealed_tee_prv_key should be sealed
    pub fn client_submit(
        &self,
        send_request: &SendRequest,
        sealed_tee_prv_key: &Vec<u8>,
    ) -> SgxResult<SignedUserMessage> {
        let req_json = serde_json::to_vec(&send_request).unwrap();
        // this should be big enough
        // TODO: serde_json is very inefficient with [u8]. but who cares for now :-)
        let mut output = vec![0; DC_NET_MESSAGE_LENGTH * 5];
        let mut output_bytes_written: usize = 0;

        let mut ret = sgx_status_t::default();
        let call_ret = unsafe {
            client_submit(
                self.enclave.geteid(),
                &mut ret,
                req_json.as_ptr(),
                req_json.len(),
                sealed_tee_prv_key.as_ptr(),
                sealed_tee_prv_key.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut output_bytes_written,
            )
        };

        if call_ret != SGX_SUCCESS {
            return Err(call_ret);
        }

        if ret != SGX_SUCCESS {
            return Err(ret);
        }

        match serde_json::from_slice(&output[..output_bytes_written]) {
            Ok(m) => Ok(m),
            Err(e) => {
                println!("Err {}", e);
                Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
            }
        }
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

#[cfg(test)]
mod tests {
    const TEST_ENCLAVE_PATH: &'static str = "/root/sgx/bin/enclave.signed.so";
    use enclave_wrapper::DcNetEnclave;
    extern crate base64;
    extern crate hexdump;
    extern crate interface;
    extern crate sgx_types;
    use interface::*;
    use sgx_status_t::SGX_SUCCESS;

    #[test]
    fn key_seal_unseal() {
        let enc = DcNetEnclave::init(TEST_ENCLAVE_PATH).unwrap();
        let sealed = enc.new_tee_signing_key().unwrap();
        let encoded = base64::encode(&sealed);
        println!("sealed key len = {}", sealed.len());
        println!("base64 encoded: {}", encoded);
        enc.unseal_to_pubkey(&sealed).unwrap();
    }

    #[test]
    fn client_submit() {
        let enc = DcNetEnclave::init(TEST_ENCLAVE_PATH).unwrap();

        let req_1 = SendRequest {
            message: [9 as u8; DC_NET_MESSAGE_LENGTH],
            round: 0,
            server_keys: vec![ServerSecret::gen_test(1), ServerSecret::gen_test(2)],
        };

        // using a testing key
        let sgx_key_sealed = base64::decode("BAACAAAAAABIIPM3auay8gNNO3pLSKd4CwAAAAAAAP8AAAAAAAAAAIaOkrL+G/tjwqpYb2cPLagU2yBuV2gTFnrQR1YRijjLAAAA8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAJAAAAAAAAAAAAAAAAAAAAMcwvJUTIR5owP6OfXybb09woO+S2ZZ1DHRXUFLcu7GfdV+AQ6ddvsqjCZpdA0X+BQECAwQ=").unwrap();

        let resp_1 = enc.client_submit(&req_1, &sgx_key_sealed).unwrap();
        let req_2 = SendRequest {
            message: resp_1.message,
            round: 0,
            server_keys: req_1.server_keys,
        };

        let resp_2 = enc.client_submit(&req_2, &sgx_key_sealed).unwrap();

        // resp 2 == req 1 because server's are xor twice
        assert_eq!(resp_2.message, req_1.message);

        enc.destroy();
    }

    #[test]
    fn enclave_tests() {
        let enc = DcNetEnclave::init(TEST_ENCLAVE_PATH).unwrap();

        enc.run_enclave_tests().unwrap();

        enc.destroy()
    }
}
