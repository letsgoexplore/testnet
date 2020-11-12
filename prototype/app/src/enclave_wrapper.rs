use sgx_types;
use sgx_urts;

use sgx_types::*;
use sgx_urts::SgxEnclave;

use interface::*;

extern "C" {
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

impl DcNetEnclave {
    const ENCLAVE_FILE: &'static str = "enclave.signed.so";

    pub fn init(enclave_path_inp: Option<PathBuf>) -> SgxResult<Self> {
        let enclave_path = enclave_path_inp.unwrap_or(PathBuf::from(DcNetEnclave::ENCLAVE_FILE));

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

    // TODO: sealed_tee_prv_key should be sealed
    pub fn client_submit(
        &self,
        send_request: &SendRequest,
        sealed_tee_prv_key: &PrvKey,
    ) -> SgxResult<SignedUserMessage> {
        let req_json = serde_json::to_vec(&send_request).unwrap();
        let key_json = serde_json::to_vec(&sealed_tee_prv_key).unwrap();

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
                key_json.as_ptr(),
                key_json.len(),
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
    extern crate interface;
    use interface::*;

    #[test]
    fn client_submit() {
        let enclave_path = std::path::PathBuf::from(TEST_ENCLAVE_PATH);
        let enc = DcNetEnclave::init(Some(enclave_path.to_owned()))
            .expect(&format!("Make sure the enclave is at {:?}", enclave_path));

        let req_1 = SendRequest {
            message: [9 as u8; DC_NET_MESSAGE_LENGTH],
            round: 0,
            server_keys: vec![ServerSecret::gen_test(1), ServerSecret::gen_test(2)],
        };

        let sgx_key = PrvKey::gen_test(9);

        let resp_1 = enc.client_submit(&req_1, &sgx_key).unwrap();

        let req_2 = SendRequest {
            message: resp_1.message,
            round: 0,
            server_keys: req_1.server_keys,
        };

        let resp_2 = enc.client_submit(&req_2, &sgx_key).unwrap();

        // resp 2 == req 1 because server's are xor twice
        assert_eq!(resp_2.message, req_1.message);

        enc.destroy();
    }

    #[test]
    fn enclave_tests() {
        let enclave_path = std::path::PathBuf::from(TEST_ENCLAVE_PATH);
        let enc = DcNetEnclave::init(Some(enclave_path.to_owned()))
            .expect(&format!("Make sure the enclave is at {:?}", enclave_path));

        enc.run_enclave_tests().unwrap();

        enc.destroy()
    }
}
