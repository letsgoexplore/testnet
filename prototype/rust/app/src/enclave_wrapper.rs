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
}

pub struct DcNetEnclave {
    enclave: sgx_urts::SgxEnclave,
}

use sgx_status_t::SGX_SUCCESS;

impl DcNetEnclave {
    const ENCLAVE_FILE: &'static str = "enclave.signed.so";

    pub fn init() -> SgxResult<Self> {
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
            DcNetEnclave::ENCLAVE_FILE,
            debug,
            &mut launch_token,
            &mut launch_token_updated,
            &mut misc_attr,
        )?;

        Ok(Self { enclave: enclave })
    }

    pub fn close(self) {
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
}
