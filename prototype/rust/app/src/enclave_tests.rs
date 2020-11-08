extern crate sgx_types;
extern crate sgx_urts;

use sgx_types::*;

use sgx_status_t::SGX_SUCCESS;
use sgx_urts::SgxEnclave;
use std::io::Result;

use utils::sgx_error;

extern "C" {
    fn test_main_entrance(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
}

pub fn test(enclave: &SgxEnclave) -> Result<()> {
    let mut retval = SGX_SUCCESS;
    unsafe {
        test_main_entrance(enclave.geteid(), &mut retval);
    }
    if retval != SGX_SUCCESS {
        return Err(sgx_error(retval));
    }
    Ok(())
}
