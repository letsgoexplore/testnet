extern crate sgx_urts;

use sgx_status_t;

use std::io::{Error, ErrorKind};

pub fn sgx_error(status: sgx_status_t) -> Error {
    Error::new(ErrorKind::Other, "SGX Error: ".to_owned() + status.as_str())
}
