use quick_error;

use sgx_types::sgx_status_t;

quick_error! {
    #[derive(Debug)]
    pub enum CryptoError {
        XorNotEqualLength
        KeyError
        SgxCryptoError(descr: sgx_status_t) {
            description(descr.as_str())
            display("Error {}", descr)
        }
        Other
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum DcNetError {
        Crypto(err: CryptoError) {
            from()
            description("crypto error")
            display("crypto error: {}", err)
            cause(err)
        }
    }
}