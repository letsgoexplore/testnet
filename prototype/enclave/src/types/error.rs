use sgx_types::sgx_status_t;
use std::string::ToString;

quick_error! {
    #[derive(Debug)]
    pub enum CryptoError {
        XorNotEqualLength
        KeyError
        SgxCryptoError(err: sgx_status_t) {
            description(err.as_str())
            display("Error {}", err)
            from()
            cause(err)
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
        AggregationError(err: &'static str) {
            description(err)
            display("Error {}", err)
            from()
        }
    }
}
