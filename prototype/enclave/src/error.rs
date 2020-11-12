use sgx_types::sgx_status_t;

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
    }
}
