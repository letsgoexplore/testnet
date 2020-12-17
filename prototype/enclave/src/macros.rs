#[macro_export]
macro_rules! unwrap_or_return {
    ( $e:expr, $return: expr ) => {
        match $e {
            Ok(x) => x,
            Err(e) => {
                println!("Err {}", e);
                return $return;
            }
        }
    };
}

#[macro_export]
macro_rules! unmarshal_or_return {
    ( $T:ty, $ptr:ident,$len:ident ) => {
        match serde_cbor::from_slice::<$T>(unsafe { slice::from_raw_parts($ptr, $len) }) {
            Ok(x) => x,
            Err(e) => {
                println!("Err {}", e);
                return SGX_ERROR_INVALID_PARAMETER;
            }
        }
    };
}
