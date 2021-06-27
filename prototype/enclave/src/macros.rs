use std::slice;

#[macro_export]
macro_rules! unwrap_or_abort {
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
macro_rules! unmarshal_or_abort {
    ( $T:ty, $ptr:expr,$len:expr ) => {
        match serde_cbor::from_slice::<$T>(unsafe { slice::from_raw_parts($ptr, $len) }) {
            Ok(x) => x,
            Err(e) => {
                println!("Err {}", e);
                return SGX_ERROR_INVALID_PARAMETER;
            }
        }
    };
}

macro_rules! unseal_or_abort {
    ( $T:ty, $ptr:expr,$len:expr ) => {
        match unsafe { utils::unseal_ptr_and_deser::<$T>($ptr, $len) } {
            Ok(x) => x,
            Err(e) => {
                println!("can't unseal {}", e);
                return SGX_ERROR_INVALID_PARAMETER;
            }
        }
    };
}

macro_rules! unseal_vec_or_abort {
    ( $T:ty, $vec:expr) => {
        match unsafe { utils::unseal_vec_and_deser::<$T>($vec) } {
            Ok(x) => x,
            Err(e) => {
                println!("can't unseal {}", e);
                return SGX_ERROR_INVALID_PARAMETER;
            }
        }
    };
}
