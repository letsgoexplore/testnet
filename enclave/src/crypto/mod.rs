use crate::types::CryptoError;
use sgx_types::{SgxError, SgxResult};
pub type CryptoResult<T> = Result<T, CryptoError>;
use sha2::Digest;

mod aes_rng;
mod dining_crypto;
mod keys;

pub use self::dining_crypto::*;
pub use self::keys::*;
