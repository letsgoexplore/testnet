use crate::interface::{SgxSignature, SgxSigningPubKey};
use crate::interface::{NoSgxPrivateKey, Hashable};
use crate::types::CryptoError;
use sgx_types::{SgxError, SgxResult, SGX_ECP256_KEY_SIZE};
use std::vec::Vec;

pub type CryptoResult<T> = Result<T, CryptoError>;

use sha2::Digest;

pub trait SignMutableSGX {
    fn sign_mut_sgx(&mut self, _: &NoSgxPrivateKey) -> SgxError;
}

mod aes_rng;
mod dining_crypto;
mod keys;

pub use self::dining_crypto::*;
pub use self::keys::*;
