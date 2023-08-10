use crate::interface::{SgxSignature, SgxSigningPubKey};
use crate::interface::{NoSgxPrivateKey, Hashable};
use crate::types::CryptoError;
use sgx_types::{SgxError, SgxResult, SGX_ECP256_KEY_SIZE};
use std::vec::Vec;

pub type CryptoResult<T> = Result<T, CryptoError>;

use sha2::Digest;

pub trait SignMutableUpdated {
    fn sign_mut_updated(&mut self, _: &NoSgxPrivateKey) -> SgxError;
}

pub trait MultiSignable {
    fn digest(&self) -> Vec<u8>;
    fn sign(&self, ssk: &SgxSigningKey) -> SgxResult<(SgxSignature, SgxSigningPubKey)> {
        let dig = self.digest();

        let ecdsa_handler = sgx_tcrypto::SgxEccHandle::new();
        ecdsa_handler.open()?;

        let pk = sgx_tcrypto::rsgx_ecc256_pub_from_priv(&ssk.into()).map(SgxSigningPubKey::from)?;

        let sig = ecdsa_handler
            .ecdsa_sign_slice(&dig, &ssk.into())
            .map(SgxSignature::from)?;                

        Ok((sig, pk))
    }
    /// verify against a list of public keys
    /// return indices of keys that verify
    fn verify_multisig(&self, pks: &[SgxSigningPubKey]) -> SgxResult<Vec<usize>>;
}

mod aes_rng;
mod dining_crypto;
mod keys;

pub use self::dining_crypto::*;
pub use self::keys::*;
