use crate::interface::{KemPubKey, SgxSigningPubKey};
use crate::types::CryptoError;
use sgx_types::{
    sgx_ec256_private_t, sgx_ec256_public_t, SgxError, SgxResult, SGX_ECP256_KEY_SIZE,
};
use std::vec::Vec;

pub type CryptoResult<T> = Result<T, CryptoError>;

pub trait Signable {
    fn digest(&self) -> Vec<u8>;
    fn get_sig(&self) -> SgxSignature;
    fn get_pk(&self) -> SgxSigningPubKey;
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
    fn verify(&self) -> SgxResult<bool> {
        let msg_hash = self.digest();

        let ecdsa_handler = sgx_tcrypto::SgxEccHandle::new();
        ecdsa_handler.open()?;

        ecdsa_handler.ecdsa_verify_slice(&msg_hash, &self.get_pk().into(), &self.get_sig().into())
    }
}

pub trait SignMutable {
    fn sign_mut(&mut self, _: &SgxSigningKey) -> SgxError;
}

mod dining_crypto;
mod keys;
mod sgx_signature;
mod sig;

pub use self::dining_crypto::*;
pub use self::keys::*;
pub use self::sgx_signature::*;
