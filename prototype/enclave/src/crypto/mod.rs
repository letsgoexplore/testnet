use crate::interface::{PrvKey, PubKey, Signature};
use crate::types::CryptoError;
use std::vec::Vec;

pub type CryptoResult<T> = Result<T, CryptoError>;

pub trait Signable {
    fn digest(&self) -> Vec<u8>;
    fn get_sig(&self) -> Signature;
    fn get_pk(&self) -> PubKey;
    fn sign(&self, ssk: &PrvKey) -> CryptoResult<(Signature, PubKey)> {
        let dig = self.digest();

        let ecdsa_handler = sgx_tcrypto::SgxEccHandle::new();
        ecdsa_handler.open()?;

        let pk = sgx_tcrypto::rsgx_ecc256_pub_from_priv(&ssk.into())
            .map(PubKey::from)
            .map_err(CryptoError::SgxCryptoError)?;

        let sig = ecdsa_handler
            .ecdsa_sign_slice(&dig, &ssk.into())
            .map(Signature::from)?;

        Ok((sig, pk))
    }
    fn verify(&self) -> CryptoResult<bool> {
        let msg_hash = self.digest();

        let ecdsa_handler = sgx_tcrypto::SgxEccHandle::new();
        ecdsa_handler.open()?;

        ecdsa_handler
            .ecdsa_verify_slice(&msg_hash, &self.get_pk().into(), &self.get_sig().into())
            .map_err(CryptoError::from)
    }
}

pub trait SignMutable {
    fn sign_mut(&mut self, _: &PrvKey) -> CryptoResult<()>;
}

mod dining_crypto;
mod sig;

pub use self::dining_crypto::derive_round_secret;
