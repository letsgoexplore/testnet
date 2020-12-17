use crate::interface::{PrvKey, PubKey, Signature};
use crate::types::CryptoError;
use std::vec::Vec;

pub type CryptoResult<T> = Result<T, CryptoError>;

pub trait Signable {
    fn digest(&self) -> Vec<u8>;
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
}

pub trait SignMutable {
    fn sign_mut(&mut self, _: &PrvKey) -> CryptoResult<()>;
}

pub trait Verifiable {
    fn verify(&self) -> CryptoResult<bool>;
}

mod dining_crypto;
mod sig;

pub use self::dining_crypto::derive_round_secret;
