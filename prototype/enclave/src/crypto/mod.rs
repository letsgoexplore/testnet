use crate::interface::{KemPubKey, SgxSigningPubKey};
use crate::types::CryptoError;
use sgx_types::{sgx_ec256_private_t, sgx_ec256_public_t, SGX_ECP256_KEY_SIZE};
use std::vec::Vec;

pub type CryptoResult<T> = Result<T, CryptoError>;

pub trait Signable {
    fn digest(&self) -> Vec<u8>;
    fn get_sig(&self) -> SgxSignature;
    fn get_pk(&self) -> SgxSigningPubKey;
    fn sign(&self, ssk: &SgxSigningKey) -> CryptoResult<(SgxSignature, SgxSigningPubKey)> {
        let dig = self.digest();

        let ecdsa_handler = sgx_tcrypto::SgxEccHandle::new();
        ecdsa_handler
            .open()
            .map_err(CryptoError::SgxCryptoLibError)?;

        let pk = sgx_tcrypto::rsgx_ecc256_pub_from_priv(&ssk.into())
            .map(SgxSigningPubKey::from)
            .map_err(CryptoError::SgxCryptoLibError)?;

        let sig = ecdsa_handler
            .ecdsa_sign_slice(&dig, &ssk.into())
            .map(SgxSignature::from)
            .map_err(CryptoError::SgxCryptoLibError)?;

        Ok((sig, pk))
    }
    fn verify(&self) -> CryptoResult<bool> {
        let msg_hash = self.digest();

        let ecdsa_handler = sgx_tcrypto::SgxEccHandle::new();
        ecdsa_handler
            .open()
            .map_err(CryptoError::SgxCryptoLibError)?;

        ecdsa_handler
            .ecdsa_verify_slice(&msg_hash, &self.get_pk().into(), &self.get_sig().into())
            .map_err(CryptoError::SgxCryptoLibError)
    }
}

pub trait SignMutable {
    fn sign_mut(&mut self, _: &SgxSigningKey) -> CryptoResult<()>;
}

mod dining_crypto;
mod keys;
mod sgx_signature;
mod sig;

pub use self::dining_crypto::{derive_round_secret, SharedServerSecret};
pub use self::keys::{KemKeyPair, KemPrvKey, SgxSigningKey};
pub use self::sgx_signature::SgxSignature;
