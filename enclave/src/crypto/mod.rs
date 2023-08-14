use crate::interface::{RoundOutput, SgxSignature, SgxSigningPubKey};
use crate::interface::{RoundOutputUpdated, NoSgxPrivateKey, NoSgxSignature, Hashable};
use crate::types::CryptoError;
use sgx_types::{SgxError, SgxResult, SGX_ECP256_KEY_SIZE};
use std::vec::Vec;

pub type CryptoResult<T> = Result<T, CryptoError>;

use sha2::Digest;

use ed25519_dalek::{
    SecretKey,
    PublicKey,
    Keypair,
    Signer,
    SECRET_KEY_LENGTH,
    PUBLIC_KEY_LENGTH,
    KEYPAIR_LENGTH,
};

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

impl MultiSignable for RoundOutput {
    fn digest(&self) -> Vec<u8> {
        self.sha256().to_vec()
    }

    fn verify_multisig(&self, pks: &[SgxSigningPubKey]) -> SgxResult<Vec<usize>> {
        log::debug!(
            "verifying RoundOutput (with {} signatures) against a list of {} server PKs",
            self.server_sigs.len(),
            pks.len()
        );

        // digest
        let msg_hash = self.digest();

        let ecdsa_handler = sgx_tcrypto::SgxEccHandle::new();
        ecdsa_handler.open()?;

        let mut verified = vec![];
        for i in 0..self.server_sigs.len() {
            let sig = self.server_sigs[i].sig;
            let pk = self.server_sigs[i].pk;

            // verify the signature
            if ecdsa_handler.ecdsa_verify_slice(&msg_hash, &pk.into(), &sig.into())? {
                debug!("signature verified against {}", pk);
            }

            // check if pk is in the server PK list
            match pks.iter().position(|&k| k == pk) {
                Some(i) => verified.push(i),
                None => {
                    log::error!("PK {} is not in the server PK list", pk);
                }
            }
        }

        Ok(verified)
    }
}

mod aes_rng;
mod dining_crypto;
mod keys;

pub use self::dining_crypto::*;
pub use self::keys::*;
