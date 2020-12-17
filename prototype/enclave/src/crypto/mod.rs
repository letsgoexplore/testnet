use crate::interface::PrvKey;
use crate::types::CryptoError;

pub type CryptoResult<T> = Result<T, CryptoError>;

pub trait SignMutable {
    fn sign(&mut self, _: &PrvKey) -> CryptoResult<()>;
}

pub trait Verifiable {
    fn verify(&self) -> CryptoResult<bool>;
}

mod dining_crypto;
mod sig;

pub use self::dining_crypto::{derive_round_secret, xor};
