use core::convert::TryFrom;
use crypto::SgxPrivateKey;
use interface::*;
use sgx_rand::{Rand, Rng};
use sgx_types::sgx_status_t::SGX_ERROR_UNEXPECTED;
use sgx_types::SgxResult;
use std::string::ToString;
use std::vec;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;

use x25519_dalek::{StaticSecret, PublicKey};
use ed25519_dalek::SECRET_KEY_LENGTH;


#[derive(Copy, Clone, Default, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
pub struct NoSgxPrivateKey {
    pub r: [u8; SECRET_KEY_LENGTH],
}


impl Rand for NoSgxPrivateKey {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        let mut r = [0 as u8; SECRET_KEY_LENGTH];
        rng.fill_bytes(&mut r);

        NoSgxPrivateKey { r }
    }
}

impl Debug for NoSgxPrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoSgxPrivateKey")
            .field("r", &hex::encode(&self.r))
            .finish()
    }
}

impl Display for NoSgxPrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        std::write!(f, "{}", hex::encode(self.r))
    }
}

impl AsRef<[u8]> for &NoSgxPrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.r
    }
}

pub fn new_keypair_ext_internal(role: &str) -> SgxResult<(NoSgxPrivateKey, AttestedPublicKeyNoSGX)> {
    let mut rand = sgx_rand::SgxRng::new().map_err(|e| {
        error!("can't create rand {}", e);
        SGX_ERROR_UNEXPECTED
    })?;

    // generate a random secret key
    let sk = rand.gen::<NoSgxPrivateKey>();
    let secret = StaticSecret::from(sk.r);
    let xpk = PublicKey::from(&secret);
    let attested_key = AttestedPublicKeyNoSGX {
        pk: NoSgxProtectedKeyPub(xpk.to_bytes()),
        xpk: NoSgxProtectedKeyPub(xpk.to_bytes()),
        role: role.to_string(),
        tee_linkable_attestation: vec![0], // TODO: add attestation
    };

    Ok((sk, attested_key))
}
