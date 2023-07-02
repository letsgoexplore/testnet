use ed25519_dalek::{
    SecretKey,
    PublicKey,
    SECRET_KEY_LENGTH,
    PUBLIC_KEY_LENGTH,
};

use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use std::convert::TryFrom;
use sha2::Sha512;

use crate::user_request::EntityId;

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
pub struct NoSgxProtectedKeyPub(pub [u8; PUBLIC_KEY_LENGTH]);

impl Debug for NoSgxProtectedKeyPub {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        std::write!(f, "({})", hex::encode(&self.0))
    }
}

impl Display for NoSgxProtectedKeyPub {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        std::write!(f, "{}", hex::encode(self.0))
    }
}


impl NoSgxProtectedKeyPub {
    /// Computes the entity ID corresponding to this KEM pubkey
    pub fn get_entity_id(&self) -> EntityId {
        EntityId::from(self)
    }
}

/// AttestedPublicKey is pk + attestation
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AttestedPublicKeyNoSGX {
    pub pk: NoSgxProtectedKeyPub,
    pub role: std::string::String,
    /// role denotes the intended use of this key e.g., "aggregator" "client" "anytrust server"
    pub tee_linkable_attestation: std::vec::Vec<u8>, // binds this key to an enclave
}

impl Debug for AttestedPublicKeyNoSGX {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestedPublicKeyNoSGX")
            .field("pk", &self.pk)
            .field("role", &self.role)
            .field(
                "tee_linkable_attestation",
                &hex::encode(&self.tee_linkable_attestation)
            )
            .finish()
    }
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
pub struct NoSgxPrivateKey {
    pub r: [u8; SECRET_KEY_LENGTH],
}

#[cfg(feature = "trusted")]
use sgx_rand::{Rand, Rng};
#[cfg(feature = "trusted")]
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

impl TryFrom<&NoSgxPrivateKey> for NoSgxProtectedKeyPub {
    type Error = &'static str;
    fn try_from(sk: &NoSgxPrivateKey) -> Result<Self, Self::Error> {
        let sk = SecretKey::from_bytes(&sk.r).expect("Cannot generate the secret key from the given bytes");
        let pk = PublicKey::from_secret::<Sha512>(&sk);
        Ok(NoSgxProtectedKeyPub(pk.to_bytes()))
    }
}

/// Contains a server's signing and KEM pubkeys
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ServerPubKeyPackageNoSGX {
    pub sig: PublicKey,
    pub kem: PublicKey,
}
