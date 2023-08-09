use ed25519_dalek::{
    SecretKey,
    PublicKey,
    Signature,
    Keypair,
    Signer,
    Verifier,
    SECRET_KEY_LENGTH,
    PUBLIC_KEY_LENGTH,
    KEYPAIR_LENGTH,
};

use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use std::convert::TryFrom;
use std::vec::Vec;
use std::vec;
use sha2::{Digest, Sha256};

use crate::user_request::{EntityId, UserSubmissionMessageUpdated};
use crate::ecall_interface_types::{RoundOutput, RoundOutputUpdated};

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
pub struct NoSgxProtectedKeyPub(pub [u8; PUBLIC_KEY_LENGTH]);

impl AsRef<[u8]> for NoSgxProtectedKeyPub {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for NoSgxProtectedKeyPub {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        std::write!(f, "({})", hex::encode(&self.0))
    }
}

impl Display for NoSgxProtectedKeyPub {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        std::write!(f, "{}", hex::encode(&self.0))
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
    pub xpk: NoSgxProtectedKeyPub,
    pub role: std::string::String,
    /// role denotes the intended use of this key e.g., "aggregator" "client" "anytrust server"
    pub tee_linkable_attestation: std::vec::Vec<u8>, // binds this key to an enclave
}

impl Debug for AttestedPublicKeyNoSGX {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestedPublicKeyNoSGX")
            .field("pk", &self.pk)
            .field("xpk", &self.xpk)
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
        let pk = PublicKey::from(&sk);
        Ok(NoSgxProtectedKeyPub(pk.to_bytes()))
    }
}

/// Contains a server's signing and KEM pubkeys
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ServerPubKeyPackageNoSGX {
    pub sig: PublicKey,
    pub kem: PublicKey,
    pub xkem: NoSgxProtectedKeyPub,
}

/// Store the bytes of signatures
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Default, Debug, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
pub struct NoSgxSignature(pub Vec<u8>);

// impl Default for NoSgxSignature {
//     fn default() -> Self {
//         Self([0u8; SIGNATURE_LENGTH])
//     }
// }

/// Used by servers in round outputs
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SignatureNoSGX {
    pub pk: PublicKey,
    pub sig: NoSgxSignature,
}

pub trait Hashable {
    fn sha256(&self) -> [u8; 32];
}

use std::convert::TryInto;

impl Hashable for RoundOutput {
    fn sha256(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.input(&self.round.to_le_bytes());
        h.input(&self.dc_msg.digest());

        h.result().try_into().unwrap()
    }
}

impl Hashable for RoundOutputUpdated {
    fn sha256(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.input(&self.round.to_le_bytes());
        h.input(&self.dc_msg.digest());

        h.result().try_into().unwrap()
    }
}

pub trait MultiSignableUpdated {
    fn digest(&self) -> Vec<u8>;
    fn sign(&self, ssk: &SecretKey) -> Result<(NoSgxSignature, PublicKey), ()> {
        let dig = self.digest();

        let pk: PublicKey = ssk.into();
        let sk_bytes: [u8; SECRET_KEY_LENGTH] = ssk.to_bytes();
        let pk_bytes: [u8; PUBLIC_KEY_LENGTH] = pk.to_bytes();
        let mut keypair_bytes: [u8; KEYPAIR_LENGTH] = [0; KEYPAIR_LENGTH];
        keypair_bytes[..SECRET_KEY_LENGTH].copy_from_slice(&sk_bytes);
        keypair_bytes[SECRET_KEY_LENGTH..].copy_from_slice(&pk_bytes);

        let keypair: Keypair = Keypair::from_bytes(&keypair_bytes).expect("Failed to generate keypair from bytes");
        let sig = NoSgxSignature(keypair.sign(dig.as_slice()).to_bytes().to_vec());

        Ok((sig, pk))
    }
    /// verify against a list of public keys
    /// return indices of keys that verify
    fn verify_multisig(&self, pks: &[PublicKey]) -> Result<Vec<usize>, ()>;
}

impl MultiSignableUpdated for RoundOutputUpdated {
    fn digest(&self) -> Vec<u8> {
        self.sha256().to_vec()
    }

    fn verify_multisig(&self, pks: &[PublicKey]) -> Result<Vec<usize>, ()> {
        // log::debug!(
        //     "verifying RoundOutput (with {} signatures) against a list of {} server PKs",
        //     self.server_sigs.len(),
        //     pks.len()
        // );

        // digest
        let msg_hash = self.digest();

        let mut verified = vec![];
        for i in 0..self.server_sigs.len() {
            let sig: Signature = Signature::from_bytes(self.server_sigs[i].sig.0.clone().as_slice())
                .expect("failed to generate Signature from bytes");
            let pk: PublicKey = self.server_sigs[i].pk;

            // verify the signature
            if pk.verify(msg_hash.as_slice(), &sig).is_ok() {
                // debug!("signature verified against {:?}", pk);
            }

            // check if pk is in the server PK list
            match pks.iter().position(|&k| k == pk) {
                Some(i) => verified.push(i),
                None => {
                    // log::error!("PK {:?} is not in the server PK list", pk);
                }
            }
        }

        Ok(verified)
    }
}

pub trait SignableUpdated {
    fn digest(&self) -> Vec<u8>;
    fn get_sig(&self) -> NoSgxSignature;
    fn get_pk(&self) -> PublicKey;
    fn sign(&self, ssk: &NoSgxPrivateKey) -> Result<(NoSgxSignature, PublicKey), ()> {
        let dig = self.digest();

        let pk: PublicKey = (&SecretKey::from_bytes(&ssk.r).expect("Failed to generate pk from sk bytes")).into();
        let sk_bytes: [u8; SECRET_KEY_LENGTH] = ssk.r;
        let pk_bytes: [u8; PUBLIC_KEY_LENGTH] = pk.to_bytes();
        let mut keypair_bytes: [u8; KEYPAIR_LENGTH] = [0; KEYPAIR_LENGTH];
        keypair_bytes[..SECRET_KEY_LENGTH].copy_from_slice(&sk_bytes);
        keypair_bytes[SECRET_KEY_LENGTH..].copy_from_slice(&pk_bytes);

        let keypair: Keypair = Keypair::from_bytes(&keypair_bytes).expect("Failed to generate keypair from bytes");
        let sig = NoSgxSignature(keypair.sign(dig.as_slice()).to_bytes().to_vec());

        Ok((sig, pk))
    }
}

impl SignableUpdated for UserSubmissionMessageUpdated {
    fn digest(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.input(b"Begin UserSubmissionMessage");
        hasher.input(&self.anytrust_group_id);
        // for id in self.user_ids.iter() {
        //     hasher.input(id);
        // }
        hasher.input(self.user_id);
        hasher.input(&self.aggregated_msg.digest());
        hasher.input(b"End UserSubmissionMessage");

        hasher.result().to_vec()
    }

    fn get_sig(&self) -> NoSgxSignature {
        self.tee_sig.clone()
    }

    fn get_pk(&self) -> PublicKey {
        self.tee_pk
    }
}
