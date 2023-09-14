use ed25519_dalek::{
    Keypair, PublicKey, SecretKey, Signature, Signer, Verifier, KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH,
    SECRET_KEY_LENGTH,
};

use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use log;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::vec::Vec;
use std::{println, vec};

use crate::ecall_interface_types::RoundOutput;
use crate::user_request::{DcMessage, DcRoundMessage, EntityId, UserSubmissionMessage};

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Copy, Clone, Default, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
pub struct SgxProtectedKeyPub(pub [u8; PUBLIC_KEY_LENGTH]);

impl AsRef<[u8]> for SgxProtectedKeyPub {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for SgxProtectedKeyPub {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        std::write!(f, "({})", hex::encode(&self.0))
    }
}

impl Display for SgxProtectedKeyPub {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        std::write!(f, "{}", hex::encode(&self.0))
    }
}

impl SgxProtectedKeyPub {
    /// Computes the entity ID corresponding to this KEM pubkey
    pub fn get_entity_id(&self) -> EntityId {
        EntityId::from(self)
    }
}

/// AttestedPublicKey is pk + attestation
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AttestedPublicKey {
    pub pk: SgxProtectedKeyPub,  // sig pub key
    pub xpk: SgxProtectedKeyPub, // kem pub key. todo: both keys are derived from the same secret.
    pub role: std::string::String,
    /// role denotes the intended use of this key e.g., "aggregator" "client" "anytrust server"
    pub tee_linkable_attestation: std::vec::Vec<u8>, // binds this key to an enclave
}

impl Debug for AttestedPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestedPublicKey")
            .field("pk", &self.pk)
            .field("xpk", &self.xpk)
            .field("role", &self.role)
            .field(
                "tee_linkable_attestation",
                &hex::encode(&self.tee_linkable_attestation),
            )
            .finish()
    }
}

/// Contains a server's signing and KEM pubkeys
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ServerPubKeyPackage {
    pub sig: PublicKey,
    pub kem: PublicKey,
    pub xkem: SgxProtectedKeyPub, //todo: why is server key using SGX type?
}

/// Store the bytes of signatures
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Default, Debug, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
pub struct SignatureBytes(pub Vec<u8>);

/// Used by servers in round outputs
#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OutputSignature {
    pub pk: PublicKey,
    pub sig: SignatureBytes,
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

pub trait MultiSignable {
    fn digest(&self) -> Vec<u8>;
    fn sign(&self, ssk: &SecretKey) -> Result<(SignatureBytes, PublicKey), ()> {
        let dig = self.digest();

        let pk: PublicKey = ssk.into();
        let sk_bytes: [u8; SECRET_KEY_LENGTH] = ssk.to_bytes();
        let pk_bytes: [u8; PUBLIC_KEY_LENGTH] = pk.to_bytes();
        let mut keypair_bytes: [u8; KEYPAIR_LENGTH] = [0; KEYPAIR_LENGTH];
        keypair_bytes[..SECRET_KEY_LENGTH].copy_from_slice(&sk_bytes);
        keypair_bytes[SECRET_KEY_LENGTH..].copy_from_slice(&pk_bytes);

        let keypair: Keypair =
            Keypair::from_bytes(&keypair_bytes).expect("Failed to generate keypair from bytes");
        let sig = SignatureBytes(keypair.sign(dig.as_slice()).to_bytes().to_vec());

        Ok((sig, pk))
    }
    /// verify against a list of public keys
    /// return indices of keys that verify
    fn verify_multisig(&self, pks: &[PublicKey]) -> Result<Vec<usize>, ()>;
}

impl MultiSignable for RoundOutput {
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
            let sig: Signature =
                Signature::from_bytes(self.server_sigs[i].sig.0.clone().as_slice())
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

// various functions for computing a.xor(b)
pub trait Xor: Clone {
    // xor_mut computes and sets self = xor(self, other)
    fn xor_mut(&mut self, other: &Self)
    where
        Self: Sized;

    // xor returns xor(self, other)
    fn xor(&self, other: &Self) -> Self {
        let mut copy = self.clone();
        copy.xor_mut(other);
        copy
    }
}

impl Xor for DcMessage {
    fn xor_mut(&mut self, other: &Self) {
        for (lhs, rhs) in self.0.iter_mut().zip(other.0.iter()) {
            *lhs ^= rhs
        }
    }
}

impl Xor for DcRoundMessage {
    fn xor_mut(&mut self, other: &Self) {
        assert_eq!(
            self.aggregated_msg.num_rows(),
            other.aggregated_msg.num_rows()
        );
        assert_eq!(
            self.aggregated_msg.num_columns(),
            other.aggregated_msg.num_columns()
        );

        // XOR the scheduling messages
        for (lhs, rhs) in self
            .scheduling_msg
            .as_mut_slice()
            .iter_mut()
            .zip(other.scheduling_msg.as_slice().iter())
        {
            *lhs ^= rhs;
        }

        // XOR the round messages
        for (lhs, rhs) in self
            .aggregated_msg
            .as_mut_slice()
            .iter_mut()
            .zip(other.aggregated_msg.as_slice().iter())
        {
            *lhs ^= rhs;
        }
    }
}
