use interface::*;
use sgx_types::sgx_status_t;

use std::prelude::v1::*;

use crate::unseal::Sealable;
use byteorder::{ByteOrder, LittleEndian};
use hkdf::Hkdf;
use sha2::Sha256;
use utils;

use super::*;
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};

/// A SharedServerSecret is the long-term secret shared between an anytrust server and this use enclave
#[derive(Copy, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiffieHellmanSharedSecret([u8; SGX_ECP256_KEY_SIZE]);

impl Debug for DiffieHellmanSharedSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

/// A ServerSecrets consists of an array of shared secrets established between a user and with a
/// group of any-trust server
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SharedSecretsDb {
    pub db: BTreeMap<SgxProtectedKeyPub, DiffieHellmanSharedSecret>,
}

impl Debug for SharedSecretsDb {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("SharedSecretsDb")
            .field("db", &self.db)
            .finish()
    }
}

use std::convert::TryFrom;

impl SharedSecretsDb {
    pub fn to_sealed_db(&self) -> SgxResult<SealedSharedSecretDb> {
        let mut sealed_shared_secrets = SealedSharedSecretDb::default();
        for (k, s) in self.db.iter() {
            sealed_shared_secrets.db.insert(k.to_owned(), s.seal()?);
        }

        Ok(sealed_shared_secrets)
    }

    pub fn derive_shared_secrets(
        my_sk: &SgxPrivateKey,
        other_pks: &[SgxProtectedKeyPub],
    ) -> SgxResult<Self> {
        let ecc_handle = SgxEccHandle::new();
        ecc_handle.open()?;

        let mut server_secrets = BTreeMap::new();

        for server_pk in other_pks.iter() {
            if !ecc_handle.check_point(&server_pk.into())? {
                error!("pk{} not on curve", server_pk);
                return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
            }
            let shared_secret =
                match ecc_handle.compute_shared_dhkey(&my_sk.into(), &server_pk.into()) {
                    Ok(ss) => ss,
                    Err(e) => {
                        error!(
                            "error compute_shared_dhkey: err={} sk={} pk={}",
                            e, my_sk, server_pk
                        );
                        return Err(e);
                    }
                };
            server_secrets.insert(
                server_pk.to_owned(),
                DiffieHellmanSharedSecret(shared_secret.s),
            );
        }

        Ok(SharedSecretsDb { db: server_secrets })
    }

    pub fn anytrust_group_id(&self) -> EntityId {
        warn!("this keys are taken from untrusted input. To fix this, seal the public keys too");
        let keys: Vec<SgxProtectedKeyPub> = self.db.keys().cloned().collect();
        compute_anytrust_group_id(&keys)
    }
}

/// A RoundSecret is an one-time pad for a given round derived from a set of
/// DiffieHellmanSharedSecret, one for each anytrust server.
pub type RoundSecret = DcRoundMessage;

use sgx_tcrypto::SgxEccHandle;
use std::fmt::Display;
use std::fmt::Result as FmtResult;

/// Derives a RoundSecret as the XOR of `HKDF(server_secrets[i], round)` for all `i` in `0`...`len(server_secrets)`
pub fn derive_round_secret(
    round: u32,
    server_secrets: &SharedSecretsDb,
) -> CryptoResult<RoundSecret> {
    // Fill this buffer with pseudorandom bytes
    let rand_bytes_needed = std::mem::size_of::<DcRoundMessage>();
    let mut round_secret_flatten = vec![0; rand_bytes_needed];

    for (_, server_secret) in server_secrets.db.iter() {
        let hk = Hkdf::<Sha256>::new(None, &server_secret.0);
        let mut round_secret_flatten_i = vec![0; rand_bytes_needed];

        // info contains round
        let mut info = [0; 32];
        LittleEndian::write_u32(&mut info, round);
        hk.expand(&info, &mut round_secret_flatten_i)?;

        for i in 0..round_secret_flatten.len() {
            round_secret_flatten[i] ^= round_secret_flatten_i[i];
        }
    }

    // drop mut
    let round_secret_flatten = round_secret_flatten;

    let mut round_secret = DcRoundMessage::default();
    let mut byte_read = 0;
    for i in 0..round_secret.scheduling_msg.len() {
        round_secret.scheduling_msg[i] = LittleEndian::read_u32(&round_secret_flatten[byte_read..]);
        byte_read += 4; // u32 is 4-byte
    }

    for i in 0..round_secret.aggregated_msg.len() {
        let l = round_secret.aggregated_msg[i].0.len();
        round_secret.aggregated_msg[i]
            .0
            .clone_from_slice(&round_secret_flatten[byte_read..byte_read + l]);
        byte_read += l;
    }

    // info!("derived secrets for round {} from {:?}. secret {:?}", round, server_secrets, round_secret);

    Ok(round_secret)
}

// various functions for computing a.xor(b)
pub trait Xor {
    // xor returns xor(self, other)
    fn xor(&self, other: &Self) -> Self;
    // xor_mut computes and sets self = xor(self, other)
    fn xor_mut(&mut self, other: &Self)
    where
        Self: Sized,
    {
        *self = self.xor(other);
    }
}

impl Xor for DcMessage {
    fn xor(&self, other: &Self) -> Self {
        let mut result = DcMessage::default();
        for i in 0..DC_NET_MESSAGE_LENGTH {
            result.0[i] = self.0[i] ^ other.0[i];
        }

        result
    }
}

impl Xor for DcRoundMessage {
    fn xor(&self, other: &Self) -> Self {
        let mut result = DcRoundMessage::default();

        for i in 0..result.scheduling_msg.len() {
            result.scheduling_msg[i] = self.scheduling_msg[i] ^ other.scheduling_msg[i];
        }

        for i in 0..result.aggregated_msg.len() {
            result.aggregated_msg[i].xor_mut(&other.aggregated_msg[i]);
        }

        result
    }
}
