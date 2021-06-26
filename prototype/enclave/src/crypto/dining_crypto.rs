use interface::*;

use std::prelude::v1::*;

use byteorder::{ByteOrder, LittleEndian};
use hkdf::Hkdf;
use sha2::Sha256;

use super::*;
use sgx_types::sgx_ec256_dh_shared_t;
use std::fmt::{Debug, Formatter};
use types::{Xor, Zero};

/// A SharedServerSecret is the long-term secret shared between an anytrust server and this use enclave
#[serde(crate = "serde")]
#[derive(Copy, Clone, Default, Serialize, Deserialize)]
pub struct SharedServerSecret {
    secret: [u8; SGX_ECP256_KEY_SIZE],
    server_id: EntityId,
}

impl From<sgx_ec256_dh_shared_t> for SharedServerSecret {
    fn from(s: sgx_ec256_dh_shared_t) -> Self {
        Self {
            secret: s.s,
            server_id: Default::default(),
        }
    }
}

impl Debug for SharedServerSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PK")
            .field("secret", &hex::encode(&self.secret))
            .field("server_id", &hex::encode(&self.server_id))
            .finish()
    }
}

impl SharedServerSecret {
    pub fn gen_test(byte: u8) -> Self {
        SharedServerSecret {
            secret: [byte; SGX_ECP256_KEY_SIZE],
            server_id: Default::default(),
        }
    }

    pub fn derive_shared_server_secret(
        my_sk: &SgxProtectedKeyPrivate,
        server_pk: &SgxProtectedKeyPub,
    ) -> SgxResult<SharedServerSecret> {
        let ecc_handle = SgxEccHandle::new();
        ecc_handle.open()?;

        let shared_secret = ecc_handle.compute_shared_dhkey(&my_sk.into(), &server_pk.into())?;
        Ok(SharedServerSecret {
            secret: shared_secret.s,
            server_id: EntityId::from(server_pk),
        })
    }
}

/// A `RoundSecret` is the one-time pad for a particular round derived from a specific set of
/// SharedServerSecrets, one for each servers invovled. The set of servers is identified
/// by `dcnet_id` which is the hash of canonically ordered server public keys.
pub struct RoundSecret {
    secret: [u8; DC_NET_MESSAGE_LENGTH],
    anytrust_group_id: EntityId, // a hash of all server public keys
}

impl RoundSecret {
    pub fn encrypt(&self, msg: &DcMessage) -> DcMessage {
        let mut output = [0; DC_NET_MESSAGE_LENGTH];

        for i in 0..DC_NET_MESSAGE_LENGTH {
            output[i] = self.secret[i] ^ msg.0[i];
        }

        DcMessage(output)
    }
}

use sgx_tcrypto::SgxEccHandle;
use std::fmt::Display;
use std::fmt::Result as FmtResult;

impl Display for RoundSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("RoundSecret")
            .field("secret", &hex::encode(&self.secret))
            .field("anytrust_group_id", &self.anytrust_group_id)
            .finish()
    }
}

/// Derives a RoundSecret as the XOR of `HKDF(server_secrets[i], round)` for all `i` in `0`...`len(server_secrets)`
pub fn derive_round_secret(
    round: u32,
    server_secrets: &Vec<SharedServerSecret>,
) -> CryptoResult<RoundSecret> {
    let mut round_secret = [0; DC_NET_MESSAGE_LENGTH];

    for server_secret in server_secrets.iter() {
        let hk = Hkdf::<Sha256>::new(None, &server_secret.secret);
        let mut derived_secret = [0; DC_NET_MESSAGE_LENGTH];

        // info contains round
        let mut info = [0; 32];
        LittleEndian::write_u32(&mut info, round);
        hk.expand(&info, &mut derived_secret)?;

        for i in 0..DC_NET_MESSAGE_LENGTH {
            round_secret[i] = round_secret[i] ^ derived_secret[i];
        }
    }

    Ok(RoundSecret {
        secret: round_secret,
        anytrust_group_id: Default::default(),
    })
}
