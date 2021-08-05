use interface::*;
use sgx_types::sgx_status_t;

use std::prelude::v1::*;

use byteorder::{ByteOrder, LittleEndian};
use hkdf::Hkdf;
use sha2::Sha256;
use types::Sealable;
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
#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct SharedSecretsDb {
    pub db: BTreeMap<SgxProtectedKeyPub, DiffieHellmanSharedSecret>,
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

        let my_pk = SgxProtectedKeyPub::try_from(my_sk)?;

        Ok(SharedSecretsDb { db: server_secrets })
    }

    pub fn anytrust_group_id(&self) -> EntityId {
        let keys: Vec<SgxProtectedKeyPub> = self.db.keys().cloned().collect();
        compute_anytrust_group_id(&keys)
    }
}

/// A RoundSecret is an one-time pad for a given round derived from a set of
/// DiffieHellmanSharedSecret, one for each anytrust server.
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

impl Into<DcMessage> for RoundSecret {
    fn into(self) -> DcMessage {
        DcMessage(self.secret)
    }
}

/// Derives a RoundSecret as the XOR of `HKDF(server_secrets[i], round)` for all `i` in `0`...`len(server_secrets)`
pub fn derive_round_secret(
    round: u32,
    server_secrets: &SharedSecretsDb,
) -> CryptoResult<RoundSecret> {
    let mut round_secret = [0; DC_NET_MESSAGE_LENGTH];

    for (_, server_secret) in server_secrets.db.iter() {
        let hk = Hkdf::<Sha256>::new(None, &server_secret.0);
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
