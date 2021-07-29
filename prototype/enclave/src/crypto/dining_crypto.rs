use interface::*;

use std::prelude::v1::*;

use byteorder::{ByteOrder, LittleEndian};
use hkdf::Hkdf;
use sha2::Sha256;

use super::*;
use sgx_types::sgx_ec256_dh_shared_t;
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};

/// A SharedServerSecret is the long-term secret shared between an anytrust server and this use enclave
#[derive(Copy, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
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

/// A ServerSecrets consists of an array of shared secrets established between a user and with a
/// group of any-trust server
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SharedSecretsWithAnyTrustGroup {
    pub user_id: EntityId,
    pub anytrust_group_pairwise_keys: BTreeMap<SgxProtectedKeyPub, SharedServerSecret>,
}

use std::convert::TryFrom;

impl SharedSecretsWithAnyTrustGroup {
    pub fn derive_server_secrets(
        my_sk: &SgxPrivateKey,
        server_pks: &[SgxProtectedKeyPub],
    ) -> SgxResult<Self> {
        let ecc_handle = SgxEccHandle::new();
        ecc_handle.open()?;

        let mut server_secrets = BTreeMap::new();

        for server_pk in server_pks.iter() {
            let shared_secret =
                ecc_handle.compute_shared_dhkey(&my_sk.into(), &server_pk.into())?;
            server_secrets.insert(
                server_pk.to_owned(),
                SharedServerSecret {
                    secret: shared_secret.s,
                    server_id: EntityId::from(server_pk),
                },
            );
        }

        let my_pk = SgxProtectedKeyPub::try_from(my_sk)?;

        Ok(SharedSecretsWithAnyTrustGroup {
            user_id: EntityId::from(&my_pk),
            anytrust_group_pairwise_keys: server_secrets,
        })
    }

    pub fn anytrust_group_id(&self) -> EntityId {
        let keys: Vec<SgxProtectedKeyPub> =
            self.anytrust_group_pairwise_keys.keys().cloned().collect();
        compute_anytrust_group_id(&keys)
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
    server_secrets: &SharedSecretsWithAnyTrustGroup,
) -> CryptoResult<RoundSecret> {
    let mut round_secret = [0; DC_NET_MESSAGE_LENGTH];

    for (_, server_secret) in server_secrets.anytrust_group_pairwise_keys.iter() {
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
