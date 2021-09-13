use core::convert::TryFrom;
use crypto::{SgxPrivateKey, SharedSecretsDb};
use interface::*;
use sgx_rand::Rng;
use sgx_types::sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED};
use sgx_types::SgxResult;
use std::string::String;
use std::string::ToString;
use std::vec;
use std::vec::Vec;
use utils;
use utils::ser_and_seal_to_vec;

pub fn new_sgx_keypair_ext_internal(
    role: &str,
) -> SgxResult<(SgxPrivateKey, SgxProtectedKeyPub, SealedKey)> {
    let mut rand = sgx_rand::SgxRng::new().map_err(|e| {
        error!("cant create rand {}", e);
        SGX_ERROR_UNEXPECTED
    })?;
    // generate a random secret key
    let sk = rand.gen::<SgxPrivateKey>();
    // make sure sk is a valid private key by computing its public key
    let pk = SgxSigningPubKey::try_from(&sk)?;

    let attested_key = AttestedPublicKey {
        pk: pk,
        role: role.to_string(),
        tee_linkable_attestation: vec![],
    };

    Ok((
        sk,
        pk,
        SealedKey {
            sealed_sk: ser_and_seal_to_vec(&sk, "key".as_bytes())?,
            attested_pk: attested_key,
        },
    ))
}

pub fn unseal_to_pubkey_internal(sealed_sk: &SealedKey) -> SgxResult<SgxProtectedKeyPub> {
    let sk: SgxPrivateKey = utils::unseal_vec_and_deser(&sealed_sk.sealed_sk)?;
    SgxProtectedKeyPub::try_from(&sk)
}
