use interface::*;
use sgx_types::{SgxResult};
use std::vec::Vec;
use utils::{ser_and_seal_to_vec};
use sgx_rand::Rng;
use std::string::ToString;
use core::convert::TryFrom;
use crypto::{SgxPrivateKey, SharedSecretsWithAnyTrustGroup};
use sgx_types::sgx_status_t::SGX_ERROR_UNEXPECTED;
use std::string::String;
use utils;

fn new_sgx_keypair_ext_internal(
    role: &str,
) -> SgxResult<(SgxPrivateKey, SgxProtectedKeyPub, SealedKey)> {
    let mut rand = sgx_rand::SgxRng::new().map_err(|e| {
        println!("cant create rand {}", e);
        SGX_ERROR_UNEXPECTED
    })?;
    // generate a random secret key
    let sk = rand.gen::<SgxPrivateKey>();

    // make sure sk is a valid private key by computing its public key
    let pk = SgxSigningPubKey::try_from(&sk)?;

    let tee_linkable_attestation = vec![];
    Ok((
        sk,
        pk,
        SealedKey {
            sealed_sk: ser_and_seal_to_vec(&sk, "key".as_bytes())?,
            pk,
            role: role.to_string(),
            tee_linkable_attestation,
        },
    ))
}

pub fn new_sgx_keypair_internal(role: &String) -> SgxResult<SealedKey> {
    Ok(new_sgx_keypair_ext_internal(&role)?.2)
}

pub fn unseal_to_pubkey_internal(sealed_sk: &SealedKey) -> SgxResult<SgxProtectedKeyPub> {
    let sk = utils::unseal_vec_and_deser::<SgxPrivateKey>(&sealed_sk.sealed_sk)?;
    SgxProtectedKeyPub::try_from(&sk)
}

/// Derives shared secrets with all the given KEM pubkeys, and derives a new signing pubkey.
/// Returns sealed secrets, a sealed private key, and a registration message to send to an
/// anytrust node
pub fn register_user_internal(anytrust_server_pks: &Vec<KemPubKey>) -> SgxResult<UserRegistration> {
    // 1. generate a SGX protected key. used for both signing and round key derivation
    let (sk, pk, sealed_key) = new_sgx_keypair_ext_internal("user")?;

    // 2. derive server secrets
    let server_secrets =
        SharedSecretsWithAnyTrustGroup::derive_server_secrets(&sk, anytrust_server_pks)?;

    Ok(UserRegistration::new(
        sealed_key,
        SealedServerSecrets {
            user_id: EntityId::from(&pk),
            anytrust_group_id: server_secrets.anytrust_group_id(),
            server_public_keys: server_secrets
                .anytrust_group_pairwise_keys
                .keys()
                .cloned()
                .collect(),
            sealed_server_secrets: ser_and_seal_to_vec(
                &server_secrets,
                "shared secrets".as_bytes(),
            )?,
        },
    ))
}
