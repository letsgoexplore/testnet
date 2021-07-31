use std::collections::BTreeMap;
use interface::*;
use sgx_types::SgxResult;
use crate::crypto::{AttestedPublicKey, Signable, SignMutable, SgxPrivateKey};
use crate::utils;
use sgx_types::sgx_status_t::SGX_ERROR_INVALID_PARAMETER;

/// This file implements ecalls used by an anytrust server

#[derive(Clone, Serialize, Deserialize)]
pub struct SignedPubKeyDb {
    pub db: BTreeMap<EntityId, KemPubKey>
}

impl Signable for SignedPubKeyDb {
    fn digest(&self) -> std::vec::Vec<u8> {
        todo!()
    }

    fn get_sig(&self) -> crate::crypto::SgxSignature {
        todo!()
    }

    fn get_pk(&self) -> SgxSigningPubKey {
        todo!()
    }
}

impl SignMutable for SignedPubKeyDb {
    fn sign_mut(&mut self, _: &crate::crypto::SgxSigningKey) -> sgx_types::SgxError {
        todo!()
    }
}


/// Verifies and adds the given user registration blob to the database of pubkeys and
/// shared secrets
/// Called by a server
pub fn recv_user_registration(input: &(SignedPubKeyDbBlob, SealedSharedSecretDb, SealedKemPrivKey, UserRegistrationBlob))
-> SgxResult<(SignedPubKeyDbBlob, SealedSharedSecretDb)> {
    let (pk_db, shared_secret_db, my_kem_sk, user_pk) = input;

    // verify user key
    let attested_pk: AttestedPublicKey = utils::unseal_vec_and_deser(&user_pk.0)?;
    warn!("skipping attestation verificatio for now");

    // add user key to pubkey db
    let pk_db : SignedPubKeyDb = utils::unseal_vec_and_deser(&pk_db.0)?;
    // verify existing sig
    if ! pk_db.verify()?  {
        return Err(SGX_ERROR_INVALID_PARAMETER);
    }
    // insert new key
    let mut pk_db_new = pk_db.clone();
    pk_db_new.db.insert(EntityId::from(&attested_pk.pk), attested_pk.pk);
    // unseal signing key
    // XXX: should we pass a separate signing key??
    let sig_sk: SgxPrivateKey = utils::unseal_vec_and_deser(&my_kem_sk.0.sealed_sk)?;
    // update sig
    pk_db_new.sign_mut(&sig_sk)?;

    // TODO: derive secrets
    

    unimplemented!()
}