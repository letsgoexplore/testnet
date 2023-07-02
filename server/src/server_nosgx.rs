use std::{vec, vec::Vec};
use crate::util::{Result, ServerError};

use interface::{
    EntityId,
    UserRegistrationBlob,
    ServerPubKeyPackageNoSGX,
};

use ed25519_dalek::{
    SecretKey,
    PublicKey,
};
use rand::rngs::OsRng;
use sha2::Sha512;

use common::types_nosgx::{
    SharedSecretsDbServer,
    SignedPubKeyDbNoSGX,
    Sealed
};

use common::funcs_nosgx::{
    verify_user_attestation,
};

use log::{
    debug,
    error,
};


pub fn new_server() -> Result<(SecretKey, SecretKey, EntityId, ServerPubKeyPackageNoSGX)> {
    let mut csprng = OsRng::new()?;
    let sig_key = SecretKey::generate(&mut csprng);
    let kem_key = SecretKey::generate(&mut csprng);

    // The standard hash function used for most ed25519 libraries is SHA-512
    let sig_key_pk = PublicKey::from_secret::<Sha512>(&sig_key);
    let kem_key_pk = PublicKey::from_secret::<Sha512>(&kem_key);

    let reg = ServerPubKeyPackageNoSGX {
        sig: sig_key_pk,
        kem: kem_key_pk,
    };

    Ok((sig_key, kem_key, EntityId::from(&reg), reg))
}

pub fn recv_user_registration_batch(
    pubkeys: &mut SignedPubKeyDbNoSGX,
    shared_secrets: &mut SharedSecretsDbServer,
    decap_key: &SecretKey,
    input_blob: &[UserRegistrationBlob],
) -> Result<()> {
    let (new_pubkey_db, new_secrets_db) = recv_user_reg_batch(
        (pubkeys, decap_key, input_blob),
    )?;

    pubkeys.users = new_pubkey_db.users;
    shared_secrets.db = new_secrets_db.db;

    Ok(())
}

fn recv_user_reg_batch(
    input: (&SignedPubKeyDbNoSGX, &SecretKey, &Vec<UserRegistrationBlob>),
) -> Result<(SignedPubKeyDb, SharedSecretsDbServer)> {
    let mut pk_db: SignedPubKeyDbNoSGX = input.0.clone();
    let my_kem_sk = input.1;

    for u in input.2.iter() {
        // verify user key
        match verify_user_attestation(&u) {
            Ok(()) => {
                debug!("verify user registration attestation succeeded");
            },
            Err(e) => {
                error!("cannot verify user registration attestation: {:?}", e);
                return Err(ServerError::UnexpectedError);
            }
        }

        pk_db.users.insert(EntityId::from(&u.pk), u.clone());
    }

    // Derive secrets
    let mut others_kem_pks = vec![];
    for (_, k) in pk_db.users.iter() {
        others_kem_pks.push(k.pk);
    }

    // TODO: derive shared secrets

}