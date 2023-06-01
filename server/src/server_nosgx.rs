use crate::util::Result;

use interface::{
    EntityId,
};

use ed25519_dalek::{
    SecretKey,
    PublicKey,
};
use rand::rngs::OsRng;
use sha2::Sha512;

use common::types_nosgx::{
    ServerPubKeyPackageNoSGX,
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