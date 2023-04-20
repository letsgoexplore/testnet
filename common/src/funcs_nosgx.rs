use interface::EntityId;
use ed25519_dalek::{PublicKey, PUBLIC_KEY_LENGTH};

extern crate sha2;
use sha2::{Digest, Sha256};

pub fn pk_to_entityid(pk: &PublicKey) -> EntityId {
    let pk_bytes: [u8; PUBLIC_KEY_LENGTH] = pk.to_bytes();
    let mut hasher = Sha256::new();
    hasher.input("anytrust_group_id");
    hasher.input(pk_bytes);

    let digest = hasher.result();

    let mut id = EntityId::default();
    id.0.copy_from_slice(&digest);
    id
}