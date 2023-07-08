use std::collections::BTreeSet;
use interface::{
    EntityId,
    UserSubmissionMessage,
    UserRegistrationBlobNew,
    RoundSecret,
    DcRoundMessage,
};
use ed25519_dalek::{
    PublicKey,
    PUBLIC_KEY_LENGTH,
};

extern crate sha2;
use sha2::{Digest, Sha256};
use rand::SeedableRng;
use byteorder::{ByteOrder, LittleEndian};
use hkdf::{Hkdf, InvalidLength};

use crate::aes_prng::Aes128Rng;
use crate::types_nosgx::{SharedSecretsDbServer, XorNoSGX};


pub fn verify_user_submission_msg(_incoming_msg: &UserSubmissionMessage) -> Result<(), ()> {
    Ok(())
}

pub fn verify_user_attestation(_reg_blob: &UserRegistrationBlobNew) -> Result<(), ()> {
    Ok(())
}

pub fn derive_round_secret_server(
    round: u32,
    shared_secrets: &SharedSecretsDbServer,
    entity_ids_to_use: Option<&BTreeSet<EntityId>>,
) -> Result<RoundSecret, InvalidLength> {
    type MyRng = Aes128Rng;

    let mut round_secret = RoundSecret::default();

    for (pk, shared_secret) in shared_secrets.db.iter() {
        // skip entries not in entity_ids_to_use
        if let Some(eids) = entity_ids_to_use {
            if !eids.contains(&EntityId::from(pk)) {
                continue;
            }
        }

        let hk = Hkdf::<Sha256>::new(None, &shared_secret.as_ref());
        // For cryptographic RNG's a seed of 256 bits is recommended, [u8; 32].
        let mut seed = <MyRng as SeedableRng>::Seed::default();

        // info contains round and window
        let mut info = [0; 32];
        let cursor = &mut info;
        LittleEndian::write_u32(cursor, round);
        hk.expand(&info, &mut seed)?;

        let mut rng = MyRng::from_seed(seed);
        round_secret.xor_mut_nosgx(&DcRoundMessage::rand_from_csprng(&mut rng));
    }

    Ok(round_secret)
}