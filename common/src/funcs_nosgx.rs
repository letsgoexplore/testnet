use std::collections::BTreeSet;
use std::vec::Vec;
use interface::{
    EntityId,
    UserRegistrationBlobNew,
    RoundSecret,
    DcRoundMessage,
    UserSubmissionMessageUpdated,
};

extern crate sha2;
use sha2::Sha256;
use rand_core::SeedableRng;
use byteorder::{ByteOrder, LittleEndian};
use hkdf::{Hkdf, InvalidLength};

use crate::aes_prng::Aes128Rng;
use crate::types_nosgx::{SharedSecretsDbServer, XorNoSGX};

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_cbor;

use log::debug;


pub fn verify_user_submission_msg(_incoming_msg: &UserSubmissionMessageUpdated) -> Result<(), ()> {
    // TODO: Move SignableUpdated trait to interface, include it
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
                debug!("entity id of client {} is not in entity_ids_to_use", pk);
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


pub fn serialize_to_vec<T: Serialize>(v: &T) -> Result<Vec<u8>, serde_cbor::Error> {
    serde_cbor::to_vec(v).map_err(|e| {
        println!("can't serialize to vec {}", e);
        e
    })
}

pub fn deserialize_from_vec<T: DeserializeOwned>(bin: &[u8]) -> Result<T, serde_cbor::Error> {
    serde_cbor::from_slice::<T>(bin).map_err(|e| {
        println!("can't deserialize from vec {}", e);
        e
    })
}