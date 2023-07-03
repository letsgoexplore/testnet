use interface::{
    EntityId,
    UserSubmissionMessage,
    UserRegistrationBlob,
};
use ed25519_dalek::{
    PublicKey,
    PUBLIC_KEY_LENGTH,
};

extern crate sha2;
use sha2::{Digest, Sha256};

pub fn verify_user_submission_msg(_incoming_msg: &UserSubmissionMessage) -> Result<(), ()> {
    Ok(())
}

pub fn verify_user_attestation(_reg_blob: &UserRegistrationBlob) -> Result<(), ()> {
    Ok(())
}