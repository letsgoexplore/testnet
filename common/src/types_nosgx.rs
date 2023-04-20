use ed25519_dalek::PublicKey;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Debug, Deserialize)]
pub struct AggRegistrationBlobNoSGX {
    pub pk: PublicKey,
    pub role: std::string::String,
}