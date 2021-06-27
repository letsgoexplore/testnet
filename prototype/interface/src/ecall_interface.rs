use std::string::String;
use crate::{SealedKey};
use std::vec::Vec;

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcallNewSgxKeypairInput {
    pub role: String,
}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcallNewSgxKeypairOutput {
    pub sk: SealedKey,
}