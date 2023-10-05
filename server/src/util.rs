use crate::server_state::ServerState;
use interface::RoundOutput;

use common::cli_util;

use std::fs::File;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use ed25519_dalek::SignatureError;
use std::convert::From;

pub(crate) type Result<T> = core::result::Result<T, ServerError>;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("error from IO")]
    Io(#[from] std::io::Error),
    #[error("error in serialization/deserialization")]
    Ser(#[from] cli_util::SerializationError),
    #[error("Unexpected Error")]
    UnexpectedError,
}

impl From<SignatureError> for ServerError {
    fn from(_error: SignatureError) -> Self {
        ServerError::UnexpectedError
    }
}

impl From<rand::Error> for ServerError {
    fn from(_error: rand::Error) -> Self {
        ServerError::UnexpectedError
    }
}

pub(crate) fn load_state(save_path: &str) -> Result<ServerState> {
    let save_file = File::open(save_path)?;
    Ok(cli_util::load(save_file)?)
}

pub(crate) fn save_state(save_path: &str, state: &ServerState) -> Result<()> {
    let save_file = File::create(save_path)?;
    Ok(cli_util::save(save_file, state)?)
}

pub(crate) fn save_output(save_path: &str, output: &RoundOutput) -> Result<()> {
    let save_file = File::create(save_path)?;
    Ok(cli_util::save(save_file, output)?)
}

pub(crate) fn load_from_stdin<D: for<'a> Deserialize<'a>>() -> Result<D> {
    let stdin = std::io::stdin();
    Ok(cli_util::load(stdin)?)
}

pub(crate) fn load_multi_from_stdin<D: for<'a> Deserialize<'a>>() -> Result<Vec<D>> {
    let stdin = std::io::stdin();
    Ok(cli_util::load_multi(stdin)?)
}

pub(crate) fn save_to_stdout<S: Serialize>(val: &S) -> Result<()> {
    let stdout = std::io::stdout();
    cli_util::save(stdout, val)?;
    println!("");
    Ok(())
}
