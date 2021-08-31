use crate::server_state::ServerState;

use common::{cli_util, enclave_wrapper::EnclaveError};

use std::fs::File;

use clap::ArgMatches;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub(crate) type Result<T> = core::result::Result<T, ServerError>;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("error from enclave")]
    Enclave(#[from] EnclaveError),
    #[error("error from IO")]
    Io(#[from] std::io::Error),
    #[error("error in serialization/deserialization")]
    Ser(#[from] cli_util::SerializationError),
}

pub(crate) fn load_state(matches: &ArgMatches) -> Result<ServerState> {
    let save_filename = matches.value_of("server-state").unwrap();
    let save_file = File::open(save_filename)?;
    Ok(cli_util::load(save_file)?)
}

pub(crate) fn save_state(matches: &ArgMatches, state: &ServerState) -> Result<()> {
    let save_filename = matches.value_of("server-state").unwrap();
    let save_file = File::create(save_filename)?;
    Ok(cli_util::save(save_file, state)?)
}

pub(crate) fn load_from_stdin<D: for<'a> Deserialize<'a>>() -> Result<D> {
    let stdin = std::io::stdin();
    Ok(cli_util::load(stdin)?)
}

pub(crate) fn save_to_stdout<S: Serialize>(val: &S) -> Result<()> {
    let stdout = std::io::stdout();
    cli_util::save(stdout, val)?;
    println!("");
    Ok(())
}
