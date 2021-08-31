use crate::user_state::UserState;

use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use clap::ArgMatches;
use common::{cli_util, enclave_wrapper::EnclaveError};
use serde::Serialize;
use thiserror::Error;

pub(crate) type Result<T> = core::result::Result<T, UserError>;

#[derive(Debug, Error)]
pub enum UserError {
    #[error("error from enclave")]
    Enclave(#[from] EnclaveError),
    #[error("error from IO")]
    Io(#[from] std::io::Error),
    #[error("error in serialization/deserialization")]
    Ser(#[from] cli_util::SerializationError),
}

pub(crate) fn load_state(matches: &ArgMatches) -> Result<UserState> {
    let save_filename = matches.value_of("user-state").unwrap();
    let save_file = File::open(save_filename)?;
    Ok(cli_util::load(save_file)?)
}

pub(crate) fn save_state(matches: &ArgMatches, state: &UserState) -> Result<()> {
    let save_filename = matches.value_of("user-state").unwrap();
    let save_file = File::create(save_filename)?;
    Ok(cli_util::save(save_file, state)?)
}

pub(crate) fn save_to_stdout<S: Serialize>(val: &S) -> Result<()> {
    let stdout = std::io::stdout();
    cli_util::save(stdout, val)?;
    println!("");
    Ok(())
}

/// Loads raw base64 from STDIN, ignoring trailing newlines
pub(crate) fn base64_from_stdin() -> Result<Vec<u8>> {
    let mut stdin = std::io::stdin();
    let f = BufReader::new(&mut stdin);
    let line = f.lines().next().expect("got no base64 input")?;
    let bytes = base64::decode(&line).map_err(cli_util::SerializationError::from)?;

    Ok(bytes)
}
