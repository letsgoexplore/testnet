use crate::agg_state::AggregatorState;

use std::{fs::File, io};

use clap::ArgMatches;
use common::{cli_util, enclave_wrapper::EnclaveError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub(crate) type Result<T> = core::result::Result<T, AggregatorError>;

#[derive(Debug, Error)]
pub enum AggregatorError {
    #[error("aggregator has not been initialized")]
    Uninitialized,
    #[error("error from enclave")]
    Enclave(#[from] EnclaveError),
    #[error("error from IO")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cli(#[from] Box<dyn std::error::Error>),
}

pub(crate) fn load_state(matches: &ArgMatches) -> Result<AggregatorState> {
    let save_filename = matches.value_of("agg-state").unwrap();
    let save_file = File::open(save_filename)?;
    Ok(cli_util::load(save_file)?)
}

pub(crate) fn save_state(matches: &ArgMatches, state: &AggregatorState) -> Result<()> {
    let save_filename = matches.value_of("agg-state").unwrap();
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
