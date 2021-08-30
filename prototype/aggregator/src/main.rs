extern crate common;
extern crate interface;

mod agg_state;
mod util;

pub use crate::util::AggregatorError;
use crate::{
    agg_state::AggregatorState,
    util::{load_from_stdin, load_state, save_state, save_to_stdout},
};

use common::{cli_util, enclave_wrapper::DcNetEnclave};
use interface::RoundSubmissionBlob;
use std::fs::File;

use clap::{App, AppSettings, Arg, SubCommand};

fn main() -> Result<(), AggregatorError> {
    // Do setup
    let enclave = DcNetEnclave::init("/sgxdcnet/lib/enclave.signed.so")?;

    let state_arg = Arg::with_name("agg-state")
        .short("s")
        .long("agg-state")
        .value_name("FILE")
        .required(true)
        .takes_value(true)
        .help("A file that contains this aggregator's previous state");

    let matches = App::new("SGX DCNet Client")
        .version("0.1.0")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("new")
                .about("Generates a new client state")
                .arg(
                    Arg::with_name("agg-state")
                        .short("s")
                        .long("agg-state")
                        .value_name("OUTFILE")
                        .required(true)
                        .takes_value(true)
                        .help("The file to which the new aggregator state will be written"),
                )
                .arg(
                    Arg::with_name("server-keys")
                    .short("k")
                    .long("server-keys")
                    .value_name("INFILE")
                    .required(true)
                    .help(
                        "A file that contains newline-delimited KEM pubkeys of the servers that \
                        this user wishes to register with"
                    )
                )
        )
        .subcommand(
            SubCommand::with_name("start-round")
                .about("Starts a fresh aggregate for the given round number")
                .arg(state_arg.clone())
                .arg(
                    Arg::with_name("round")
                    .short("r")
                    .long("round")
                    .value_name("INTEGER")
                    .required(true)
                    .takes_value(true)
                    .help("The current round number of the DC net")
                )
        )
        .subcommand(
            SubCommand::with_name("input")
                .about("Adds the given round submission blob from STDIN to the aggregate")
                .arg(state_arg.clone())
        )
        .subcommand(
            SubCommand::with_name("finalize")
                .about("Finalizes the current round and outputs the aggregate to the console")
                .arg(state_arg.clone())
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("new") {
        // Load up the KEM keys
        let pubkeys_filename = matches.value_of("server-keys").unwrap();
        let keysfile = File::open(pubkeys_filename)?;
        let kem_pubkeys = cli_util::load_multi(keysfile)?;

        // Make a new state and agg registration. Save the state and and print the registration
        let (state, reg_blob) = AggregatorState::new(&enclave, kem_pubkeys)?;
        save_state(&matches, &state)?;
        save_to_stdout(&reg_blob)?;
    }

    if let Some(matches) = matches.subcommand_matches("start-round") {
        // Load the round
        let round_str = matches.value_of("round").unwrap();
        let round = u32::from_str_radix(&round_str, 10).map_err(|e| {
            let e: Box<dyn std::error::Error> = Box::new(e);
            e
        })?;

        // Now update the state and save it
        let mut state = load_state(&matches)?;
        state.clear(&enclave, round)?;
        save_state(&matches, &state)?;

        println!("OK");
    }

    if let Some(matches) = matches.subcommand_matches("input") {
        // Load the STDIN input and load the state
        let round_blob: RoundSubmissionBlob = load_from_stdin()?;
        let mut state = load_state(&matches)?;

        // Pass the input to the state and save the result
        state.add_to_aggregate(&enclave, &round_blob)?;
        save_state(&matches, &state)?;

        println!("OK");
    }

    if let Some(matches) = matches.subcommand_matches("finalize") {
        // Load the state
        let state = load_state(&matches)?;

        // Pass the input to the state and print the result
        let agg_blob = state.finalize_aggregate(&enclave)?;
        save_to_stdout(&agg_blob)?;
    }

    Ok(())
}
