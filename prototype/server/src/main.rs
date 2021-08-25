extern crate common;
extern crate interface;

mod server_state;
use server_state::ServerState;

use common::{cli_util, enclave_wrapper::DcNetEnclave};
use interface::{AggRegistrationBlob, KemPubKey, RoundSubmissionBlob, UserRegistrationBlob};

use std::{
    error::Error,
    fs::File,
    sync::{Arc, Mutex},
};

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use serde::{Deserialize, Serialize};

fn load_state(matches: &ArgMatches) -> Result<ServerState, Box<dyn Error>> {
    let save_filename = matches.value_of("server-state").unwrap();
    let save_file = File::open(save_filename)?;
    cli_util::load(save_file)
}

fn save_state(matches: &ArgMatches, state: &ServerState) -> Result<(), Box<dyn Error>> {
    let save_filename = matches.value_of("server-state").unwrap();
    let save_file = File::create(save_filename)?;
    cli_util::save(save_file, state)
}

fn load_from_stdin<D: for<'a> Deserialize<'a>>() -> Result<D, Box<dyn Error>> {
    let stdin = std::io::stdin();
    cli_util::load(stdin)
}

fn save_to_stdout<S: Serialize>(val: &S) -> Result<(), Box<dyn Error>> {
    let stdout = std::io::stdout();
    cli_util::save(stdout, val)
}

fn main() -> Result<(), Box<dyn Error>> {
    // Do setup
    let enclave = DcNetEnclave::init("/sgxdcnet/lib/enclave.signed.so")?;

    let state_arg = Arg::with_name("server-state")
        .short("s")
        .long("server-state")
        .value_name("FILE")
        .required(true)
        .takes_value(true)
        .help("A file that contains this server's previous state");

    let matches = App::new("SGX DCNet Anytrust Node")
        .version("0.1.0")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("new").about("Generates a new server state"))
        .subcommand(
            SubCommand::with_name("get-kem-pubkey")
                .about("Outputs this server's KEM pubkey")
                .arg(state_arg.clone()),
        )
        .subcommand(
            SubCommand::with_name("register-user")
                .about("Registers a user with this server")
                .arg(state_arg.clone()),
        )
        .subcommand(
            SubCommand::with_name("unblind-aggregate")
                .about("Unblinds the given top-level aggregate value")
                .arg(state_arg.clone()),
        )
        .get_matches();

    if let Some(_) = matches.subcommand_matches("new") {
        // Make a new state and print it out
        let state = ServerState::new(&enclave)?.0;
        save_to_stdout(&state)?;
    }

    if let Some(matches) = matches.subcommand_matches("get-kem-pubkey") {
        // Get the stat'es KEM pubkey and print it
        let state = load_state(&matches)?;
        let kem_pubkey = &state.decap_key.0.attested_pk.pk;
        save_to_stdout(kem_pubkey)?;
    }

    if let Some(matches) = matches.subcommand_matches("register-user") {
        // Parse a user registration blob from stdin
        let reg_blob: UserRegistrationBlob = load_from_stdin()?;

        // Feed it to the state and save the new state
        let mut state = load_state(&matches)?;
        state.recv_user_registration(&enclave, &reg_blob)?;
        save_state(&matches, &state)?;

        println!("OK");
    }

    if let Some(matches) = matches.subcommand_matches("register-agg") {
        // Parse an aggregator registration blob from stdin
        let reg_blob: AggRegistrationBlob = load_from_stdin()?;

        // Feed it to the state and save the new state
        let mut state = load_state(&matches)?;
        state.recv_aggregator_registration(&enclave, &reg_blob)?;
        save_state(&matches, &state)?;

        println!("OK");
    }

    if let Some(matches) = matches.subcommand_matches("unblind-agg") {
        // Parse an aggregation blob from stdin
        let agg_blob: RoundSubmissionBlob = load_from_stdin()?;

        // Feed it to the state and print the result
        let mut state = load_state(&matches)?;
        let agg = state.unblind_aggregate(&enclave, &agg_blob)?;
        save_to_stdout(&agg)?;
    }

    enclave.destroy();
    Ok(())
}
