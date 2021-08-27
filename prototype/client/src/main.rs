extern crate common;
extern crate interface;

mod user_state;
use crate::user_state::UserState;

use common::{cli_util, enclave_wrapper::DcNetEnclave};
use interface::{DcMessage, SealedFootprintTicket, DC_NET_MESSAGE_LENGTH};

use std::{
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
};

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use serde::Serialize;

fn load_state(matches: &ArgMatches) -> Result<UserState, Box<dyn Error>> {
    let save_filename = matches.value_of("user-state").unwrap();
    let save_file = File::open(save_filename)?;
    cli_util::load(save_file)
}

fn save_state(matches: &ArgMatches, state: &UserState) -> Result<(), Box<dyn Error>> {
    let save_filename = matches.value_of("user-state").unwrap();
    let save_file = File::create(save_filename)?;
    cli_util::save(save_file, state)
}

fn save_to_stdout<S: Serialize>(val: &S) -> Result<(), Box<dyn Error>> {
    let stdout = std::io::stdout();
    cli_util::save(stdout, val)?;
    println!("");
    Ok(())
}

/// Loads raw base64 from STDIN, ignoring trailing newlines
pub fn base64_from_stdin() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut stdin = std::io::stdin();
    let f = BufReader::new(&mut stdin);
    let line = f.lines().next().expect("got no base64 input")?;
    let bytes = base64::decode(&line)?;

    Ok(bytes)
}

fn main() -> Result<(), Box<dyn Error>> {
    // Do setup
    let enclave = DcNetEnclave::init("/sgxdcnet/lib/enclave.signed.so")?;

    let state_arg = Arg::with_name("user-state")
        .short("s")
        .long("user-state")
        .value_name("FILE")
        .required(true)
        .takes_value(true)
        .help("A file that contains this user's previous state");

    let matches = App::new("SGX DCNet Client")
        .version("0.1.0")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("new")
                .about("Generates a new client state")
                .arg(
                    Arg::with_name("user-state")
                        .short("s")
                        .long("user-state")
                        .value_name("OUTFILE")
                        .required(true)
                        .takes_value(true)
                        .help("The file to which the new user state will be written"),
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
            SubCommand::with_name("encrypt-msg")
                .about(format!(
                    "Encrypts a round message to the DC net. STDIN is a base64-encoded bytestring \
                    of length at most {}",
                    DC_NET_MESSAGE_LENGTH
                ).as_str())
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
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("new") {
        // Load up the KEM keys
        let pubkeys_filename = matches.value_of("server-keys").unwrap();
        let keysfile = File::open(pubkeys_filename)?;
        let kem_pubkeys = cli_util::load_multi(keysfile)?;

        // Make a new state and user registration. Save the state and and print the registration
        let (state, reg_blob) = UserState::new(&enclave, kem_pubkeys)?;
        save_state(&matches, &state)?;
        save_to_stdout(&reg_blob)?;
    }

    if let Some(matches) = matches.subcommand_matches("encrypt-msg") {
        // Load the message
        let msg = base64_from_stdin()?;
        assert!(
            msg.len() < DC_NET_MESSAGE_LENGTH,
            format!(
                "input message must be less than {} bytes long",
                DC_NET_MESSAGE_LENGTH
            )
        );

        // Pad out the message and put it in the correct wrapper
        let mut dc_msg = DcMessage::default();
        dc_msg.0[..msg.len()].copy_from_slice(&msg);

        // Load the round
        let round_str = matches.value_of("round").unwrap();
        let round = u32::from_str_radix(&round_str, 10)?;

        // Input the footprint ticket
        // TODO: Acutally do this
        let ticket = SealedFootprintTicket(Vec::new());

        // Now encrypt the message and output it
        let state = load_state(&matches)?;
        let ciphertext = state.submit_round_msg(&enclave, round, &dc_msg, &ticket)?;
        save_to_stdout(&ciphertext)?;
    }

    enclave.destroy();
    Ok(())
}
