extern crate common;
extern crate interface;

mod user_state;
mod util;

use crate::{
    user_state::UserState,
    util::{base64_from_stdin, load_state, save_state, save_to_stdout, UserError},
};

use common::{cli_util, enclave_wrapper::DcNetEnclave};
use interface::{DcMessage, RoundOutput, ServerPubKeyPackage, UserMsg, DC_NET_MESSAGE_LENGTH};
use std::fs::File;

use clap::{App, AppSettings, Arg, SubCommand};

fn main() -> Result<(), UserError> {
    // Do setup
    env_logger::init();
    let enclave = DcNetEnclave::init("/sgxdcnet/lib/enclave.signed.so")?;

    let state_arg = Arg::with_name("user-state")
        .short("s")
        .long("user-state")
        .value_name("FILE")
        .required(true)
        .takes_value(true)
        .help("A file that contains this user's previous state");

    let times_talked_arg = Arg::with_name("times-talked")
        .short("t")
        .long("times-talked")
        .required(true)
        .takes_value(true)
        .help("The number of times this user has sent a message or reserved a slot during this window");

    let round_arg = Arg::with_name("round")
        .short("r")
        .long("round")
        .value_name("INTEGER")
        .required(true)
        .takes_value(true)
        .help("The current round number of the DC net");

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
                        "A file that contains newline-delimited pubkey packages of the servers \
                        that this user wishes to register with"
                    )
                )
        )
        .subcommand(
            SubCommand::with_name("reserve-slot")
                .about("Reserves a message slot for the next round")
                .arg(state_arg.clone())
                .arg(round_arg.clone())
                .arg(times_talked_arg.clone())
        )
        .subcommand(
            SubCommand::with_name("send-empty")
                .about("Sends the empty message as cover traffic for the system")
                .arg(state_arg.clone())
                .arg(round_arg.clone())
        )
        .subcommand(
            SubCommand::with_name("encrypt-msg")
                .about(format!(
                    "Encrypts a round message to the DC net. STDIN is a base64-encoded bytestring \
                    of length at most {}",
                    DC_NET_MESSAGE_LENGTH
                ).as_str())
                .arg(state_arg.clone())
                .arg(round_arg.clone())
                .arg(times_talked_arg.clone())
                .arg(
                    Arg::with_name("prev-round-output")
                    .short("p")
                    .long("prev-round-output")
                    .value_name("INFILE")
                    .required(true)
                    .help("A file that contains the output of the previous round")
                )
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("new") {
        // Load up the KEM keys
        let pubkeys_filename = matches.value_of("server-keys").unwrap();
        let keysfile = File::open(pubkeys_filename)?;
        let pubkeys: Vec<ServerPubKeyPackage> = cli_util::load_multi(keysfile)?;

        // Make a new state and user registration. Save the state and and print the registration
        let (state, reg_blob) = UserState::new(&enclave, pubkeys)?;
        save_state(&matches, &state)?;
        save_to_stdout(&reg_blob)?;
    }

    // Send cover traffic
    if let Some(matches) = matches.subcommand_matches("send-empty") {
        // Make a cover traffic message
        let msg = UserMsg::Cover;

        // Load the round
        let round = cli_util::parse_u32(matches.value_of("round").unwrap())?;

        // Now encrypt the message and output it
        let mut state = load_state(&matches)?;
        let ciphertext = state.submit_round_msg(&enclave, round, msg)?;
        save_to_stdout(&ciphertext)?;

        // The shared secrets were ratcheted, so we have to save the new state
        save_state(&matches, &state)?;
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
        let round = cli_util::parse_u32(matches.value_of("round").unwrap())?;
        let times_talked = cli_util::parse_u32(matches.value_of("times-talked").unwrap())?;

        // Load the previous round output. Load a placeholder output if this is the first round of
        // the first window
        let prev_round_output: RoundOutput = if round > 0 {
            let round_output_filename = matches.value_of("prev-round-output").unwrap();
            let round_file = File::open(round_output_filename)?;
            cli_util::load(round_file)?
        } else {
            RoundOutput::default()
        };

        let msg = UserMsg::TalkAndReserve {
            msg: dc_msg,
            prev_round_output,
            times_talked,
        };

        // Now encrypt the message and output it
        let mut state = load_state(&matches)?;
        let ciphertext = state.submit_round_msg(&enclave, round, msg)?;
        save_to_stdout(&ciphertext)?;

        // The shared secrets were ratcheted, so we have to save the new state
        save_state(&matches, &state)?;
    }

    if let Some(matches) = matches.subcommand_matches("reserve-slot") {
        // Load the round
        let round = cli_util::parse_u32(matches.value_of("round").unwrap())?;
        let times_talked = cli_util::parse_u32(matches.value_of("times-talked").unwrap())?;

        let msg = UserMsg::Reserve { times_talked };

        // Compute the reservation
        let mut state = load_state(&matches)?;
        let ciphertext = state.submit_round_msg(&enclave, round, msg)?;
        save_to_stdout(&ciphertext)?;
    }

    enclave.destroy();
    Ok(())
}
