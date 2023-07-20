extern crate common;
extern crate interface;

mod server_state;
mod service;
mod util;
mod server_nosgx;

use crate::{
    server_state::ServerState,
    service::start_service,
    util::{load_from_stdin, load_multi_from_stdin, load_state, save_state, save_to_stdout},
};

use common::cli_util;
use interface::UserRegistrationBlobNew;

use common::types_nosgx::{
    RoundSubmissionBlobNoSGX,
    UnblindedAggregateShareBlobNoSGX,
    ServerRegistrationBlobNoSGX,
    AggRegistrationBlobNoSGX,
};

use std::{error::Error, fs::File};

use clap::{App, AppSettings, Arg, SubCommand};
use log::info;

fn main() -> Result<(), Box<dyn Error>> {
    // Do setup
    env_logger::init();

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
        .subcommand(
            SubCommand::with_name("new")
                .about(
                    "Generates a new server state and outputs a registration message for other \
                    anytrust servers",
                )
                .arg(
                    Arg::with_name("server-state")
                        .short("s")
                        .long("server-state")
                        .value_name("OUTFILE")
                        .required(true)
                        .takes_value(true)
                        .help("The file to which the new server state will be written"),
                ),
        )
        .subcommand(
            SubCommand::with_name("get-pubkeys")
                .about("Outputs this server's pubkey package")
                .arg(state_arg.clone()),
        )
        .subcommand(
            SubCommand::with_name("register-user")
                .about(
                    "Registers a user with this server. STDIN is newline-separated user \
                    registration blobs",
                )
                .arg(state_arg.clone()),
        )
        .subcommand(
            SubCommand::with_name("register-aggregator")
                .about("Registers an aggregator with this server")
                .arg(state_arg.clone()),
        )
        .subcommand(
            SubCommand::with_name("register-server")
                .about("Registers another server with this server")
                .arg(state_arg.clone()),
        )
        .subcommand(
            SubCommand::with_name("unblind-aggregate")
                .about("Unblinds the given top-level aggregate value")
                .arg(state_arg.clone()),
        )
        .subcommand(
            SubCommand::with_name("combine-shares")
                .about("Combines the given unblinded shares from each server")
                .arg(state_arg.clone())
                .arg(
                    Arg::with_name("shares")
                        .short("a")
                        .long("shares")
                        .value_name("INFILE")
                        .required(true)
                        .takes_value(true)
                        .help(
                            "A file containing newline-delimited unblinded shares from every \
                            anytrust server",
                        ),
                ),
        )
        .subcommand(
            SubCommand::with_name("start-service")
                .about(
                    "Starts a web service at BIND_ADDR. After TIMEOUT seconds, sends the\
                    aggregate to the aggregator or server at FORWARD_ADDR.",
                )
                .arg(state_arg.clone())
                .arg(
                    Arg::with_name("bind")
                        .short("b")
                        .long("bind")
                        .value_name("BIND_ADDR")
                        .required(true)
                        .help("The local address to bind the service to. Example: localhost:9000"),
                )
                .arg(
                    Arg::with_name("leader-url")
                        .short("l")
                        .long("leader-url")
                        .value_name("LEADER_ADDR")
                        .required(false)
                        .help(
                            "The URL of the leader of this anytrust group. Example: \
                            http://192.168.0.10:9000 . If this node is the leader, this flag is \
                            omitted.",
                        ),
                )
                .arg(
                    Arg::with_name("no-persist")
                        .short("n")
                        .long("no-persist")
                        .required(false)
                        .takes_value(false)
                        .help("If this is set, the service will not persist its state to disk"),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("new") {
        // Make a new state and registration message
        let (state, reg_blob) = ServerState::new()?;
        // Save the state and output the registration blob
        let state_path = matches.value_of("server-state").unwrap();
        save_state(&state_path, &state)?;
        save_to_stdout(&reg_blob)?;
    }

    if let Some(matches) = matches.subcommand_matches("get-pubkeys") {
        // Get the server's pubkey package and print it
        let state_path = matches.value_of("server-state").unwrap();
        let state = load_state(&state_path)?;
        save_to_stdout(&state.pubkey_pkg)?;
    }

    if let Some(matches) = matches.subcommand_matches("register-user") {
        // Parse user registration blobs from stdin
        let reg_blobs: Vec<UserRegistrationBlobNew> = load_multi_from_stdin()?;

        // Feed them to the state and save the new state
        let state_path = matches.value_of("server-state").unwrap();
        let mut state = load_state(&state_path)?;
        state.recv_user_registrations(&reg_blobs)?;

        save_state(&state_path, &state)?;

        println!("OK");
    }

    if let Some(matches) = matches.subcommand_matches("register-aggregator") {
        // Parse an aggregator registration blob from stdin
        let reg_blob: AggRegistrationBlobNoSGX = load_from_stdin()?;

        // Feed it to the state and save the new state
        let state_path = matches.value_of("server-state").unwrap();
        let mut state = load_state(&state_path)?;
        state.recv_aggregator_registration(&reg_blob)?;
        save_state(&state_path, &state)?;

        println!("OK");
    }

    if let Some(matches) = matches.subcommand_matches("register-server") {
        // Parse an aggregator registration blob from stdin
        let reg_blob: ServerRegistrationBlobNoSGX = load_from_stdin()?;

        // Feed it to the state and save the new state
        let state_path = matches.value_of("server-state").unwrap();
        let mut state = load_state(&state_path)?;
        state.recv_server_registration(&reg_blob)?;
        save_state(&state_path, &state)?;

        println!("OK");
    }

    if let Some(matches) = matches.subcommand_matches("unblind-aggregate") {
        // Load the aggregation blob
        let agg_blob: RoundSubmissionBlobNoSGX = load_from_stdin()?;

        // Feed it to the state and print the result
        let state_path = matches.value_of("server-state").unwrap();
        let mut state = load_state(&state_path)?;
        let agg = state.unblind_aggregate(&agg_blob)?;
        save_to_stdout(&agg)?;

        // The shared secrets were ratcheted, so we have to save the new state
        save_state(&state_path, &state)?;
    }

    if let Some(matches) = matches.subcommand_matches("combine-shares") {
        // Parse each server's unblinded inputs
        let shares_filename = matches.value_of("shares").unwrap();
        let sharefile = File::open(shares_filename)?;
        let shares: Vec<UnblindedAggregateShareBlobNoSGX> = cli_util::load_multi(sharefile)?;

        // Feed it to the state and output the result
        let state_path = matches.value_of("server-state").unwrap();
        let state = load_state(&state_path)?;
        let round_output = state.derive_round_output(shares.as_slice())?;
        save_to_stdout(&round_output)?;

        // Log the raw round result in base64
        let round = round_output.round;
        let round_msg = &round_output.dc_msg.aggregated_msg.as_row_major();
        // info!("round {} output: {}", round, base64::encode(round_msg));
        info!("round {} output: {:?}", round, round_msg);
    }

    if let Some(matches) = matches.subcommand_matches("start-service") {
        // Load the args
        let bind_addr = matches.value_of("bind").unwrap().to_string();
        let leader_url = matches.value_of("leader-url").map(|s| s.to_string());

        // Check that the forward-to URL is well-formed
        leader_url.as_ref().map(|u| {
            u.parse::<actix_web::http::Uri>()
                .expect("the leader-url parameter must be a URL");
        });

        // Load the aggregator state and clear it for this round
        let state_path = matches.value_of("server-state").unwrap().to_string();
        let server_state = load_state(&state_path)?;
        info!(
            "Loaded server state. Group size is {}",
            server_state.anytrust_group_size
        );

        // If no-persist is set, then the state path is None
        let server_state_path = if matches.is_present("no-persist") {
            None
        } else {
            Some(state_path)
        };

        let state = service::ServiceState::new(
            server_state,
            server_state_path,
            leader_url,
        );
        start_service(bind_addr, state).unwrap();
    }

    Ok(())
}
