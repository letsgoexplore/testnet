extern crate common;
extern crate interface;

mod agg_state;
mod service;
mod util;
mod agg_nosgx;

pub use crate::util::AggregatorError;
use crate::{
    agg_state::AggregatorState,
    service::start_service,
    util::{load_from_stdin, load_state, save_state, save_to_stdout, split_data_collection},
};

use common::cli_util;
use common::types_nosgx::{AggregatedMessage, SubmissionMessage};
use interface::{ServerPubKeyPackageNoSGX, UserSubmissionMessageUpdated};
use std::{fs::File, time::SystemTime};

use clap::{App, AppSettings, Arg, SubCommand};
use log::info;

fn main() -> Result<(), AggregatorError> {
    env_logger::init();

    // Do setup
    let state_arg = Arg::with_name("agg-state")
        .short("s")
        .long("agg-state")
        .value_name("FILE")
        .required(true)
        .takes_value(true)
        .help("A file that contains this aggregator's previous state");

    let round_arg = Arg::with_name("round")
        .short("r")
        .long("round")
        .value_name("INTEGER")
        .required(true)
        .takes_value(true)
        .help("The current round number within this window of the DC net");

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
                    Arg::with_name("level")
                        .short("l")
                        .long("level")
                        .required(true)
                        .takes_value(true)
                        .value_name("LEVEL")
                        .help(
                            "Indicates the level in the aggregation tree of this aggregator. 0 \
                            means this is a leaf aggregator.",
                        ),
                )
                .arg(
                    Arg::with_name("agg-number")
                        .short("a")
                        .long("agg-number")
                        .required(true)
                        .takes_value(true)
                        .value_name("LEVEL")
                        .help(
                            "[onlyevaluation] This is for aggregator knowing which file to save or read the msg.",
                        ),
                )
                .arg(
                    Arg::with_name("server-keys")
                        .short("k")
                        .long("server-keys")
                        .value_name("INFILE")
                        .required(true)
                        .help(
                            "A file that contains newline-delimited pubkey packages of the \
                            servers that this user wishes to register with",
                        ),
                ),
        )
        .subcommand(
            SubCommand::with_name("start-round")
                .about("Starts a fresh aggregate for the given round number")
                .arg(state_arg.clone())
                .arg(round_arg.clone()),
        )
        .subcommand(
            SubCommand::with_name("input-agg")
                .about("Adds the given aggregator round submission blob from STDIN to the aggregate")
                .arg(state_arg.clone()),
        )
        .subcommand(
            SubCommand::with_name("input-user")
                .about("Adds the given user round submission blob from STDIN to the aggregate")
                .arg(state_arg.clone()),
        )
        .subcommand(
            SubCommand::with_name("finalize")
                .about("Finalizes the current round and outputs the aggregate to the console")
                .arg(state_arg.clone()),
        )
        .subcommand(
            SubCommand::with_name("start-service")
                .about(
                    "Starts a web service at BIND_ADDR. After TIMEOUT seconds, sends the\
                    aggregate to the aggregator or server at FORWARD_ADDR.",
                )
                .arg(state_arg.clone())
                .arg(round_arg.clone())
                .arg(
                    Arg::with_name("bind")
                        .short("b")
                        .long("bind")
                        .value_name("BIND_ADDR")
                        .required(true)
                        .help("The local address to bind the service to. Example: localhost:9000"),
                )
                .arg(
                    Arg::with_name("forward-to")
                        .short("f")
                        .long("forward-to")
                        .value_name("FORWARD_ADDRS")
                        .required(true)
                        .help(
                            "A comma-separated list URLs of the next-level servers or aggregators \
                            in the aggregation tree. Example: \
                            \"http://192.168.0.10:9000,http://192.168.0.11:3030\"",
                        ),
                )
                .arg(
                    Arg::with_name("round-duration")
                        .short("d")
                        .long("round-duration")
                        .value_name("DURATION")
                        .required(true)
                        .help("The duration of a single DC net round, in seconds"),
                )
                .arg(
                    Arg::with_name("start-time")
                        .short("t")
                        .long("start-time")
                        .value_name("TIME")
                        .required(true)
                        .help(
                            "The time the specified round will start, in seconds since Unix epoch",
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
        .subcommand(
            SubCommand::with_name("split-dataset")
                .about("[single2multi] This is to seperate the single dataset to multiple small datasets, for multi-thread purpose")
                .arg(
                    Arg::with_name("user-number")
                        .short("u")
                        .long("user-number")
                        .value_name("USERNUM")
                        .required(true)
                        .takes_value(true)
                        .help("user number in the dataset"),
                )
                .arg(
                    Arg::with_name("thread-number")
                        .short("m")
                        .long("thread-number")
                        .value_name("THREADNUM")
                        .required(true)
                        .takes_value(true)
                        .help("how many piece to seperate into"),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("new") {
        // Load up the pubkeys
        let pubkeys_filename = matches.value_of("server-keys").unwrap();
        let keysfile = File::open(pubkeys_filename)?;
        let pubkeys: Vec<ServerPubKeyPackageNoSGX> = cli_util::load_multi(keysfile)?;

        let level = cli_util::parse_u32(matches.value_of("level").unwrap())?;
        let agg_number = cli_util::parse_u32(matches.value_of("agg-number").unwrap())?;

        // Make a new state and agg registration. Save the state and and print the registration
        let (state, reg_blob) = AggregatorState::new(pubkeys, level, agg_number)?;
        let state_path = matches.value_of("agg-state").unwrap();
        save_state(&state_path, &state)?;
        save_to_stdout(&reg_blob)?;
    }

    if let Some(matches) = matches.subcommand_matches("start-round") {
        // Load the round
        let round = cli_util::parse_u32(matches.value_of("round").unwrap())?;

        // Now update the state and save it
        let state_path = matches.value_of("agg-state").unwrap();
        let mut state = load_state(&state_path)?;
        state.clear(round)?;
        save_state(&state_path, &state)?;

        println!("OK");
    }

    if let Some(matches) = matches.subcommand_matches("input-agg") {
        // Load the STDIN input and load the state
        let round_blob: AggregatedMessage = load_from_stdin()?;
        let state_path = matches.value_of("agg-state").unwrap();
        let mut state = load_state(&state_path)?;

        // Pass the input to the state and save the result
        let round_blob = SubmissionMessage::AggSubmission(round_blob);
        state.add_to_aggregate(&round_blob)?;
        save_state(&state_path, &state)?;

        println!("OK");
    }

    if let Some(matches) = matches.subcommand_matches("input-user") {
        // Load the STDIN input and load the state
        let round_blob: UserSubmissionMessageUpdated = load_from_stdin()?;
        let state_path = matches.value_of("agg-state").unwrap();
        let mut state = load_state(&state_path)?;

        // Pass the input to the state and save the result
        let round_blob = SubmissionMessage::UserSubmission(round_blob);
        state.add_to_aggregate(&round_blob)?;
        save_state(&state_path, &state)?;

        println!("OK");
    }

    if let Some(matches) = matches.subcommand_matches("finalize") {
        // Load the state
        let state_path = matches.value_of("agg-state").unwrap();
        let state = load_state(&state_path)?;

        // Pass the input to the state and print the result
        let agg_blob = state.finalize_aggregate()?;
        save_to_stdout(&agg_blob)?;
    }

    if let Some(matches) = matches.subcommand_matches("start-service") {
        // Load the args
        env_logger::init();
        let bind_addr = matches.value_of("bind").unwrap().to_string();
        let round = cli_util::parse_u32(matches.value_of("round").unwrap())?;
        let round_dur = {
            let secs = cli_util::parse_u32(matches.value_of("round-duration").unwrap())?;
            std::time::Duration::from_secs(secs as u64)
        };
        // Compute the start time as an std::Instant. This is kinda roundabout because we're
        // converting a system time to a monotonic time. This doesn't handle clock changes.
        let start_time = {
            let secs_since_epoch = std::time::Duration::from_secs(cli_util::parse_u64(
                matches.value_of("start-time").unwrap(),
            )?);
            SystemTime::UNIX_EPOCH + secs_since_epoch
        };
        let forward_urls: Vec<String> = matches
            .value_of("forward-to")
            .unwrap()
            .split(",")
            .map(String::from)
            .collect();
        // Check that the forward-to URLs are well-formed
        for url in forward_urls.iter() {
            info!("url:{}",url);
            let _: actix_web::http::Uri =
                url.parse().expect(&format!("{} is not a valid URL", url));
        }

        // Load the aggregator state and clear it for this round
        let state_path = matches.value_of("agg-state").unwrap().to_string();
        let mut agg_state = load_state(&state_path)?;
        agg_state.clear(round)?;
        info!("Initialized round {}", round);

        // If no-persist is set, then the state path is None
        let agg_state_path = if matches.is_present("no-persist") {
            None
        } else {
            Some(state_path)
        };

        let level = agg_state.level;
        let state = service::ServiceState::new(
            agg_state,
            forward_urls,
            round,
            agg_state_path,
        );
        start_service(bind_addr, state, round_dur, start_time, level).unwrap();
    }

    if let Some(matches) = matches.subcommand_matches("split-dataset") {
        // Load the parameter
        let user_num = cli_util::parse_u32(matches.value_of("user-number").unwrap())?;
        let thread_num = cli_util::parse_u32(matches.value_of("thread-number").unwrap())?;

        // split the dataset
        split_data_collection(user_num, thread_num);
        
    }

    Ok(())
}
