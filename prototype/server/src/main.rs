extern crate common;
extern crate interface;

mod server_state;
use server_state::ServerState;

use common::{cli_util, enclave_wrapper::DcNetEnclave};
use interface::KemPubKey;

use std::{
    error::Error,
    fs::File,
    sync::{Arc, Mutex},
};

use clap::{App, AppSettings, Arg, SubCommand};

fn main() -> Result<(), Box<dyn Error>> {
    // Do setup
    let enclave = DcNetEnclave::init("/sgxdcnet/lib/enclave.signed.so")?;

    let matches = App::new("SGX DCNet Anytrust Node")
        .version("0.1.0")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("get-kem-pubkey")
                .about("Outputs this server's KEM pubkey")
                .arg(
                    Arg::with_name("server-state")
                        .short("s")
                        .long("server-state")
                        .value_name("FILE")
                        .required(true)
                        .takes_value(true)
                        .help("A file that contains this server's previous state"),
                ),
        )
        .subcommand(SubCommand::with_name("new").about("Generates a new server state"))
        .get_matches();

    if let Some(_) = matches.subcommand_matches("new") {
        // Make a new state and print it out
        let state = ServerState::new(&enclave)?.0;
        let stdout = std::io::stdout();
        let mut stdout = File::create("state.txt")?;
        cli_util::save(stdout, &state)?;

        return Ok(());
    }
    if let Some(matches) = matches.subcommand_matches("get-kem-pubkey") {
        // Load state
        let save_filename = matches.value_of("server-state").unwrap();
        let save_file = File::open(save_filename)?;
        let state: ServerState = cli_util::load(save_file)?;

        // Get KEM pubkey and print it
        let kem_pubkey = &state.decap_key.0.attested_pk.pk;
        let stdout = std::io::stdout();
        cli_util::save(stdout, kem_pubkey)?;

        return Ok(());
    }

    enclave.destroy();
    Ok(())
}
