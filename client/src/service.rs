use crate::{
    util::{save_state, UserError},
    UserState,
};
use common::{cli_util, enclave::DcNetEnclave};
use interface::{DcMessage, RoundOutputUpdated, UserSubmissionBlobUpdated, UserMsg, DC_NET_MESSAGE_LENGTH};

use core::ops::DerefMut;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use actix_web::{
    client::Client,
    http::{StatusCode, Uri},
    post, rt as actix_rt, web, App, HttpResponse, HttpServer, ResponseError,
};
use log::{debug, error, info};
use thiserror::Error;

#[derive(Debug, Error)]
enum ApiError {
    #[error("internal error")]
    Internal(#[from] UserError),
    #[error("base64 encoding error")]
    Encoding(#[from] base64::DecodeError),
    #[error("error in serialization/deserialization")]
    Ser(#[from] cli_util::SerializationError),
    #[error("malformed input")]
    Malformed(String),
}
impl ResponseError for ApiError {}

#[derive(Clone)]
pub(crate) struct ServiceState {
    pub(crate) user_state: UserState,
    pub(crate) enclave: DcNetEnclave,
    pub(crate) agg_url: String,
    pub(crate) round: u32,
    /// The path to this users's state file. If `None`, state is not persisted to disk
    pub(crate) user_state_path: Option<String>,
}

/// Receives previous round output and new message to encrypt. These are newline-separated
/// base64-encoded CBOR
#[post("/encrypt-msg")]
async fn encrypt_msg(
    (payload, state): (String, web::Data<Arc<Mutex<ServiceState>>>),
) -> Result<HttpResponse, ApiError> {
    let start = Instant::now();

    // Unpack state
    let mut handle = state.get_ref().lock().unwrap();
    let ServiceState {
        ref mut user_state,
        ref enclave,
        ref agg_url,
        round,
        ref user_state_path,
        ..
    } = handle.deref_mut();

    // debug!("payload: {:?}", payload);
    // The payload is msg COMMA prev_rount_output
    let mut payload_it = payload.split(',');

    // debug!("payload_it: {:?}", payload_it);

    // Load the message first. It's just a base64 string of length <= DC_NET_MESSAGE_LENGTH
    let dc_msg: DcMessage = {
        // Decode the message from the first comma-separated component of the input
        let msg_bytes = base64::decode(
            &payload_it
                .next()
                .unwrap() // The first element of a split is always defined
                .trim()
                .as_bytes(),
        )
        .map_err(cli_util::SerializationError::from)?;

        // Check the length
        if msg_bytes.len() > DC_NET_MESSAGE_LENGTH {
            return Err(ApiError::Malformed(format!(
                "input message must be less than {} bytes long",
                DC_NET_MESSAGE_LENGTH
            )));
        }

        debug!("msg_bytes: {:?}", msg_bytes);

        // Copy into a DC net buffer
        let mut buf = DcMessage::default();
        buf.0[..msg_bytes.len()].copy_from_slice(&msg_bytes);
        buf
    };

    // debug!("dc_msg: {:?}", dc_msg.0);

    let encoded_round_output = payload_it.next();
    let prev_round_output: RoundOutputUpdated = match encoded_round_output {
        Some(s) => cli_util::load(s.trim().as_bytes())?,
        None => RoundOutputUpdated::default(),
    };

    // debug!("prev_round_output: {:?}", prev_round_output);

    let msg = UserMsg::TalkAndReserveUpdated {
        msg: dc_msg,
        prev_round_output,
        times_participated: user_state.get_times_participated(),
    };

    debug!("msg before submit: {:?}", msg);

    // Encrypt the message and send it

    let start_submit = Instant::now();
    let ciphertext = user_state.submit_round_msg(&enclave, *round, msg)?;
    let duration_submit = start_submit.elapsed();
    debug!("[client] submit_round_msg: {:?}", duration_submit);


    debug!("round: {}", ciphertext.round);
    debug!("scheduling_msg.len(): {}", ciphertext.aggregated_msg.scheduling_msg.len());
    debug!("aggregated_msg.len(): {} * {}", ciphertext.aggregated_msg.aggregated_msg.num_rows(), ciphertext.aggregated_msg.aggregated_msg.num_columns());

    send_ciphertext(&ciphertext, agg_url).await;

    // Increment the round and save the user state
    *round += 1;
    user_state_path.as_ref().map(|path| {
        info!("Saving state");
        match save_state(path, user_state) {
            Err(e) => error!("failed to save user state {:?}", e),
            _ => (),
        }
    });

    let duration = start.elapsed();
    debug!("[client] encrypt-msg: {:?}", duration);

    Ok(HttpResponse::Ok().body("OK\n"))
}

/// Reserves a talking slot for the next round
#[post("/reserve-slot")]
async fn reserve_slot(
    state: web::Data<Arc<Mutex<ServiceState>>>,
) -> Result<HttpResponse, ApiError> {
    // Unpack state
    let mut handle = state.get_ref().lock().unwrap();
    let ServiceState {
        ref mut user_state,
        ref enclave,
        ref agg_url,
        round,
        ref user_state_path,
        ..
    } = handle.deref_mut();

    // Encrypt a reservation and send it
    let msg = UserMsg::Reserve {
        times_participated: user_state.get_times_participated(),
    };
    let ciphertext = user_state.submit_round_msg(&enclave, *round, msg)?;
    send_ciphertext(&ciphertext, agg_url).await;

    // Increment the round and save the user state
    *round += 1;
    user_state_path.as_ref().map(|path| {
        info!("Saving state");
        match save_state(path, user_state) {
            Err(e) => error!("failed to save user state {:?}", e),
            _ => (),
        }
    });

    Ok(HttpResponse::Ok().body("OK\n"))
}

/// Sends cover traffic
#[post("/send-cover")]
async fn send_cover(state: web::Data<Arc<Mutex<ServiceState>>>) -> Result<HttpResponse, ApiError> {
    // Unpack state
    let mut handle = state.get_ref().lock().unwrap();
    let ServiceState {
        ref mut user_state,
        ref enclave,
        ref agg_url,
        round,
        ref user_state_path,
        ..
    } = handle.deref_mut();

    // Encrypt an empty message and send it
    let ciphertext = user_state.submit_round_msg(&enclave, *round, UserMsg::Cover)?;
    send_ciphertext(&ciphertext, agg_url).await;
    debug!("send success!");
    // Increment the round and save the user state
    *round += 1;
    user_state_path.as_ref().map(|path| {
        info!("Saving state");
        match save_state(path, user_state) {
            Err(e) => error!("failed to save user state {:?}", e),
            _ => (),
        }
    });

    Ok(HttpResponse::Ok().body("OK\n"))
}

/// Sends a ciphertext to base_url/submit-agg
async fn send_ciphertext(ciphertext: &UserSubmissionBlobUpdated, base_url: &str) {
    let start = Instant::now();

    // Serialize the ciphertext
    let mut body = Vec::new();
    cli_util::save(&mut body, ciphertext).expect("could not serialize ciphertext");

    // Send the serialized contents
    debug!("Making client");
    let client = Client::builder().timeout(Duration::from_secs(5)).finish();
    let post_path: Uri = [base_url, "/submit-agg"].concat().parse().expect(&format!(
        "Couldn't not append '/submit-agg' to forward URL {}",
        base_url
    ));

    debug!("post_path: {:?}", post_path);
    debug!("body.len(): {:?}", body.len());

    debug!("Sending");

    match client.post(post_path).send_body(body).await {
        Ok(res) => {
            if res.status() == StatusCode::OK {
                info!("Successfully sent ciphertext")
            } else {
                error!("Could not send ciphertext1: {:?}", res)
            }
        }
        Err(e) => error!("Could not send ciphertext2: {:?}", e),
    }

    let duration = start.elapsed();
    debug!("[client] send_ciphertext: {:?}", duration);
}

#[actix_rt::main]
pub(crate) async fn start_service(bind_addr: String, state: ServiceState) -> std::io::Result<()> {
    let state = Arc::new(Mutex::new(state));

    // Start the web server
    HttpServer::new(move || {
        App::new().data(state.clone()).configure(|cfg| {
            cfg.service(encrypt_msg);
            cfg.service(reserve_slot);
            cfg.service(send_cover);
        })
    })
    .workers(1)
    .bind(bind_addr)
    .expect("could not bind")
    .run()
    .await
}
