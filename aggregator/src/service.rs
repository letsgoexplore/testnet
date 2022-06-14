use crate::{
    util::{save_state, AggregatorError},
    AggregatorState,
};
use common::{cli_util, ecall_wrapper::DcNetEnclave};
use interface::RoundSubmissionBlob;

use core::ops::DerefMut;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use actix_rt::{
    spawn,
    time::{delay_until, Instant},
    Arbiter,
};
use actix_web::{
    client::Client,
    get,
    http::{StatusCode, Uri},
    post, rt as actix_rt, web, App, HttpResponse, HttpServer, ResponseError,
};
use futures::future::FutureExt;
use log::{error, info};
use thiserror::Error;

// We take 5 seconds at the end of every round for the aggregates to propagate up the tree
const PROPAGATION_SECS: u64 = 5;

#[derive(Debug, Error)]
enum ApiError {
    #[error("internal error")]
    Internal(#[from] AggregatorError),
    #[error("base64 encoding error")]
    Encoding(#[from] base64::DecodeError),
    #[error("error in serialization/deserialization")]
    Ser(#[from] cli_util::SerializationError),
}
impl ResponseError for ApiError {}

#[derive(Clone)]
pub(crate) struct ServiceState {
    pub(crate) agg_state: AggregatorState,
    pub(crate) enclave: DcNetEnclave,
    /// The URLs of the next aggregators
    pub(crate) forward_urls: Vec<String>,
    pub(crate) round: u32,
    /// The path to this aggregator's state file. If `None`, state is not persisted to disk
    pub(crate) agg_state_path: Option<String>,
}

/// Receives a partial aggregate from an aggregator or a user
#[post("/submit-agg")]
async fn submit_agg(
    (payload, state): (String, web::Data<Arc<Mutex<ServiceState>>>),
) -> Result<HttpResponse, ApiError> {
    // Strip whitespace from the payload
    let payload = payload.split_whitespace().next().unwrap_or("");
    // Parse aggregation
    let agg_data: RoundSubmissionBlob = cli_util::load(&mut payload.as_bytes())?;

    // Unpack state
    let mut handle = state.get_ref().lock().unwrap();
    let ServiceState {
        ref mut agg_state,
        ref enclave,
        ..
    } = handle.deref_mut();
    // Add to aggregate
    agg_state.add_to_aggregate(enclave, &agg_data)?;

    Ok(HttpResponse::Ok().body("OK\n"))
}

/// Forces the current round to end. Only for debugging purposes
#[get("/force-round-end")]
async fn force_round_end(
    state: web::Data<Arc<Mutex<ServiceState>>>,
) -> Result<HttpResponse, ApiError> {
    let state = state.get_ref();

    // End the round. Serialize the aggregate and forward it in the background. Time out
    // after 1 second
    let send_timeout = Duration::from_secs(1);
    let (agg_payload, forward_urls) = get_agg_payload(&*state);
    spawn(
        actix_rt::time::timeout(send_timeout, send_aggregate(agg_payload, forward_urls)).map(|r| {
            if r.is_err() {
                error!("timeout for sending aggregation was hit");
            }
        }),
    );

    // Start the next round immediately
    start_next_round(state.clone());

    Ok(HttpResponse::Ok().body("OK\n"))
}

/// Finalizes and serializes the current aggregator state. Returns the pyaload nad all the
/// forwarding URLs
fn get_agg_payload(state: &Mutex<ServiceState>) -> (Vec<u8>, Vec<String>) {
    let handle = state.lock().unwrap();
    let ServiceState {
        ref agg_state,
        ref enclave,
        ref forward_urls,
        ..
    } = *handle;

    // Finalize and serialize the aggregate
    let agg = agg_state
        .finalize_aggregate(enclave)
        .expect("could not finalize aggregate");
    let mut payload = Vec::new();
    cli_util::save(&mut payload, &agg).expect("could not serialize aggregate");

    (payload, forward_urls.clone())
}

/// Sends a finalized aggregate to base_url/submit-agg for all base_url in forward_urls
async fn send_aggregate(payload: Vec<u8>, forward_urls: Vec<String>) {
    info!("Forwarding aggregate to {:?}", forward_urls);
    for base_url in forward_urls {
        // Send the serialized contents
        let client = Client::builder().finish();
        let post_path: Uri = [&base_url, "/submit-agg"].concat().parse().expect(&format!(
            "Couldn't not append '/submit-agg' to forward URL {}",
            base_url
        ));
        match client.post(post_path).send_body(payload.clone()).await {
            Ok(res) => {
                if res.status() == StatusCode::OK {
                    info!("Successfully sent finalize aggregate")
                } else {
                    error!("Could not send finalized aggregate: {:?}", res)
                }
            }
            Err(e) => error!("Could not send finalized aggregate: {:?}", e),
        }
    }
}

// Saves the state and start the next round
fn start_next_round(state: Arc<Mutex<ServiceState>>) {
    let mut handle = state.lock().unwrap();
    let ServiceState {
        ref mut agg_state,
        ref enclave,
        ref mut round,
        ref agg_state_path,
        ..
    } = *handle;

    info!("round {} complete", round);
    // Save the state if a path is specified
    agg_state_path.as_ref().map(|path| {
        info!("Saving state");
        match save_state(path, agg_state) {
            Err(e) => error!("failed to save agg state {:?}", e),
            _ => (),
        }
    });

    // Increment the round and clear the state
    *round += 1;
    agg_state
        .clear(&enclave, *round)
        .expect("could not start new round");
}

// This converts future system time to a monotonic instant. Doing this has weird edge cases in
// practice and we don't deal with them for now
fn systime_to_instant(time: SystemTime) -> Instant {
    let now_inst = std::time::Instant::now();
    let now_sys = SystemTime::now();
    let delta = time
        .duration_since(now_sys)
        .expect("expected next instant to be in the future");
    Instant::from_std(now_inst + delta)
}

/// Every `round_dur`, ends the round and forwards the finalized aggregate to the next aggregator
/// or anytrust server up the tree
async fn round_finalization_loop(
    state: Arc<Mutex<ServiceState>>,
    round_dur: Duration,
    mut start_time: SystemTime,
    level: u32,
) {
    let one_sec = Duration::from_secs(1);
    let send_timeout = one_sec;
    let propagation_dur = Duration::from_secs(PROPAGATION_SECS);

    // Wait until the start time, then start the round loop
    delay_until(systime_to_instant(start_time)).await;
    loop {
        // We send our aggregate `level` seconds after the official end of the round
        let end_time = start_time + round_dur + level * one_sec;

        // Wait
        delay_until(systime_to_instant(end_time)).await;

        // The round has ended. Serialize the aggregate and forward it in the background. Time out
        // after 1 second
        let (agg_payload, forward_urls) = get_agg_payload(&state);
        spawn(
            actix_rt::time::timeout(send_timeout, send_aggregate(agg_payload, forward_urls)).map(
                |r| {
                    if r.is_err() {
                        error!("timeout for sending aggregation was hit");
                    }
                },
            ),
        );

        // Start the next round early
        start_next_round(state.clone());

        // The official round start time is right after propagation terminates. We update this so
        // that end_time is calculated correctly.
        start_time = start_time + round_dur + propagation_dur;
    }
}

#[actix_rt::main]
pub(crate) async fn start_service(
    bind_addr: String,
    state: ServiceState,
    round_dur: Duration,
    start_time: SystemTime,
    level: u32,
) -> std::io::Result<()> {
    let state = Arc::new(Mutex::new(state));
    let state_copy = state.clone();

    Arbiter::spawn(round_finalization_loop(
        state_copy, round_dur, start_time, level,
    ));

    // Start the web server
    HttpServer::new(move || {
        App::new().data(state.clone()).configure(|cfg| {
            cfg.service(submit_agg).service(force_round_end);
        })
    })
    .workers(1)
    .bind(bind_addr)
    .expect("could not bind")
    .run()
    .await
}
