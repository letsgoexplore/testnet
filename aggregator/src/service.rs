use crate::{
    util::{save_state, AggregatorError},
    AggregatorState,
};
use common::cli_util;
use common::log_time::log_agg_encrypt_time;
use common::types_nosgx::{
    AggregatedMessage,
    SubmissionMessage,
};
use interface::UserSubmissionMessageUpdated;

use core::ops::DerefMut;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
    fs::File, io, env,
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
use log::{error, info, debug};
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
impl From<std::io::Error> for ApiError {
    fn from(error: std::io::Error) -> Self {
        ApiError::Internal(AggregatorError::Io(error))
    }
}

// #[derive(Clone)]
pub(crate) struct ServiceState {
    pub(crate) agg_state: AggregatorState,
    /// The URLs of the next aggregators
    pub(crate) forward_urls: Vec<String>,
    pub(crate) round: u32,
    /// The path to this aggregator's state file. If `None`, state is not persisted to disk
    pub(crate) agg_state_path: Option<String>,
}

/// Receives a partial aggregate from user
// #[post("/submit-agg")]
// async fn submit_agg(
//     (payload, state): (String, web::Data<Arc<Mutex<ServiceState>>>),
// ) -> Result<HttpResponse, ApiError> {
//     let start = std::time::Instant::now();
//     // Strip whitespace from the payload
//     let payload = payload.split_whitespace().next().unwrap_or("");
//     // Parse aggregation
//     let data: UserSubmissionMessageUpdated = cli_util::load(&mut payload.as_bytes())?;

//     // Unpack state
//     let mut handle = state.get_ref().lock().unwrap();
//     let ServiceState {
//         ref mut agg_state,
//         ..
//     } = handle.deref_mut();

//     // Add to aggregate
//     let agg_data = SubmissionMessage::UserSubmission(data);
//     agg_state.add_to_aggregate(&agg_data)?;

//     // debug!("[agg] submit-agg success");
//     let duration = start.elapsed();
//     debug!("[agg] submit_agg: {:?}", duration);
//     log_agg_encrypt_time(duration.as_nanos());
//     Ok(HttpResponse::Ok().body("OK\n"))
// }

/// Receives a partial aggregate from user, for evaluation purpose
#[post("/submit-agg")]
async fn submit_agg(
    (payload, data_collection): (String, web::Data<Arc<Mutex<Vec<UserSubmissionMessageUpdated>>>>),
) -> Result<HttpResponse, ApiError> {
    let start = std::time::Instant::now();
    // Strip whitespace from the payload
    let payload = payload.split_whitespace().next().unwrap_or("");
    // Parse aggregation
    let data: UserSubmissionMessageUpdated = cli_util::load(&mut payload.as_bytes())?;

    let mut data_collection_handle = data_collection.lock().unwrap();
    data_collection_handle.push(data);

    let num_user = 
        env::var("DC_NUM_USER")
        .unwrap_or_else(|_| "100".to_string())
        .parse::<usize>()
        .expect("Invalid DC_NUM_USER value");
    info!("now we have {}/{}", data_collection_handle.len(), num_user);
    if data_collection_handle.len() == num_user {
        info!("User finish sending all msg!");
        // Save data_collection to a file
        let save_path = "data_collection.txt";
        let file = std::fs::File::create(save_path)?;
        let data_vec = data_collection_handle.clone();
        cli_util::save(file, &data_vec)?;
        info!("Data saved to {}", save_path);
    }

    Ok(HttpResponse::Ok().body("OK\n"))
}

#[get("/aggregate-eval")]
async fn aggregate_eval(
    state: web::Data<Arc<Mutex<ServiceState>>>,
) -> Result<HttpResponse, ApiError> {
    // Load data_collection from the file (if needed)
    let save_path = "data_collection.txt";
    let file = File::open(save_path)?;
    let data_collection_loaded: Vec<UserSubmissionMessageUpdated> = cli_util::load(file)?;
    info!("Data loaded from {}", save_path);
    // Unpack state
    let start = std::time::Instant::now();
    let mut handle = state.get_ref().lock().unwrap();
    let ServiceState {
        ref mut agg_state,
        ..
    } = handle.deref_mut();
    for data in data_collection_loaded{
        let agg_data = SubmissionMessage::UserSubmission(data);
        agg_state.add_to_aggregate(&agg_data)?;
    }
    let duration = start.elapsed();
    debug!("[agg] aggregating time: {:?}", duration);
    log_agg_encrypt_time(duration.as_nanos());
    Ok(HttpResponse::Ok().body("OK\n"))
}

/// Receives a partial aggregate from an aggregator
#[post("/submit-agg-from-agg")]
async fn submit_agg_from_agg(
    (payload, state): (String, web::Data<Arc<Mutex<ServiceState>>>),
) -> Result<HttpResponse, ApiError> {
    let start = std::time::Instant::now();
    // Strip whitespace from the payload
    let payload = payload.split_whitespace().next().unwrap_or("");
    // Parse aggregation
    let data: AggregatedMessage = cli_util::load(&mut payload.as_bytes())?;

    // Unpack state
    let mut handle = state.get_ref().lock().unwrap();
    let ServiceState {
        ref mut agg_state,
        ..
    } = handle.deref_mut();

    // Add to aggregate
    let agg_data = SubmissionMessage::AggSubmission(data);
    agg_state.add_to_aggregate(&agg_data)?;

    // debug!("[agg] submit-agg-from-agg success");
    let duration = start.elapsed();
    debug!("[agg] submit_agg_from_agg: {:?}", duration);
    Ok(HttpResponse::Ok().body("OK\n"))
}

/// Forces the current round to end. Only for debugging purposes
#[get("/force-round-end")]
async fn force_round_end(
    state: web::Data<Arc<Mutex<ServiceState>>>,
) -> Result<HttpResponse, ApiError> {
    let start = std::time::Instant::now();

    let state = state.get_ref();

    // End the round. Serialize the aggregate and forward it in the background. Time out
    // after 1 second
    let send_timeout = Duration::from_secs(20);
    let (agg_payload, forward_urls) = get_agg_payload(&*state);

    spawn(
        actix_rt::time::timeout(send_timeout, send_aggregate(agg_payload, forward_urls)).map(|r| {
            if r.is_err() {
                error!("sending aggregation was hit");
            }
        }),
    );

    // Start the next round immediately
    // as we will only do evaluation, we will not actually start nextround, but only save it
    start_next_round(state.clone());

    let duration = start.elapsed();
    debug!("[agg] force_round_end: {:?}", duration);

    Ok(HttpResponse::Ok().body("OK\n"))
}

#[get("/round-num")]
async fn round_num(
    state: web::Data<Arc<Mutex<ServiceState>>>,
) -> Result<HttpResponse, ApiError>  {
    // Unwrap the round and make it a struct

    // Unpack state
    let handle = state.get_ref().lock().unwrap();
    let ServiceState {
        ref round,
        ..
    } = *handle;
    info!("[agg] round: {:?}", &round);
    let body = round.to_string();
    Ok(HttpResponse::Ok().body(body))

}

/// Finalizes and serializes the current aggregator state. Returns the pyaload nad all the
/// forwarding URLs
fn get_agg_payload(state: &Mutex<ServiceState>) -> (Vec<u8>, Vec<String>) {
    let start = std::time::Instant::now();

    let handle = state.lock().unwrap();
    let ServiceState {
        ref agg_state,
        ref forward_urls,
        ..
    } = *handle;

    // Finalize and serialize the aggregate
    let agg = agg_state
        .finalize_aggregate()
        .expect("could not finalize aggregate");
    let mut payload = Vec::new();
    cli_util::save(&mut payload, &agg).expect("could not serialize aggregate");

    let duration = start.elapsed();
    debug!("[agg] get_agg_payload: {:?}", duration);

    (payload, forward_urls.clone())
}

/// Sends a finalized aggregate to base_url/submit-agg for all base_url in forward_urls
async fn send_aggregate(payload: Vec<u8>, forward_urls: Vec<String>) {
    let start = std::time::Instant::now();

    let mut forward_urls_reverse = forward_urls.clone();
    forward_urls_reverse.reverse();
    info!("Forwarding aggregate to {:?}", forward_urls_reverse);
    for base_url in forward_urls_reverse {
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
                    error!("Could not send finalized aggregate-msg error: {:?}", res)
                }
            }
            Err(e) => error!("Could not send finalized aggregate-network error: {:?}", e),
        }
    }

    let duration = start.elapsed();
    debug!("[agg] send_aggregate: {:?}", duration);
}

// Saves the state and start the next round
fn start_next_round(state: Arc<Mutex<ServiceState>>) {
    let start = std::time::Instant::now();

    let mut handle = state.lock().unwrap();
    let ServiceState {
        ref mut agg_state,
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
    // *round += 1;
    // agg_state
    //     .clear(*round)
    //     .expect("could not start new round");

    let duration = start.elapsed();
    debug!("[agg] start_next_round: {:?}", duration);
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

    // debug!("start round_finalization_loop");

    // Wait until the start time, then start the round loop
    delay_until(systime_to_instant(start_time)).await;
    loop {
        // We send our aggregate `level` seconds after the official end of the round
        let end_time = start_time + round_dur + level * one_sec;

        // debug!("systime_to_instant(end_time): {:?}", systime_to_instant(end_time));

        // Wait
        delay_until(systime_to_instant(end_time)).await;

        // The round has ended. Serialize the aggregate and forward it in the background. Time out
        // after 1 second
        let (agg_payload, forward_urls) = get_agg_payload(&state);
        // debug!("agg_payload.len: {}", agg_payload.len());
        // debug!("forward_urls: {:?}", forward_urls);

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
    let data_collection = Arc::new(Mutex::new(Vec::<UserSubmissionMessageUpdated>::new()));

    Arbiter::spawn(round_finalization_loop(
        state_copy, round_dur, start_time, level,
    ));

    // Start the web server
    HttpServer::new(move || {
        App::new().data(state.clone()).data(data_collection.clone()).data(web::PayloadConfig::new(10 << 21))
        .configure(|cfg| {
            cfg.service(submit_agg).service(force_round_end).service(round_num).service(aggregate_eval);
        })
    })
    .workers(1)
    .bind(bind_addr)
    .expect("could not bind")
    .run()
    .await
}
