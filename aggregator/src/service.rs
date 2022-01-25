use crate::{
    util::{save_state, AggregatorError},
    AggregatorState,
};
use common::{cli_util, enclave_wrapper::DcNetEnclave};
use interface::RoundSubmissionBlob;

use core::ops::DerefMut;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use actix_rt::Arbiter;
use actix_web::{
    client::Client,
    http::{StatusCode, Uri},
    post, rt as actix_rt, web, App, HttpResponse, HttpServer, ResponseError,
};
use log::{error, info};
use thiserror::Error;

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
    pub(crate) forward_urls: Vec<String>,
    pub(crate) round: u32,
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

/// Sends a finalized aggregate to base_url/submit-agg
async fn send_aggregate(agg_state: &AggregatorState, enclave: &DcNetEnclave, base_url: &str) {
    // Finalize and serialize the aggregate
    let agg = match agg_state.finalize_aggregate(enclave) {
        Ok(a) => a,
        Err(e) => {
            error!("Could not finalize aggregate: {:?}", e);
            return;
        }
    };
    let mut body = Vec::new();
    cli_util::save(&mut body, &agg).expect("could not serialize aggregate");

    // Send the serialized contents
    let client = Client::builder().timeout(Duration::from_secs(20)).finish();
    let post_path: Uri = [base_url, "/submit-agg"].concat().parse().expect(&format!(
        "Couldn't not append '/submit-agg' to forward URL {}",
        base_url
    ));
    match client.post(post_path).send_body(body).await {
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

/// Every `round_dur`, ends the round and forwards the finalized aggregate to the next aggregator
/// or anytrust server up the tree
async fn round_finalization_loop(
    state_path: String,
    state: Arc<Mutex<ServiceState>>,
    round_dur: Duration,
) {
    // Every round_dur seconds, end the round, save the state, and send the finalized aggregate to
    // the next aggregator up the tree
    let mut interval = actix_rt::time::interval(round_dur);
    // The first tick fires immediately, so get that out of the way
    interval.tick().await;
    // Now start the round loop
    loop {
        interval.tick().await;

        // The round has ended. Save the state and forward the aggregate before starting the
        // new round
        {
            let mut handle = state.lock().unwrap();
            let ServiceState {
                ref mut agg_state,
                ref enclave,
                ref forward_urls,
                ref mut round,
            } = *handle;

            info!("round {} complete", round);

            info!("Forwarding aggregate to {:?}", forward_urls);
            for forward_url in forward_urls {
                send_aggregate(agg_state, enclave, forward_url).await;
            }

            // Save the state and start the next round
            info!("Saving state");
            save_state(&state_path, agg_state).expect("failed to save state");

            *round += 1;
            agg_state
                .clear(&enclave, *round)
                .expect("could not start new round");
        }
    }
}

#[actix_rt::main]
pub(crate) async fn start_service(
    bind_addr: String,
    state_path: String,
    state: ServiceState,
    round_dur: Duration,
) -> std::io::Result<()> {
    let state = Arc::new(Mutex::new(state));
    let state_copy = state.clone();

    Arbiter::spawn(round_finalization_loop(state_path, state_copy, round_dur));

    // Start the web server
    HttpServer::new(move || {
        App::new().data(state.clone()).configure(|cfg| {
            cfg.service(submit_agg);
        })
    })
    .workers(1)
    .bind(bind_addr)
    .expect("could not bind")
    .run()
    .await
}
