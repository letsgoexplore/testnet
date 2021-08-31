use crate::{
    util::{save_state, AggregatorError},
    AggregatorState,
};
use common::{cli_util, enclave_wrapper::DcNetEnclave};
use interface::RoundSubmissionBlob;

use core::ops::DerefMut;
use std::{sync::Mutex, time::Duration};

use actix_web::{http::StatusCode, post, web, App, HttpResponse, HttpServer, ResponseError};
use log::{error, info};
use reqwest::{blocking::Client, Url};
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
pub(crate) struct ServerState {
    pub(crate) agg_state: AggregatorState,
    pub(crate) enclave: DcNetEnclave,
    pub(crate) round: u32,
}

#[post("/submit")]
async fn submit(
    (payload, state): (String, web::Data<Mutex<ServerState>>),
) -> Result<HttpResponse, ApiError> {
    // Parse aggregation
    let agg_data: RoundSubmissionBlob = cli_util::load(&mut payload.as_bytes())?;

    // Unpack state
    let mut handle = state.get_ref().lock().unwrap();
    let ServerState {
        ref mut agg_state,
        ref enclave,
        ..
    } = handle.deref_mut();
    // Add to aggregate
    agg_state.add_to_aggregate(enclave, &agg_data)?;

    Ok(HttpResponse::Ok().finish())
}

fn forward_aggregate(agg_state: &AggregatorState, enclave: &DcNetEnclave, base_url: &Url) {
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
    let client = Client::new();
    let post_path = base_url
        .join("/submit")
        .expect("Couldn't not append '/submit' to forward URL");
    match client
        .post(post_path)
        .timeout(Duration::from_secs(10))
        .body(body)
        .send()
    {
        Ok(res) => {
            if res.status() == StatusCode::OK {
                info!("Successfully sent finalize aggregate")
            } else {
                error!("Could not send finalized aggregate: {:?}", res.text())
            }
        }
        Err(e) => error!("Could not send finalized aggregate: {:?}", e),
    }
}

fn round_finalization_loop(
    state_path: String,
    state: web::Data<Mutex<ServerState>>,
    round_dur: Duration,
    forward_url: Url,
) {
    // Every round_dur seconds, end the round, save the state, and send the finalized aggregate to
    // the next aggregator up the tree
    loop {
        std::thread::sleep(round_dur);

        // The round has ended. Save the state and forward the aggregate before starting the
        // new round
        {
            let mut handle = state.get_ref().lock().unwrap();
            let ServerState {
                ref mut agg_state,
                ref enclave,
                ref mut round,
            } = *handle;

            info!("Round {} complete", round);

            info!("Saving state");
            save_state(&state_path, agg_state).expect("failed to save state");

            info!("Forwarding aggregate");
            forward_aggregate(agg_state, enclave, &forward_url);

            // Otherwise, start the next round
            *round = *round + 1;
            if let Err(e) = agg_state.clear(&enclave, *round) {
                error!("Could not start new round: {:?}", e);
            }
        }
    }
}

#[actix_rt::main]
pub(crate) async fn start_service(
    bind_addr: String,
    forward_url: Url,
    state_path: String,
    state: ServerState,
    round_dur: Duration,
) -> std::io::Result<()> {
    let state = web::Data::new(Mutex::new(state));
    let state_copy = state.clone();

    std::thread::spawn(move || {
        round_finalization_loop(state_path, state_copy, round_dur, forward_url);
    });

    // Start the web server
    HttpServer::new(move || {
        App::new().data(state.clone()).configure(|cfg| {
            cfg.service(submit);
        })
    })
    .bind(bind_addr)
    .expect("could not bind")
    .run()
    .await
}
