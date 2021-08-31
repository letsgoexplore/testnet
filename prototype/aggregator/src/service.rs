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
use log::{debug, error, info};
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
    pub(crate) terminated: bool,
}

#[post("/submit")]
async fn submit(
    (payload, state): (String, web::Data<Arc<Mutex<ServerState>>>),
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

async fn forward_aggregate(agg_state: &AggregatorState, enclave: &DcNetEnclave, base_url: &str) {
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
    let post_path: Uri = [base_url, "/submit"]
        .concat()
        .parse()
        .expect("Couldn't not append '/submit' to forward URL");
    println!("Connecting");
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

async fn round_finalization_loop(
    state_path: String,
    state: Arc<Mutex<ServerState>>,
    round_dur: Duration,
    forward_url: String,
) {
    // Every round_dur seconds, end the round, save the state, and send the finalized aggregate to
    // the next aggregator up the tree
    let mut interval = actix_rt::time::interval(round_dur);
    while let _ = interval.tick().await {
        // The round has ended. Save the state and forward the aggregate before starting the
        // new round
        {
            let mut handle = state.lock().unwrap();
            let ServerState {
                ref mut agg_state,
                ref enclave,
                ref mut round,
                ref terminated,
            } = *handle;

            info!("Round {} complete", round);

            info!("Saving state");
            save_state(&state_path, agg_state).expect("failed to save state");

            info!("Forwarding aggregate");
            forward_aggregate(agg_state, enclave, &forward_url).await;

            // If the server has terminated, exit
            if *terminated {
                return;
            }

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
    forward_url: String,
    state_path: String,
    state: ServerState,
    round_dur: Duration,
) -> std::io::Result<()> {
    let state = Arc::new(Mutex::new(state));
    let state_copy = state.clone();

    Arbiter::spawn(round_finalization_loop(
        state_path,
        state_copy,
        round_dur,
        forward_url,
    ));

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
