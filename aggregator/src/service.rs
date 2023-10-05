use crate::{
    util::{save_state, AggregatorError},
    AggregatorState,
};
use common::cli_util;
use common::log_time::{log_detailed_time, log_time};
use common::types::{AggregatedMessage, SubmissionMessage};
use interface::{
    UserSubmissionMessage, AGGREGATOR_THREAD_NUMBER, DC_NUM_USER, EVALUATION_FLAG, PARAMETER_FLAG,
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
use core::ops::DerefMut;
use futures::future::{join_all, FutureExt};
use log::{debug, error, info};
use std::{
    env,
    fs::File,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
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
    /// [onlyevaluaton] for root aggregator to save the aggregate share from leaf aggregator
    pub(crate) root_data_collection: Vec<AggregatedMessage>,
    pub(crate) round: u32,
    /// The path to this aggregator's state file. If `None`, state is not persisted to disk
    pub(crate) agg_state_path: Option<String>,
}

impl ServiceState {
    pub(crate) fn new(
        agg_state: AggregatorState,
        forward_urls: Vec<String>,
        round: u32,
        agg_state_path: Option<String>,
    ) -> ServiceState {
        ServiceState {
            agg_state,
            forward_urls,
            root_data_collection: Vec::new(),
            round,
            agg_state_path,
        }
    }
}

struct CombinedData {
    state: Arc<Mutex<ServiceState>>,
    data_collection: Arc<Mutex<Vec<UserSubmissionMessage>>>,
}

/// Receives a partial aggregate from user, for evaluation purpose
#[post("/submit-agg")]
async fn submit_agg(
    (payload, combined_data): (String, web::Data<CombinedData>),
) -> Result<HttpResponse, ApiError> {
    // let start = std::time::Instant::now();
    // step 1: unwrap input data
    let combined_data = combined_data.get_ref();
    let state = &combined_data.state;
    let data_collection = &combined_data.data_collection;
    let payload = payload.split_whitespace().next().unwrap_or("");

    // step 2: get the aggregator number and level
    let mut handle = state.lock().unwrap();
    let ServiceState {
        ref mut agg_state,
        ref forward_urls,
        ..
    } = handle.deref_mut();
    let agg_number = agg_state.agg_number.unwrap();
    let level = agg_state.level;

    // step 3: load data and push to data_collection
    let data: UserSubmissionMessage = cli_util::load(&mut payload.as_bytes())?;
    let mut data_collection_handle = data_collection.lock().unwrap();
    data_collection_handle.push(data.clone());

    let num_user = if PARAMETER_FLAG {
        env::var("DC_NUM_USER")
            .unwrap_or_else(|_| "100".to_string())
            .parse::<usize>()
            .expect("Invalid DC_NUM_USER value")
    } else {
        DC_NUM_USER
    };

    // evaluation mode
    if EVALUATION_FLAG == true {
        //step 4: judging whether all msg is sent; if so, save it to file.
        info!(
            "now aggregator No.{} have {}/{}",
            agg_number,
            data_collection_handle.len(),
            num_user / AGGREGATOR_THREAD_NUMBER
        );
        if data_collection_handle.len() == num_user / AGGREGATOR_THREAD_NUMBER {
            info!("User finish sending all msg!");
            // Save data_collection to a file
            let save_path_prefix = "data_collection_";
            let save_path_postfix = ".txt";
            let save_path = format!("{}{}{}", save_path_prefix, agg_number, save_path_postfix);
            let file = std::fs::File::create(save_path.clone())?;
            let data_vec = data_collection_handle.clone();
            cli_util::save(file, &data_vec)?;
            info!("Data saved to {}", save_path);
        }
    } else {
        if AGGREGATOR_THREAD_NUMBER == 1 {
            let agg_data = SubmissionMessage::UserSubmission(data);
            agg_state.add_to_aggregate(&agg_data)?;
            if data_collection_handle.len() == num_user / AGGREGATOR_THREAD_NUMBER {
                force_round_output(&*state).await;
            }
        } else if level == 0 {
            error!("the root aggregator doesn't receive msg from client");
        } else {
            let agg_data = SubmissionMessage::UserSubmission(data);
            agg_state.add_to_aggregate(&agg_data)?;
            if data_collection_handle.len() == num_user / AGGREGATOR_THREAD_NUMBER {
                let share: AggregatedMessage = agg_state
                    .finalize_aggregate()
                    .expect("could not finalize aggregate");
                actix_rt::spawn(send_share_to_root(forward_urls.clone(), share));
            }
        }
    }
    Ok(HttpResponse::Ok().body("OK\n"))
}

/// [onlyevaluation] This is for the case when the Httpserver stop saving. This can manually resaving.
#[get("/save-data")]
async fn save_data_collection(
    combined_data: web::Data<CombinedData>,
) -> Result<HttpResponse, ApiError> {
    let combined_data = combined_data.get_ref();

    //step 1: get agg_number
    let state = &combined_data.state;
    let handle = state.lock().unwrap();
    let ServiceState { ref agg_state, .. } = *handle;
    let agg_number = agg_state.agg_number.unwrap();

    //step 2: open data_collection
    let data_collection = &combined_data.data_collection;
    let data_collection_handle = data_collection.lock().unwrap();
    let save_path_prefix = "data_collection_";
    let save_path_postfix = ".txt";
    let save_path = format!("{}{}{}", save_path_prefix, agg_number, save_path_postfix);
    let file = std::fs::File::create(save_path.clone())?;
    let data_vec = data_collection_handle.clone();
    cli_util::save(file, &data_vec)?;
    info!("Data saved to {}", save_path);
    Ok(HttpResponse::Ok().body("OK\n"))
}

/// [onlyevaluation] This is for aggregator reading data from file, and do the aggrgagtion
#[get("/aggregate-eval")]
async fn aggregate_eval(combined_data: web::Data<CombinedData>) -> Result<HttpResponse, ApiError> {
    // step 1: unwrap input
    let combined_data = combined_data.get_ref();
    let state = &combined_data.state;
    let mut handle = state.lock().unwrap();
    let ServiceState {
        ref mut agg_state,
        ref forward_urls,
        ..
    } = handle.deref_mut();

    // step 2: load from file
    // here, because we initially seperate into 32 split, and we now only need 16-thread, so we are reading two files for one agg
    let agg_number = agg_state.agg_number.unwrap();
    let save_path_prefix = "data_collection_";
    let save_path_postfix = ".txt";
    let save_path = format!("{}{}{}", save_path_prefix, agg_number, save_path_postfix);
    let file = File::open(save_path.clone())?;
    let data_collection_loaded: Vec<UserSubmissionMessage> = cli_util::load(file)?;
    info!("Data loaded from {}", save_path);
    // let save_path_2 =  format!("{}{}{}", save_path_prefix, agg_number+16, save_path_postfix);
    // let file_2 = File::open(save_path_2.clone())?;
    // let data_collection_loaded_2: Vec<UserSubmissionMessage> = cli_util::load(file_2)?;

    // step 3: aggregate
    let logflag: bool = false;
    log_time();
    if logflag {
        let log_msg = format!("leaf-agg{} start aggregate", agg_number);
        log_detailed_time(log_msg);
    }

    for data in data_collection_loaded {
        let agg_data = SubmissionMessage::UserSubmission(data);
        agg_state.add_to_aggregate(&agg_data)?;
    }

    // for data in data_collection_loaded_2{
    //     let agg_data = SubmissionMessage::UserSubmission(data);
    //     agg_state.add_to_aggregate(&agg_data)?;
    // }

    // step 4: send to root
    if logflag {
        let log_msg = format!("leaf-agg{} before finalize", agg_number);
        log_detailed_time(log_msg);
    }

    let share: AggregatedMessage = agg_state
        .finalize_aggregate()
        .expect("could not finalize aggregate");
    // debug!("{}'s share is:{:?}, forward-url is {:?}",agg_number, share, forward_urls.clone());
    if logflag {
        let log_msg = format!("leaf-agg{} before sending to root", agg_number);
        log_detailed_time(log_msg);
    }

    actix_rt::spawn(send_share_to_root(forward_urls.clone(), share));

    // debug!("[agg] aggregating log time: {:?}", load_duration);
    // debug!("[agg] aggregating time: {:?}", duration);
    // log_agg_encrypt_time(duration.as_nanos());

    Ok(HttpResponse::Ok().body("OK\n"))
}

async fn send_share_to_root(base_url: Vec<String>, share: AggregatedMessage) {
    // step 1: serialize the share
    let mut body = Vec::new();
    cli_util::save(&mut body, &share).expect("could not serialize share");

    // step 2: Send the serialized contents as an HTTP POST to leader/submit-share
    let timeout_sec = 20;
    let base_url = &base_url[0];
    // debug!(
    //     "Sending share to {} with timeout {}s, content is {:?}",
    //     base_url, timeout_sec, body.clone()
    // );
    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_sec))
        .finish();
    let post_path: Uri = [&base_url, "/submit-agg-from-agg"]
        .concat()
        .parse()
        .expect("Couldn't not append '/submit-agg-from-agg' to forward URL");

    let mut retries = 20;

    loop {
        match client.post(post_path.clone()).send_body(body.clone()).await {
            Ok(res) => {
                if res.status() == StatusCode::OK {
                    debug!("Share sent successfully");
                    break;
                } else {
                    error!("Could not send share message error: {:?}", res);
                }
            }
            Err(e) => {
                error!("Could not send share network error: {:?}", e);
            }
        }

        retries -= 1;
        if retries <= 0 {
            error!("Failed to send share after multiple attempts");
            break;
        }
        // Wait for 50ms before retrying
        // actix::clock::sleep(Duration::from_millis(50)).await;
    }
}

/// Receives a partial aggregate from an aggregator
#[post("/submit-agg-from-agg")]
async fn submit_agg_from_agg(
    (payload, combined_data): (String, web::Data<CombinedData>),
) -> Result<HttpResponse, ApiError> {
    //step 1: unwrap payload
    let logflag: bool = false;

    if logflag {
        let log_msg = format!("receiving leaf share");
        log_detailed_time(log_msg);
    }

    let data: AggregatedMessage = cli_util::load(&mut payload.as_bytes())?;

    if logflag {
        let log_msg = format!("root already load");
        log_detailed_time(log_msg);
    }

    // step 2: unwrap input
    let mut flag: bool = false;
    let combined_data_ref = combined_data.get_ref();
    let state = &combined_data_ref.state;
    {
        let mut handle = state.lock().unwrap();
        let ServiceState {
            ref mut agg_state,
            ref mut root_data_collection,
            ..
        } = handle.deref_mut();
        root_data_collection.push(data.clone());

        if logflag {
            let log_msg = format!("root finish unwrapping msg");
            log_detailed_time(log_msg);
        }

        //step 3: add to aggregate
        let agg_data = SubmissionMessage::AggSubmission(data);
        agg_state.add_to_aggregate(&agg_data)?;

        if logflag {
            let log_msg = format!("root finish aggregating");
            log_detailed_time(log_msg);
        }

        //step 4: judge whether all shares are collected
        if root_data_collection.len() == AGGREGATOR_THREAD_NUMBER {
            flag = true;
        }
    }
    if flag {
        info!("collecting all shares!");
        if logflag {
            let log_msg = format!("root start output");
            log_detailed_time(log_msg);
        }
        log_time();
        force_round_output(&*state).await;
        info!("root-agg successfully send msg to server");
    }
    // debug!("[agg] submit-agg-from-agg success");
    // let duration = start.elapsed();
    // debug!("[agg] submit_agg_from_agg: {:?}", duration);
    Ok(HttpResponse::Ok().body("OK\n"))
}

/// Forces the current round to end. Only for debugging purposes
#[get("/force-round-end")]
async fn force_round_end(combined_data: web::Data<CombinedData>) -> Result<HttpResponse, ApiError> {
    let start = std::time::Instant::now();

    // step 1: unwrap input
    let combined_data_ref = combined_data.get_ref();
    let state = &combined_data_ref.state;

    // step 2: force round output
    force_round_output(&*state).await;
    let duration = start.elapsed();
    debug!("[agg] force_round_end: {:?}", duration);

    Ok(HttpResponse::Ok().body("OK\n"))
}

/// root will trigger this function to send msg to server
async fn force_round_output(state: &Mutex<ServiceState>) {
    debug!("start round output!");
    let send_timeout = Duration::from_secs(20);
    let (agg_payload, forward_urls) =
        get_agg_payload(<&std::sync::Mutex<ServiceState>>::clone(&state));
    debug!("forward_urls is {:?}", forward_urls);
    spawn(
        actix_rt::time::timeout(send_timeout, send_aggregate(agg_payload, forward_urls)).map(|r| {
            if r.is_err() {
                error!("sending aggregation was hit");
            }
        }),
    );

    // [onlyevaluation]Start the next round immediately
    // as we will only do evaluation, we will not actually start nextround
    if !EVALUATION_FLAG {
        start_next_round(<&std::sync::Mutex<ServiceState>>::clone(&state));
    }
}

#[get("/round-num")]
async fn round_num(combined_data: web::Data<CombinedData>) -> Result<HttpResponse, ApiError> {
    // Unwrap the round and make it a struct
    let state = &combined_data.get_ref().state;
    // Unpack state
    let handle = state.lock().unwrap();
    let ServiceState { ref round, .. } = *handle;
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
    debug!("forward_urls is {:?}", forward_urls.clone());
    (payload, forward_urls.clone())
}

/// Sends a finalized aggregate to base_url/submit-agg for all base_url in forward_urls
async fn send_aggregate(payload: Vec<u8>, forward_urls: Vec<String>) {
    let start = std::time::Instant::now();
    let mut forward_urls_reverse = forward_urls.clone();
    forward_urls_reverse.reverse();
    info!("Forwarding aggregate to {:?}", forward_urls_reverse);
    println!("payload len in send_aggregate:{}", payload.len());
    // Create a vector to store all the futures
    let mut futures = Vec::new();

    for base_url in forward_urls_reverse {
        let future = send_to_url(base_url, payload.clone());
        futures.push(future);
    }

    // Await all futures to complete in parallel
    join_all(futures).await;

    let duration = start.elapsed();
    debug!("[agg] send_aggregate: {:?}", duration);
}

async fn send_to_url(base_url: String, payload: Vec<u8>) {
    let timeout_sec = 5;
    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_sec))
        .finish();
    let post_path: Uri = [&base_url, "/submit-agg"].concat().parse().expect(&format!(
        "Couldn't not append '/submit-agg' to forward URL {}",
        base_url
    ));
    println!("payload len in send_to_url:{}", payload.len());
    match client.post(post_path).send_body(payload).await {
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

// Saves the state and start the next round
fn start_next_round(state: &Mutex<ServiceState>) {
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
    *round += 1;
    agg_state.clear(*round).expect("could not start new round");

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
/// [problem] When the round is normally ended, the clock is not reset. We can set a end-time in the ServiceState.
/// Currently, each round time is set to 100,000s in server_ctrl.sh
async fn round_finalization_loop(
    state: Arc<Mutex<ServiceState>>,
    round_dur: Duration,
    mut start_time: SystemTime,
    level: u32,
) {
    let one_sec = Duration::from_secs(100);
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
        start_next_round(&state.clone());

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
    let data_collection = Arc::new(Mutex::new(Vec::<UserSubmissionMessage>::new()));

    Arbiter::spawn(round_finalization_loop(
        state_copy, round_dur, start_time, level,
    ));

    // Start the web server
    if level == 0 {
        HttpServer::new(move || {
            App::new()
                .data(CombinedData {
                    state: state.clone(),
                    data_collection: data_collection.clone(),
                })
                .data(web::PayloadConfig::new(10 << 21))
                .configure(|cfg| {
                    cfg.service(submit_agg)
                        .service(force_round_end)
                        .service(round_num)
                        .service(aggregate_eval)
                        .service(save_data_collection)
                        .service(submit_agg_from_agg);
                })
        })
        .workers(16)
        .bind(bind_addr)
        .expect("could not bind")
        .run()
        .await
    } else {
        HttpServer::new(move || {
            App::new()
                .data(CombinedData {
                    state: state.clone(),
                    data_collection: data_collection.clone(),
                })
                .data(web::PayloadConfig::new(10 << 21))
                .configure(|cfg| {
                    cfg.service(submit_agg)
                        .service(force_round_end)
                        .service(round_num)
                        .service(aggregate_eval)
                        .service(save_data_collection)
                        .service(submit_agg_from_agg);
                })
        })
        .workers(1)
        .bind(bind_addr)
        .expect("could not bind")
        .run()
        .await
    }
}
