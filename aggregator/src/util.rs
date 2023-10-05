use crate::agg_state::AggregatorState;
use common::{cli_util, enclave::EnclaveError};
use interface::UserSubmissionMessage;
use log::info;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{convert::TryInto, fs::File, io};
use thiserror::Error;

pub(crate) type Result<T> = core::result::Result<T, AggregatorError>;

#[derive(Debug, Error)]
pub enum AggregatorError {
    #[error("aggregator has not been initialized")]
    Uninitialized,
    #[error("error from enclave")]
    Enclave(#[from] EnclaveError),
    #[error("error from IO")]
    Io(#[from] io::Error),
    #[error("error in serialization/deserialization")]
    Ser(#[from] cli_util::SerializationError),
    #[error("invalid parameter")]
    InvalidParameter,
}

pub(crate) fn load_state(save_path: &str) -> Result<AggregatorState> {
    let save_file = File::open(save_path)?;
    let mut loaded_state: AggregatorState = cli_util::load(save_file)?;
    if loaded_state.agg_number.is_none() {
        loaded_state.agg_number = Some(0);
    }
    Ok(loaded_state)
}

pub(crate) fn save_state(save_path: &str, state: &AggregatorState) -> Result<()> {
    let save_file = File::create(save_path)?;
    Ok(cli_util::save(save_file, state)?)
}

pub(crate) fn load_from_stdin<D: for<'a> Deserialize<'a>>() -> Result<D> {
    let stdin = std::io::stdin();
    Ok(cli_util::load(stdin)?)
}

pub(crate) fn save_to_stdout<S: Serialize>(val: &S) -> Result<()> {
    let stdout = std::io::stdout();
    cli_util::save(stdout, val)?;
    println!("");
    Ok(())
}

///[onlyevaluation]split the data_collection to several pieces, for multi-thread
pub(crate) fn split_data_collection(num_user: u32, thread: u32) {
    let save_path = "data_collection.txt";
    let file = File::open(save_path).unwrap();
    let data_collection_loaded: Vec<UserSubmissionMessage> = cli_util::load(file).unwrap();
    info!("Data loaded from {}", save_path);

    let remainder = num_user % thread;
    let single_leaf_agg_msg_num = (num_user - remainder) / thread;
    (0..remainder).into_par_iter().for_each(|i| {
        let index_start = (i * (single_leaf_agg_msg_num + 1)).try_into().unwrap();
        let index_end = ((i + 1) * (single_leaf_agg_msg_num + 1))
            .try_into()
            .unwrap();
        let data_slice: &[UserSubmissionMessage] = &data_collection_loaded[index_start..index_end];
        let data_vec: Vec<UserSubmissionMessage> = data_slice.to_vec();

        let save_path_prefix = "data_collection_";
        let save_path_postfix = ".txt";
        let save_path = format!("{}{}{}", save_path_prefix, i + 1, save_path_postfix);
        let file = std::fs::File::create(save_path.clone()).unwrap();
        cli_util::save(file, &data_vec).unwrap();
        info!("Data saved to {}", save_path);
    });
    (remainder..thread).into_par_iter().for_each(|i| {
        let index_start = (i * single_leaf_agg_msg_num + remainder)
            .try_into()
            .unwrap();
        let index_end = ((i + 1) * single_leaf_agg_msg_num + remainder)
            .try_into()
            .unwrap();
        let data_slice: &[UserSubmissionMessage] = &data_collection_loaded[index_start..index_end];
        let data_vec: Vec<UserSubmissionMessage> = data_slice.to_vec();

        let save_path_prefix = "data_collection_";
        let save_path_postfix = ".txt";
        let save_path = format!("{}{}{}", save_path_prefix, i + 1, save_path_postfix);
        let file = std::fs::File::create(save_path.clone()).unwrap();
        cli_util::save(file, &data_vec).unwrap();
        info!("Data saved to {}", save_path);
    });
}
