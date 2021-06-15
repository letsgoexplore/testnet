use crate::params::*;
use crate::Signature;

use std::vec::Vec;

#[allow(dead_code)]
pub struct Footprint {
    fp: [bool; FOOTPRINT_BIT_SIZE],
}

#[allow(dead_code)]
pub struct SchedulingState {
    round: u32,
    reservation_map: Vec<bool>,
    footprints: Vec<Footprint>,
    finished: bool,
    tee_sig: Signature,
}

// TODO: Flesh out these structs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FootprintTicket;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedFootprintTicket;
