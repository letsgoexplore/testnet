use crate::key::Signature;
use crate::params::*;

use std::vec::Vec;

pub struct Footprint {
    fp: [bool; FOOTPRINT_BIT_SIZE],
}

pub struct SchedulingState {
    round: u32,
    reservation_map: Vec<bool>,
    footprints: Vec<Footprint>,
    finished: bool,
    tee_sig: Signature,
}
