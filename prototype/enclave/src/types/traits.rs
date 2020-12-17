use crate::interface::*;
use crate::types::*;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::ops::Deref;
use std::prelude::v1::*;

// various functions for computing a.xor(b)
pub trait Xor {
    fn xor(&self, other: &Self) -> Self;
    fn xor_mut(&mut self, other: &Self)
    where
        Self: Sized,
    {
        *self = self.xor(other);
    }
}

impl Xor for RawMessage {
    fn xor(&self, other: &Self) -> Self {
        let mut result = RawMessage::zero();
        let msg: Vec<u8> = self.iter().zip(other).map(|(x, y)| x ^ y).collect();
        for i in 0..msg.len() {
            result[i] = msg[i];
        }

        result
    }
}

impl Xor for Vec<u8> {
    fn xor(&self, other: &Self) -> Self {
        self.iter().zip(other).map(|(x, y)| x ^ y).collect()
    }
}

use crate::hex;

impl Xor for DCMessage {
    fn xor(&self, other: &DCMessage) -> Self {
        DCMessage {
            msg: self.msg.xor(&other.msg),
        }
    }
}
