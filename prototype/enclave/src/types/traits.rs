use crate::interface::*;
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

impl Xor for DCMessage {
    fn xor(&self, other: &DCMessage) -> Self {
        DCMessage::from(AsRef::<RawMessage>::as_ref(self).xor(other.as_ref()))
    }
}
