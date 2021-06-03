pub trait Size {
    fn size() -> usize;
    fn size_marshaled() -> usize;
}

impl<T> Size for T {
    fn size() -> usize {
        std::mem::size_of::<T>()
    }

    fn size_marshaled() -> usize {
        // TODO: we heuristically believe that our marshaling scheme has an expansion ratio < 2
        std::mem::size_of::<T>() * 2
    }
}

// return a reasonable zero value
pub trait Zero {
    fn zero() -> Self;
}

use crate::params::DC_NET_MESSAGE_LENGTH;
use crate::user_request::{DCMessage, RawMessage};

impl Zero for RawMessage {
    fn zero() -> Self {
        [0 as u8; DC_NET_MESSAGE_LENGTH]
    }
}

impl Zero for DCMessage {
    fn zero() -> Self {
        DCMessage::from(RawMessage::zero())
    }
}
