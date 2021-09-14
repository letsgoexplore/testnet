use crate::interface::DcMessage;
use std::prelude::v1::*;

pub trait Sealable {
    fn seal(&self) -> SgxResult<Vec<u8>>;
}

use serde::Serialize;
use sgx_types::SgxResult;
use utils::ser_and_seal_to_vec;

impl<T> Sealable for T
where
    T: Serialize,
{
    fn seal(&self) -> SgxResult<Vec<u8>> {
        ser_and_seal_to_vec(self, b"")
    }
}

pub trait UnsealableAs<T> {
    fn unseal(&self) -> SgxResult<T>;
}

pub trait UnmarshallableAs<T> {
    fn unmarshal(&self) -> SgxResult<T>;
}

pub trait MarshallAs<T> {
    fn marshal(&self) -> SgxResult<T>;
}

pub trait SealAs<T> {
    fn seal(&self) -> SgxResult<T>;
}
