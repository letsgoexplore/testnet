mod error;
mod message;

pub use self::error::*;
pub use self::message::*;

pub type DcNetResult<T> = Result<T, DcNetError>;
