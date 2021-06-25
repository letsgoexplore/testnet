mod error;
mod traits;

pub use self::error::*;
pub use self::traits::*;

pub type DcNetResult<T> = Result<T, DcNetError>;
