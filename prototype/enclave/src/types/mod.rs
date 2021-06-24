mod aggregated_msg;
mod error;
mod traits;

pub use self::aggregated_msg::*;
pub use self::error::*;
pub use self::traits::*;

pub type DcNetResult<T> = Result<T, DcNetError>;
