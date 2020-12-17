mod aggregation;
mod keygen;
mod submit;

pub use self::aggregation::aggregate;
pub use self::keygen::{new_tee_signing_key, unseal_to_pubkey};
pub use self::submit::ecall_client_submit;
