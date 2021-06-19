mod aggregation;
mod keygen;
mod seal_unseal;
mod submit;

pub use self::aggregation::aggregate;
pub use self::keygen::{ecall_new_sgx_signing_key, ecall_unseal_to_pubkey};
pub use self::submit::ecall_user_submit;
