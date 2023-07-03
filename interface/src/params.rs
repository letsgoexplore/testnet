/// User id is sha-256 hash of some public key
pub const USER_ID_LENGTH: usize = 32;
pub const USER_ID_MAX_LEN: usize = 32;

/// The num of bits in a footprint. must be smaller than 32 (checked in enclave)
pub const FOOTPRINT_BIT_SIZE: usize = 3;

/// The number of scheduling slots. This should be larger than DC_NET_N_SLOTS to avoid collision.
pub const FOOTPRINT_N_SLOTS: usize = DC_NET_N_SLOTS * 4;

/// The number of slots in a DC net message
pub const DC_NET_N_SLOTS: usize = 100;
/// The number of bytes in each DC net slot
pub const DC_NET_MESSAGE_LENGTH: usize = 160;

/// There are these many rounds per window
pub const DC_NET_ROUNDS_PER_WINDOW: u32 = 100;
/// A user is allowed to talk this many times per window
pub const DC_NET_MSGS_PER_WINDOW: u32 = 10;

/// The size of an anytrust shared secret
pub const SERVER_KEY_LENGTH: usize = DC_NET_MESSAGE_LENGTH;

/// The size of a sealed secret key. Although the secret key is only 32-byte, the sealed version is
/// quite large and we can't go much smaller than 1024.
pub const SEALED_SGX_SIGNING_KEY_LENGTH: usize = 1024;

/// The size of a public key of a server
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// Gets the window that this round belongs to
pub fn round_window(round: u32) -> u32 {
    let relative_round = round % DC_NET_ROUNDS_PER_WINDOW;
    (round - relative_round)
        .checked_div(DC_NET_ROUNDS_PER_WINDOW)
        .unwrap()
}

pub const ENCLAVE_LOG_LEVEL: &str = "debug"; // "debug" or "info"

/// Number of threads for deriving round secrets
pub const N_THREADS_DERIVE_ROUND_SECRET: usize = 10;
