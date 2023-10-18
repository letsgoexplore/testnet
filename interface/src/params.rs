/// whether or not DC_NET_N_SLOTS,DC_NET_MESSAGE_LENGTH, FOOTPRINT_N_SLOTS are read from env, or from
pub const PARAMETER_FLAG: bool = true;

/// Whether this is evaluation mode, or this is normal running mode.
/// When turning to evaluation mode, aggregator will first save all msg from client to file,
/// and the the state of Aggregator and Server will not be renewed,
/// this is for the convenience of repeated experiment.
pub const EVALUATION_FLAG: bool = false;

/// User id is sha-256 hash of some public key
pub const USER_ID_LENGTH: usize = 32;
pub const USER_ID_MAX_LEN: usize = 32;

/// The num of bits in a footprint. must be smaller than 32 (checked in enclave)
pub const FOOTPRINT_BIT_SIZE: usize = 3;

/// The number of scheduling slots. This should be larger than DC_NET_N_SLOTS to avoid collision.
pub const FOOTPRINT_N_SLOTS: usize = DC_NET_N_SLOTS * 4;

/// The number of users
pub const DC_NUM_USER: usize = 1024;
/// The number of slots in a DC net message
pub const DC_NET_N_SLOTS: usize = 100;
/// The number of bytes in each DC net slot
pub const DC_NET_MESSAGE_LENGTH: usize = 160;

/// There are these many rounds per window
pub const DC_NET_ROUNDS_PER_WINDOW: u32 = 100;
/// A user is allowed to talk this many times per window
pub const DC_NET_MSGS_PER_WINDOW: u32 = 10;

/// The thread number of the aggregator
pub const AGGREGATOR_THREAD_NUMBER: usize = 16;
/// The size of an anytrust shared secret
pub const SERVER_KEY_LENGTH: usize = DC_NET_MESSAGE_LENGTH;

/// The size of a sealed secret key. Although the secret key is only 32-byte, the sealed version is
/// quite large and we can't go much smaller than 1024.
pub const SEALED_SGX_SIGNING_KEY_LENGTH: usize = 1024;

/// The size of a diffie hellman shared secret
pub const SHARED_SECRET_LENGTH: usize = 32;

/// Gets the window that this round belongs to
pub fn round_window(round: u32) -> u32 {
    let relative_round = round % DC_NET_ROUNDS_PER_WINDOW;
    (round - relative_round)
        .checked_div(DC_NET_ROUNDS_PER_WINDOW)
        .unwrap()
}

pub const ENCLAVE_LOG_LEVEL: &str = "off"; // "debug" or "info"

/// Number of threads for deriving round secrets
pub const N_THREADS_DERIVE_ROUND_SECRET: usize = 10;

/// Network communication settings
/// timeout time
pub const TIMEOUT_SEC: u64 = 20;
/// how many retries it will take before termination
pub const RETRIES: usize = 10;
