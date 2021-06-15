/// User id is sha-256 hash of some public key
pub const USER_ID_LENGTH: usize = 32;
pub const USER_ID_MAX_LEN: usize = 32;

/// The number of bytes in each DC net slot
pub const DC_NET_MESSAGE_LENGTH: usize = 1024;

/// The size of an anytrust shared secret
pub const SERVER_KEY_LENGTH: usize = DC_NET_MESSAGE_LENGTH;

pub const FOOTPRINT_BIT_SIZE: usize = 3;
