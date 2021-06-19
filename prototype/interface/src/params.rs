/// User id is sha-256 hash of some public key
pub const USER_ID_LENGTH: usize = 32;
pub const USER_ID_MAX_LEN: usize = 32;

/// The number of bytes in each DC net slot
pub const DC_NET_MESSAGE_LENGTH: usize = 1024;

/// The size of an anytrust shared secret
pub const SERVER_KEY_LENGTH: usize = DC_NET_MESSAGE_LENGTH;

pub const FOOTPRINT_BIT_SIZE: usize = 3;

/// The size of a sealed secret key. Although the secret key is only 32-byte, the sealed version is
/// quite large and we can't go much smaller than 640.
pub const SEALED_SGX_SIGNING_KEY_LENGTH: usize = 640;
