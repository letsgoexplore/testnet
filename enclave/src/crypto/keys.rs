use ed25519_dalek::SECRET_KEY_LENGTH;

#[derive(Copy, Clone, Default, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
pub struct SgxPrivateKey {
    pub r: [u8; SECRET_KEY_LENGTH],
}

use sgx_rand::{Rand, Rng};
impl Rand for SgxPrivateKey {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        let mut r = [0 as u8; SECRET_KEY_LENGTH];
        rng.fill_bytes(&mut r);

        SgxPrivateKey { r }
    }
}

use std::fmt::{Debug, Display, Formatter, Result};

impl Debug for SgxPrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("NoSgxPrivateKey")
            .field("r", &hex::encode(&self.r))
            .finish()
    }
}

impl Display for SgxPrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        std::write!(f, "{}", hex::encode(self.r))
    }
}

impl AsRef<[u8]> for &SgxPrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.r
    }
}

use ed25519_dalek::{PublicKey, SecretKey};
use interface::UserSubmissionMessage;
use sgx_types::sgx_status_t::SGX_ERROR_UNEXPECTED;
use sgx_types::SgxResult;

pub fn ed25519pk_from_secret(sk: &SgxPrivateKey) -> SgxResult<PublicKey> {
    let sk = SecretKey::from_bytes(&sk.r).map_err(|e| SGX_ERROR_UNEXPECTED)?;

    let pk = PublicKey::from(&sk);
    Ok(pk)
}

use crypto::CryptoResult;
use ed25519_dalek::{Keypair, Signer, KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH};
use interface::SignatureBytes;

pub fn sign_submission(
    msg: &UserSubmissionMessage,
    ssk: &SgxPrivateKey,
) -> CryptoResult<(SignatureBytes, PublicKey)> {
    let dig = msg.digest();

    // todo: expect is used
    let pk: PublicKey =
        (&SecretKey::from_bytes(&ssk.r).expect("Failed to generate pk from sk bytes")).into();
    let sk_bytes: [u8; SECRET_KEY_LENGTH] = ssk.r;
    let pk_bytes: [u8; PUBLIC_KEY_LENGTH] = pk.to_bytes();
    let mut keypair_bytes: [u8; KEYPAIR_LENGTH] = [0; KEYPAIR_LENGTH];
    keypair_bytes[..SECRET_KEY_LENGTH].copy_from_slice(&sk_bytes);
    keypair_bytes[SECRET_KEY_LENGTH..].copy_from_slice(&pk_bytes);

    let keypair: Keypair =
        Keypair::from_bytes(&keypair_bytes).expect("Failed to generate keypair from bytes");
    let sig = SignatureBytes(keypair.sign(dig.as_slice()).to_bytes().to_vec());

    Ok((sig, pk))
}
