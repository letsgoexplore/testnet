use crypto::SgxSigningKey;
use crypto::SignMutableSGX;
use interface::{RoundSecret, SgxSignature, SgxSigningPubKey, NoSgxPrivateKey};
use sgx_types::SgxError;
use sha2::Digest;
use sha2::Sha256;
use std::vec::Vec;

use interface::{UserSubmissionMessage, SignableUpdated};

impl SignMutableSGX for UserSubmissionMessage {
    fn sign_mut_sgx(&mut self, sk: &NoSgxPrivateKey) -> SgxError {
        let (sig, pk) = self.sign(sk).expect("Signing the user submission message failed");
        self.tee_pk = pk;
        self.tee_sig = sig;

        Ok(())
    }
}