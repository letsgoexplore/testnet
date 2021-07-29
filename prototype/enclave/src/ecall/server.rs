use interface::*;
use sgx_types::SgxResult;

/// This file implements ecalls used by an anytrust server


pub fn recv_user_registration(input: &(SignedPubKeyDb, SealedSharedSecretDb, SealedKemPrivKey, UserRegistrationBlob))
-> SgxResult<(SignedPubKeyDb, SealedSharedSecretDb)> {
    unimplemented!()
}