use crypto::SgxPrivateKey;
use crypto::SharedSecretsDb;
use interface::*;
use messages_types;
use messages_types::AggregatedMessage;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_cbor;
use sgx_tseal::SgxSealedData;
use sgx_types::sgx_status_t::{SGX_ERROR_INVALID_PARAMETER, SGX_ERROR_UNEXPECTED};
use sgx_types::{sgx_sealed_data_t, SgxError, SgxResult};
use std::borrow::ToOwned;
use std::collections::BTreeSet;
use std::vec::Vec;

fn serialize_to_vec<T: Serialize>(v: &T) -> SgxResult<Vec<u8>> {
    serde_cbor::to_vec(v).map_err(|e| {
        println!("can't serialize_to_vec {}", e);
        SGX_ERROR_UNEXPECTED
    })
}

fn deserialize_from_vec<T: DeserializeOwned>(bin: &[u8]) -> SgxResult<T> {
    serde_cbor::from_slice::<T>(bin).map_err(|e| {
        println!("can't deserialize_from_vec {}", e);
        SGX_ERROR_INVALID_PARAMETER
    })
}

fn ser_and_seal_to_vec<T: Serialize>(a: &T, ad: &[u8]) -> SgxResult<Vec<u8>> {
    let bin = match serde_cbor::ser::to_vec(a) {
        Ok(b) => b,
        Err(e) => {
            println!("can't serialize {}", e);
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
    };

    let sealed = SgxSealedData::<[u8]>::seal_data(ad, &bin)?;
    let mut sealed_bin = vec![0u8; (sealed.get_payload_size() + 1024) as usize];
    match unsafe {
        sealed.to_raw_sealed_data_t(
            sealed_bin.as_mut_ptr() as *mut sgx_sealed_data_t,
            sealed_bin.len() as u32,
        )
    } {
        Some(_) => Ok(sealed_bin),
        None => {
            println!("can't seal. cap {}", sealed_bin.len());
            Err(SGX_ERROR_INVALID_PARAMETER)
        }
    }
}

// TODO: make input generic AsRef<[u8]>
/// Unseal bytes and unmarshal to a T. Returns (T, additional data)
fn unseal_vec_and_deser<T: DeserializeOwned + Default>(input: &Vec<u8>) -> SgxResult<(T, Vec<u8>)> {
    let mut bin = input.clone();

    let sealed_data =
        unsafe {
            match SgxSealedData::<[u8]>::from_raw_sealed_data_t(
                bin.as_mut_ptr() as *mut sgx_sealed_data_t,
                bin.len() as u32,
            ) {
                Some(t) => t,
                None => {
                    return Err(SGX_ERROR_INVALID_PARAMETER);
                }
            }
        };

    let unsealed = sealed_data.unseal_data()?;
    let unsealed_slice = unsealed.get_decrypt_txt();

    // unmarshal
    let t = match serde_cbor::de::from_slice(unsealed_slice) {
        Ok(t) => t,
        Err(_e) => {
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
    };

    Ok((t, unsealed.get_additional_txt().to_vec()))
}


/// a few useful traits
pub trait Sealable {
    fn seal(&self, ad: Some(&[u8])) -> SgxResult<Vec<u8>>;
}

/// Any serializable type can be sealed
impl<T> Sealable for T
    where
        T: Serialize,
{
    fn seal(&self, ad: Some(&[u8])) -> SgxResult<Vec<u8>> {
        ser_and_seal_to_vec(self, match ad {
            Some(ad) => ad,
            None => b"",
        })
    }
}

/// Seal and store sealed bytes in type T
pub trait SealInto<T> {
    fn seal_into(&self) -> SgxResult<T>;
}

pub trait UnsealableInto<T> {
    fn unseal_into(&self) -> SgxResult<T>;
}

/// the relationship between keys
/// SgxPrivateKey ---sealed as---> SealedKey ---wrapped as---> SealedSigPrivKey or SealedKemPrivKey

impl UnsealableInto<SgxPrivateKey> for SealedSigPrivKey {
    fn unseal_into(&self) -> sgx_types::SgxResult<SgxPrivateKey> {
        unseal_vec_and_deser(&self.0.sealed_sk).0  // ignore the ad
    }
}

impl UnsealableInto<SgxPrivateKey> for SealedKemPrivKey {
    fn unseal_into(&self) -> sgx_types::SgxResult<SgxPrivateKey> {
        unseal_vec_and_deser(&self.0.sealed_sk).0 // ignore the ad
    }
}

impl UnsealableInto<SgxPrivateKey> for SealedKeyPair {
    fn unseal_into(&self) -> sgx_types::SgxResult<SgxPrivateKey> {
        unseal_vec_and_deser(&self.sealed_sk).0
    }
}

impl SealInto<SealedSharedSecretDb> for SharedSecretsDb {
    fn seal_into(&self) -> SgxResult<SealedSharedSecretDb> {
        let mut sealed_shared_secrets = SealedSharedSecretDb::default();
        for (k, s) in self.db.iter() {
            sealed_shared_secrets.db.insert(k.to_owned(), s.seal()?);
        }

        Ok(sealed_shared_secrets)
    }
}

impl UnsealableInto<SharedSecretsDb> for SealedSharedSecretDb {
    fn unseal_into(&self) -> sgx_types::SgxResult<SharedSecretsDb> {
        let mut db = SharedSecretsDb::default();
        for (k, v) in self.db.iter() {
            db.db.insert(k.to_owned(), unseal_vec_and_deser(&v)?);
        }

        Ok(db)
    }
}


pub trait MarshallAs<T> {
    fn marshal(&self) -> SgxResult<T>;
}

pub trait UnmarshalledAs<T> {
    fn unmarshal(&self) -> SgxResult<T>;
}

impl UnmarshalledAs<AggregatedMessage> for RoundSubmissionBlob {
    fn unmarshal(&self) -> sgx_types::SgxResult<AggregatedMessage> {
        deserialize_from_vec(&self.0)
    }
}

impl MarshallAs<RoundSubmissionBlob> for messages_types::AggregatedMessage {
    fn marshal(&self) -> SgxResult<RoundSubmissionBlob> {
        Ok(RoundSubmissionBlob(serialize_to_vec(&self)?))
    }
}

impl MarshallAs<SignedPartialAggregate> for messages_types::AggregatedMessage {
    fn marshal(&self) -> SgxResult<SignedPartialAggregate> {
        Ok(SignedPartialAggregate(serialize_to_vec(&self)?))
    }
}

impl UnmarshalledAs<AggregatedMessage> for SignedPartialAggregate {
    fn unmarshal(&self) -> sgx_types::SgxResult<AggregatedMessage> {
        deserialize_from_vec(&self.0)
    }
}

impl MarshallAs<UnblindedAggregateShareBlob> for messages_types::UnblindedAggregateShare {
    fn marshal(&self) -> sgx_types::SgxResult<UnblindedAggregateShareBlob> {
        Ok(UnblindedAggregateShareBlob(serialize_to_vec(&self)?))
    }
}


impl UnmarshalledAs<messages_types::UnblindedAggregateShare> for UnblindedAggregateShareBlob {
    fn unmarshal(&self) -> sgx_types::SgxResult<messages_types::UnblindedAggregateShare> {
        deserialize_from_vec(&self.0)
    }
}
