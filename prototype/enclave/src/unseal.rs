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
fn unseal_vec_and_deser<T: DeserializeOwned + Default>(input: &Vec<u8>) -> SgxResult<T> {
    let mut bin = input.clone();
    unsafe { unseal_ptr_and_deser(bin.as_mut_ptr(), bin.len()) }
}

unsafe fn unseal_ptr_and_deser<T: DeserializeOwned + Default>(
    input: *mut u8,
    input_len: usize,
) -> SgxResult<T> {
    if input_len == 0 {
        warn!("empty sealed data");
        return Ok(Default::default());
    }

    let sealed_data = match SgxSealedData::<[u8]>::from_raw_sealed_data_t(
        input as *mut sgx_sealed_data_t,
        input_len as u32,
    ) {
        Some(t) => t,
        None => {
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
    };

    let unsealed = sealed_data.unseal_data()?;
    let unsealed_slice = unsealed.get_decrypt_txt();
    Ok(match serde_cbor::de::from_slice(unsealed_slice) {
        Ok(t) => t,
        Err(_e) => {
            return Err(SGX_ERROR_INVALID_PARAMETER);
        }
    })
}

/// a few useful traits
pub trait Sealable {
    fn seal(&self) -> SgxResult<Vec<u8>>;
}

impl<T> Sealable for T
where
    T: Serialize,
{
    fn seal(&self) -> SgxResult<Vec<u8>> {
        ser_and_seal_to_vec(self, b"")
    }
}

pub trait SealAs<T> {
    fn seal(&self) -> SgxResult<T>;
}

pub trait UnsealableAs<T> {
    fn unseal(&self) -> SgxResult<T>;
}

pub trait UnmarshalledAs<T> {
    fn unmarshal(&self) -> SgxResult<T>;
}

pub trait MarshallAs<T> {
    fn marshal(&self) -> SgxResult<T>;
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
        if !self.0.is_empty() {
            deserialize_from_vec(&self.0)
        } else {
            Ok(AggregatedMessage {
                round: u32::max_value(),
                anytrust_group_id: Default::default(),
                user_ids: BTreeSet::new(),
                aggregated_msg: DcRoundMessage::default(),
                tee_sig: Default::default(),
                tee_pk: Default::default(),
            })
        }
    }
}

impl UnsealableAs<SgxPrivateKey> for SealedSigPrivKey {
    fn unseal(&self) -> sgx_types::SgxResult<SgxPrivateKey> {
        unseal_vec_and_deser(&self.0.sealed_sk)
    }
}

impl UnsealableAs<SgxPrivateKey> for SealedKemPrivKey {
    fn unseal(&self) -> sgx_types::SgxResult<SgxPrivateKey> {
        unseal_vec_and_deser(&self.0.sealed_sk)
    }
}

impl UnsealableAs<SgxPrivateKey> for SealedKey {
    fn unseal(&self) -> sgx_types::SgxResult<SgxPrivateKey> {
        unseal_vec_and_deser(&self.sealed_sk)
    }
}

impl UnsealableAs<SharedSecretsDb> for SealedSharedSecretDb {
    fn unseal(&self) -> sgx_types::SgxResult<SharedSecretsDb> {
        let mut db = SharedSecretsDb::default();
        for (k, v) in self.db.iter() {
            db.db.insert(k.to_owned(), unseal_vec_and_deser(&v)?);
        }

        Ok(db)
    }
}

impl UnmarshalledAs<messages_types::UnblindedAggregateShare> for UnblindedAggregateShareBlob {
    fn unmarshal(&self) -> sgx_types::SgxResult<messages_types::UnblindedAggregateShare> {
        deserialize_from_vec(&self.0)
    }
}

impl MarshallAs<UnblindedAggregateShareBlob> for messages_types::UnblindedAggregateShare {
    fn marshal(&self) -> sgx_types::SgxResult<UnblindedAggregateShareBlob> {
        Ok(UnblindedAggregateShareBlob(serialize_to_vec(&self)?))
    }
}
