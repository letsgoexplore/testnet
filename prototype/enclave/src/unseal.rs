use crate::types::MarshallAs;
use crypto::SgxPrivateKey;
use crypto::SharedSecretsDb;
use interface::*;
use messages_types;
use messages_types::AggregatedMessage;
use sgx_types::SgxResult;
use std::borrow::ToOwned;
use std::collections::BTreeSet;
use types::UnmarshallableAs;
use types::UnsealableAs;
use utils;

impl UnmarshallableAs<AggregatedMessage> for RoundSubmissionBlob {
    fn unmarshal(&self) -> sgx_types::SgxResult<AggregatedMessage> {
        utils::deserialize_from_vec(&self.0)
    }
}

impl MarshallAs<RoundSubmissionBlob> for messages_types::AggregatedMessage {
    fn marshal(&self) -> SgxResult<RoundSubmissionBlob> {
        Ok(RoundSubmissionBlob(utils::serialize_to_vec(&self)?))
    }
}

impl UnmarshallableAs<AggregatedMessage> for SignedPartialAggregate {
    fn unmarshal(&self) -> sgx_types::SgxResult<AggregatedMessage> {
        if !self.0.is_empty() {
            utils::deserialize_from_vec(&self.0)
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
        utils::unseal_vec_and_deser(&self.0.sealed_sk)
    }
}

impl UnsealableAs<SgxPrivateKey> for SealedKemPrivKey {
    fn unseal(&self) -> sgx_types::SgxResult<SgxPrivateKey> {
        utils::unseal_vec_and_deser(&self.0.sealed_sk)
    }
}

impl UnsealableAs<SharedSecretsDb> for SealedSharedSecretDb {
    fn unseal(&self) -> sgx_types::SgxResult<SharedSecretsDb> {
        let mut db = SharedSecretsDb::default();
        for (k, v) in self.db.iter() {
            db.db.insert(k.to_owned(), utils::unseal_vec_and_deser(&v)?);
        }

        Ok(db)
    }
}

impl UnmarshallableAs<messages_types::UnblindedAggregateShare> for UnblindedAggregateShareBlob {
    fn unmarshal(&self) -> sgx_types::SgxResult<messages_types::UnblindedAggregateShare> {
        utils::deserialize_from_vec(&self.0)
    }
}

impl MarshallAs<UnblindedAggregateShareBlob> for messages_types::UnblindedAggregateShare {
    fn marshal(&self) -> sgx_types::SgxResult<UnblindedAggregateShareBlob> {
        Ok(UnblindedAggregateShareBlob(utils::serialize_to_vec(&self)?))
    }
}
