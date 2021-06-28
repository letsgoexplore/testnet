use crypto::SgxSignature;
use interface::{DcMessage, EntityId, SgxSigningPubKey};

#[serde(crate = "serde")]
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedUserMessage {
    pub user_id: EntityId,
    pub anytrust_group_id: EntityId,
    pub round: u32,
    pub msg: DcMessage,
    pub tee_sig: SgxSignature,
    pub tee_pk: SgxSigningPubKey,
}
