use interface::{
    EntityId,
    DcRoundMessage,
};
use ed25519_dalek::{
    SecretKey,
    PublicKey,
    Signature,
    Keypair,
    SECRET_KEY_LENGTH,
    PUBLIC_KEY_LENGTH,
    KEYPAIR_LENGTH,
    SignatureError,
};

extern crate sha2;
use sha2::{Digest, Sha256, Sha512};

use crate::types_nosgx::{
    AggregatedMessageNoSGX,
    SignableNoSGX,
    SignMutableNoSGX,
    XorNoSGX,
};

pub fn pk_to_entityid(pk: &PublicKey) -> EntityId {
    let pk_bytes: [u8; PUBLIC_KEY_LENGTH] = pk.to_bytes();
    let mut hasher = Sha256::new();
    hasher.input("anytrust_group_id");
    hasher.input(pk_bytes);

    let digest = hasher.result();

    let mut id = EntityId::default();
    id.0.copy_from_slice(&digest);
    id
}


impl SignableNoSGX for AggregatedMessageNoSGX {
    fn digest(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.input(b"Begin AggregatedMessageNoSGX");
        hasher.input(&self.anytrust_group_id);
        for id in self.user_ids.iter() {
            hasher.input(id);
        }
        hasher.input(&self.aggregated_msg.digest());
        hasher.input(b"End AggregatedMessageNoSGX");

        hasher.result().to_vec()
    }

    fn get_sig(&self) -> Signature {
        self.sig
    }

    fn get_pk(&self) -> PublicKey {
        self.pk
    }
}

impl SignMutableNoSGX for AggregatedMessageNoSGX {
    fn sign_mut(&mut self, sk: &SecretKey) -> Result<(), SignatureError> {
        let (sig, pk) = self.sign(sk)?;
        self.pk = pk;
        self.sig = sig;

        Ok(())
    }
}

impl XorNoSGX for DcRoundMessage {
    fn xor_mut_nosgx(&mut self, other: &Self) {
        assert_eq!(
            self.aggregated_msg.num_rows(),
            other.aggregated_msg.num_rows()
        );
        assert_eq!(
            self.aggregated_msg.num_columns(),
            other.aggregated_msg.num_columns()
        );

        // XOR the scheduling messages
        for (lhs, rhs) in self
            .scheduling_msg
            .as_mut_slice()
            .iter_mut()
            .zip(other.scheduling_msg.as_slice().iter())
        {
            *lhs ^= rhs;
        }

        // XOR the round messages
        for (lhs, rhs) in self
            .aggregated_msg
            .as_mut_slice()
            .iter_mut()
            .zip(other.aggregated_msg.as_slice().iter())
        {
            *lhs ^= rhs;
        }
    }
}