use aes::Aes128;
use cipher::{BlockCipherKey, FromBlockCipher, NewBlockCipher, StreamCipher};
use ctr::{Ctr, Ctr64LE};
use rand_core::{CryptoRng, Error as RandError, RngCore, SeedableRng};

/// An RNG whose stream is an AES-CTR keystream
pub struct Aes128Rng(Ctr64LE<Aes128>);

impl RngCore for Aes128Rng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.apply_keystream(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl SeedableRng for Aes128Rng {
    type Seed = BlockCipherKey<Aes128>;

    /// The RNG is the keystream of AES-CTR(key=seed, iv=00...0), using 64-bit counters
    fn from_seed(seed: Self::Seed) -> Aes128Rng {
        let key = seed;
        let iv = BlockCipherKey::<Aes128>::default();

        let ciph = Aes128::new(&key);
        let stream = Ctr::from_block_cipher(ciph, &iv);
        Aes128Rng(stream)
    }
}

impl CryptoRng for Aes128Rng {}

use byteorder::{ByteOrder, LittleEndian};
use hkdf::Hkdf;
use interface::{DcRoundMessage, EntityId, RoundSecret, SealedSharedSecretDb};
use sha2::Sha256;
use std::collections::BTreeSet;

pub fn derive_round_secret_for_userset(
    round: u32,
    shared_secrets: &SealedSharedSecretDb,
    user_set: &BTreeSet<EntityId>,
) -> RoundSecret {
    type MyRng = Aes128Rng;

    let mut round_secret = RoundSecret::default();

    for (pk, shard_secret) in shared_secrets.db.iter() {
        // skip entries not in entity_ids_to_use
        if !user_set.contains(&EntityId::from(pk)) {
            continue;
        }

        let hk = Hkdf::<Sha256>::new(None, shard_secret.as_ref());
        // For cryptographic RNG's a seed of 256 bits is recommended, [u8; 32].
        let mut seed = <MyRng as SeedableRng>::Seed::default();

        // info contains round and window
        let mut info = [0; 32];
        let cursor = &mut info;
        LittleEndian::write_u32(cursor, round);
        hk.expand(&info, &mut seed).unwrap();

        let mut rng = MyRng::from_seed(seed);

        //copied from enclave
        fn xor_mut(a: &mut RoundSecret, other: &RoundSecret) {
            assert_eq!(a.aggregated_msg.num_rows(), other.aggregated_msg.num_rows());
            assert_eq!(
                a.aggregated_msg.num_columns(),
                other.aggregated_msg.num_columns()
            );

            // XOR the scheduling messages
            for (lhs, rhs) in a
                .scheduling_msg
                .as_mut_slice()
                .iter_mut()
                .zip(other.scheduling_msg.as_slice().iter())
            {
                *lhs ^= rhs;
            }

            // XOR the round messages
            for (lhs, rhs) in a
                .aggregated_msg
                .as_mut_slice()
                .iter_mut()
                .zip(other.aggregated_msg.as_slice().iter())
            {
                *lhs ^= rhs;
            }
        }
        xor_mut(
            &mut round_secret,
            &DcRoundMessage::rand_from_csprng(&mut rng),
        )
    }

    round_secret
}

#[cfg(test)]
mod tests {
    use super::*;

    // The size of the randomness buffer we use in tests
    const BUF_SIZE: usize = 100;

    #[test]
    fn fill_bytes() {
        // Make a seed
        let mut seed = <Aes128Rng as SeedableRng>::Seed::default();
        let seed_str = b"test fill_bytes";
        seed[..seed_str.len()].copy_from_slice(seed_str);

        // Instantiate the RNG
        let mut rng = Aes128Rng::from_seed(seed);

        // Generate bytes
        let mut buf = [0u8; BUF_SIZE];
        rng.fill_bytes(&mut buf);

        // Make sure the bytes weren't just zeros
        assert_ne!(buf, [0u8; BUF_SIZE]);
    }
}
