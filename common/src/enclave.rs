use sgx_status_t::SGX_SUCCESS;
use sgx_types;
use sgx_types::*;
use sgx_urts;
use sgx_urts::SgxEnclave;
use std::collections::BTreeSet;
use std::path::PathBuf;

use interface::*;
use std::time::Instant;

// error type for enclave operations
use quick_error::quick_error;
use sgx_types::sgx_status_t;

quick_error! {
    #[derive(Debug)]
    pub enum EnclaveError {
        SgxError(err: sgx_status_t) {
            from(sgx_status_t)
        }
        EnclaveLogicError(err: sgx_status_t) {
            from(sgx_status_t)
        }
        MarshallError(e: serde_cbor::Error) {
            from(e: serde_cbor::Error) -> (e)
        }
    }
}

pub type EnclaveResult<T> = Result<T, EnclaveError>;

#[derive(Clone, Debug)]
pub struct DcNetEnclave {
    enclave: sgx_urts::SgxEnclave,
}

use itertools::Itertools;
use std::iter::FromIterator;
use std::sync::mpsc;
use std::thread;

use crate::ecall_wrapper::ecall_allowed;

impl DcNetEnclave {
    pub fn init(enclave_file: &'static str) -> EnclaveResult<Self> {
        let enclave_path = PathBuf::from(enclave_file);

        let mut launch_token: sgx_launch_token_t = [0; 1024];
        let mut launch_token_updated: i32 = 0;
        // call sgx_create_enclave to initialize an enclave instance
        // Debug Support: set 2nd parameter to 1
        let debug = 1;
        let mut misc_attr = sgx_misc_attribute_t {
            secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
            misc_select: 0,
        };

        let start_time = std::time::Instant::now();
        let enclave = SgxEnclave::create(
            enclave_path,
            debug,
            &mut launch_token,
            &mut launch_token_updated,
            &mut misc_attr,
        )
        .map_err(EnclaveError::SgxError)?;

        info!(
            "============== enclave created. took {}us",
            start_time.elapsed().as_micros()
        );
        Ok(Self { enclave })
    }

    pub fn destroy(self) {
        self.enclave.destroy();
    }

    /// This method can be used for creating signing keys and KEM private keys.
    /// Use unseal_to_pubkey to unseal the key and compute its public key.
    /// Returns (sealed sk, AttestedPublicKey)
    fn new_sgx_protected_key(&self, role: String) -> EnclaveResult<(Vec<u8>, AttestedPublicKey)> {
        Ok(ecall_allowed::new_sgx_keypair(self.enclave.geteid(), role)?)
    }

    /// Returns the public key corresponding to the sealed secret key
    pub fn unseal_to_public_key_on_p256(
        &self,
        sealed_private_key: &Vec<u8>,
    ) -> EnclaveResult<SgxProtectedKeyPub> {
        Ok(ecall_allowed::unseal_to_public_key(
            self.enclave.geteid(),
            sealed_private_key,
        )?)
    }

    /// Given a message, constructs a round message for sending to an aggregator
    /// SGX will
    ///     1. Check the signature on the preivous round output against a signing key (might have to change API a bit for that)
    ///     2. Check that the current round is prev_round+1
    ///     3. Use the derived slot for the given message
    ///     4. Make a new footprint reservation for this round
    ///
    /// This function returns the message as well as the ratcheted shared secrets.
    ///
    /// Error handling:
    ///
    /// If scheduling failed (e.g., due to collision) this will return
    /// Err(EnclaveLogicError(SGX_ERROR_SERVICE_UNAVAILABLE)). Higher level application should
    /// retry, for example, in the next round.
    pub fn user_submit_round_msg(
        &self,
        submission_req: &UserSubmissionReq,
        sealed_usk: &SealedSigPrivKey,
    ) -> EnclaveResult<(RoundSubmissionBlob, SealedSharedSecretDb)> {
        Ok(ecall_allowed::user_submit(
            self.enclave.geteid(),
            (submission_req, sealed_usk),
        )?)
    }

    /// Makes an empty aggregation state for the given round and wrt the given anytrust nodes
    pub fn new_aggregate(
        &self,
        _round: u32,
        _anytrust_group_id: &EntityId,
    ) -> EnclaveResult<SignedPartialAggregate> {
        // A new aggregator is simply an empty blob
        Ok(Default::default())
    }

    /// Adds the given input from a user to the given partial aggregate
    /// Note: if marshalled_current_aggregation is empty (len = 0), an empty aggregation is created
    ///  and the signed message is aggregated into that.
    pub fn add_to_aggregate(
        &self,
        agg: &mut SignedPartialAggregate,
        observed_nonces: &mut Option<BTreeSet<RateLimitNonce>>,
        new_input: &RoundSubmissionBlob,
        signing_key: &SealedSigPrivKey,
    ) -> EnclaveResult<()> {
        let (new_agg, new_observed_nonces) = ecall_allowed::add_to_agg(
            self.enclave.geteid(),
            (new_input, agg, observed_nonces, signing_key),
        )?;

        // Update the agg and nonces
        *agg = new_agg;
        *observed_nonces = new_observed_nonces;

        Ok(())
    }

    /// Constructs an aggregate message from the given state. The returned blob is to be sent to
    /// the parent aggregator or an anytrust server.
    /// Note: this is an identity function because SignedPartialAggregate and RoundSubmissionBlob
    /// are exact the same thing.
    pub fn finalize_aggregate(
        &self,
        agg: &SignedPartialAggregate,
    ) -> EnclaveResult<RoundSubmissionBlob> {
        return Ok(agg.clone());
    }

    /// XORs the shared secrets into the given aggregate. Returns the server's share of the
    /// unblinded aggregate as well as the ratcheted shared secrets.
    ///
    /// This is invoked by the root anytrust server.
    pub fn unblind_aggregate_single_thread(
        &self,
        toplevel_agg: &RoundSubmissionBlob,
        signing_key: &SealedSigPrivKey,
        shared_secrets: &SealedSharedSecretDb,
    ) -> EnclaveResult<(UnblindedAggregateShareBlob, SealedSharedSecretDb)> {
        ecall_allowed::unblind_aggregate(
            self.enclave.geteid(),
            (toplevel_agg, signing_key, shared_secrets),
        )
    }

    /// The multi thread version
    pub fn unblind_aggregate_mt(
        &self,
        toplevel_agg: &AggregatedMessage,
        signing_key: &SealedSigPrivKey,
        shared_secrets: &SealedSharedSecretDb,
        n_threads: usize,
    ) -> EnclaveResult<(UnblindedAggregateShareBlob, SealedSharedSecretDb)> {
        let start = Instant::now();
        let chunk_size = (toplevel_agg.user_ids.len() + n_threads - 1) / n_threads;
        assert_ne!(chunk_size, 0);

        let eid = self.enclave.geteid();
        let round = shared_secrets.round;

        // make a mpsc channel
        let (tx, rx) = mpsc::channel();

        // // partition the user ids into N batches
        let user_keys: Vec<EntityId> = toplevel_agg.user_ids.iter().cloned().collect();
        for uks in &user_keys.into_iter().chunks(chunk_size) {
            let uks_vec = uks.collect_vec();

            let db_cloned = shared_secrets.clone();
            let tx_cloned = mpsc::Sender::clone(&tx);

            thread::spawn(move || {
                info!("thread working on {} ids", uks_vec.len());
                let user_ids: BTreeSet<EntityId> = BTreeSet::from_iter(uks_vec.into_iter());
                let rs =
                    ecall_allowed::unblind_aggregate_partial(eid, (round, &db_cloned, &user_ids))
                        .unwrap();
                tx_cloned.send(rs).unwrap();
            });
        }

        info!("========= set up threads after {:?}", start.elapsed());

        drop(tx);

        let round_secrets: Vec<RoundSecret> = rx.iter().collect();
        info!("========= threads join after {:?}", start.elapsed());

        let result = ecall_allowed::unblind_aggregate_merge(
            self.enclave.geteid(),
            (toplevel_agg, &round_secrets, signing_key, shared_secrets),
        );

        info!(
            "========= {} round secrets merged after {:?}.",
            round_secrets.len(),
            start.elapsed()
        );

        result
    }

    /// The multi thread version, with parameters taken from config file
    pub fn unblind_aggregate(
        &self,
        toplevel_agg: &AggregatedMessage,
        signing_key: &SealedSigPrivKey,
        shared_secrets: &SealedSharedSecretDb,
    ) -> EnclaveResult<(UnblindedAggregateShareBlob, SealedSharedSecretDb)> {
        self.unblind_aggregate_mt(
            toplevel_agg,
            signing_key,
            shared_secrets,
            interface::N_THREADS_DERIVE_ROUND_SECRET,
        )
    }

    /// The insecure version for performance evaluation. This ecall leaks the OTPs to the untrusted world so it defeats
    /// the security of SGX
    pub fn unblind_aggregate_insecure(
        &self,
        toplevel_agg: &AggregatedMessage,
        signing_key: &SealedSigPrivKey,
        sealed_shared_secrets: &SealedSharedSecretDb,
        n_threads: usize,
    ) -> EnclaveResult<(UnblindedAggregateShareBlob, SealedSharedSecretDb)> {
        let shared_secrets =
            ecall_allowed::leak_dh_secrets(self.enclave.geteid(), sealed_shared_secrets)?;

        let start = Instant::now();
        let chunk_size = (toplevel_agg.user_ids.len() + n_threads - 1) / n_threads;
        assert_ne!(chunk_size, 0);

        let round = shared_secrets.round;

        // make a mpsc channel
        let (tx, rx) = mpsc::channel();

        // // partition the user ids into N batches
        let user_keys: Vec<EntityId> = toplevel_agg.user_ids.iter().cloned().collect();
        for uks in &user_keys.into_iter().chunks(chunk_size) {
            let uks_vec = uks.collect_vec();

            let db_cloned = shared_secrets.clone();
            let tx_cloned = mpsc::Sender::clone(&tx);

            thread::spawn(move || {
                info!("thread working on {} ids", uks_vec.len());

                let rs = crate::aes_prng::derive_round_secret_for_userset(
                    round,
                    &db_cloned,
                    &BTreeSet::from_iter(uks_vec.into_iter()),
                );

                tx_cloned.send(rs).unwrap();
            });
        }

        info!("========= set up threads after {:?}", start.elapsed());

        drop(tx);

        let round_secrets: Vec<RoundSecret> = rx.iter().collect();
        info!("========= threads join after {:?}", start.elapsed());

        let result = ecall_allowed::unblind_aggregate_merge(
            self.enclave.geteid(),
            (
                toplevel_agg,
                &round_secrets,
                signing_key,
                sealed_shared_secrets,
            ),
        );

        info!(
            "========= {} round secrets merged after {:?}.",
            round_secrets.len(),
            start.elapsed()
        );

        result
    }

    /// Derives the final round output given all the shares of the unblinded aggregates
    pub fn derive_round_output(
        &self,
        sealed_sig_sk: &SealedSigPrivKey,
        server_aggs: &[UnblindedAggregateShareBlob],
    ) -> EnclaveResult<RoundOutput> {
        ecall_allowed::derive_round_output(self.enclave.geteid(), (sealed_sig_sk, server_aggs))
    }

    /// Create a new TEE protected secret key. Derives shared secrets with all the given KEM pubkeys.
    /// This function
    /// 1. Verify the enclave attestations on the packages
    /// 2. Use the KEM pubkeys to derive the shared secrets.
    /// TODO: what should it do with the signing keys?
    pub fn new_user(
        &self,
        server_pks: &[ServerPubKeyPackage],
    ) -> EnclaveResult<(
        SealedSharedSecretDb,
        SealedSigPrivKey,
        EntityId,
        UserRegistrationBlob,
    )> {
        let u = ecall_allowed::new_user(self.enclave.geteid(), server_pks)?;
        Ok((u.0, u.1, EntityId::from(&u.2), u.2))
    }

    /// Create a new TEE protected secret key for an aggregator.
    /// Returns sealed private key, entity id, and an AggRegistrationBlob that contains the
    /// attestation information to send to anytrust nodes.
    pub fn new_aggregator(
        &self,
    ) -> EnclaveResult<(SealedSigPrivKey, EntityId, AggRegistrationBlob)> {
        let (sealed_sk, attested_pk) = self.new_sgx_protected_key("agg".to_string())?;
        Ok((
            SealedSigPrivKey(sealed_sk),
            EntityId::from(&attested_pk.pk),
            AggRegistrationBlob(attested_pk),
        ))
    }

    /// Create new TEE protected secret keys. Returns ServerRegistrationBlob that contains the
    /// pubkey and attestation information to send to other anytrust nodes.
    pub fn new_server(
        &self,
    ) -> EnclaveResult<(
        SealedSigPrivKey,
        SealedKemPrivKey,
        EntityId,
        ServerRegistrationBlob,
    )> {
        let s = ecall_allowed::new_server(self.enclave.geteid(), ())?;

        Ok((s.0, s.1, EntityId::from(&s.2), s.2))
    }

    /// Verifies and adds the given user registration blob to the database of pubkeys and
    /// shared secrets
    /// Called by a server
    pub fn recv_user_registration(
        &self,
        pubkeys: &mut SignedPubKeyDb,
        shared_secrets: &mut SealedSharedSecretDb,
        decap_key: &SealedKemPrivKey,
        input_blob: &UserRegistrationBlob,
    ) -> EnclaveResult<()> {
        let (new_pubkey_db, new_secrets_db) = ecall_allowed::recv_user_reg(
            self.enclave.geteid(),
            (pubkeys, shared_secrets, decap_key, input_blob),
        )?;

        pubkeys.users.clear();
        pubkeys.users.extend(new_pubkey_db.users);

        shared_secrets.db.clear();
        shared_secrets.db.extend(new_secrets_db.db);

        Ok(())
    }

    pub fn recv_user_registration_batch(
        &self,
        pubkeys: &mut SignedPubKeyDb,
        shared_secrets: &mut SealedSharedSecretDb,
        decap_key: &SealedKemPrivKey,
        input_blob: &[UserRegistrationBlob],
    ) -> EnclaveResult<()> {
        let (new_pubkey_db, new_secrets_db) = ecall_allowed::recv_user_reg_batch(
            self.enclave.geteid(),
            (pubkeys, decap_key, input_blob),
        )?;

        pubkeys.users = new_pubkey_db.users;
        shared_secrets.db = new_secrets_db.db;

        Ok(())
    }

    /// Verifies and adds the given aggregator registration blob to the database of pubkeys
    pub fn recv_aggregator_registration(
        &self,
        pubkeys: &mut SignedPubKeyDb,
        input_blob: &AggRegistrationBlob,
    ) -> EnclaveResult<()> {
        let new_db = ecall_allowed::recv_aggregator_registration(
            self.enclave.geteid(),
            (pubkeys, input_blob),
        )?;

        pubkeys.aggregators.clear();
        pubkeys.aggregators.extend(new_db.aggregators);

        Ok(())
    }

    /// Verifies and adds the given server registration blob to the database of pubkeys
    pub fn recv_server_registration(
        &self,
        pubkeys: &mut SignedPubKeyDb,
        input_blob: &ServerRegistrationBlob,
    ) -> EnclaveResult<()> {
        let new_db =
            ecall_allowed::recv_server_registration(self.enclave.geteid(), (pubkeys, input_blob))?;

        pubkeys.servers.clear();
        pubkeys.servers.extend(new_db.servers);

        Ok(())
    }

    pub fn run_enclave_tests(&self) -> SgxError {
        let mut retval = SGX_SUCCESS;
        unsafe {
            test_main_entrance(self.enclave.geteid(), &mut retval);
        }
        if retval != SGX_SUCCESS {
            return Err(retval);
        }
        Ok(())
    }
}

extern "C" {
    fn test_main_entrance(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
}
