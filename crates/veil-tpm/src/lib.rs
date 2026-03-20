use tss_esapi::{
    constants::{SessionType, StartupType},
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    handles::{KeyHandle, PersistentTpmHandle, SessionHandle, TpmHandle},
    interface_types::{
        algorithm::HashingAlgorithm,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Digest, KeyedHashScheme, PcrSelectionList, PcrSlot, Private, Public,
        PublicBuilder, PublicKeyedHashParameters, RsaExponent, SensitiveData,
        SymmetricDefinition, SymmetricDefinitionObject,
    },
    tcti_ldr::TctiNameConf,
    traits::{Marshall, UnMarshall},
    utils, Context,
};
use veil_core::{
    backend::{BackendType, TeeBackend, WrappedKey},
    error::{Result, VeilError},
};

/// Persistent handle address for veil's Primary Key: 0x81000001
const PERSISTENT_HANDLE_ADDR: u32 = 0x81000001;

fn tpm_err(e: tss_esapi::Error) -> VeilError {
    VeilError::Backend(Box::new(e))
}

/// PCR binding policy for sealed objects.
#[derive(Debug, Clone)]
pub enum PcrPolicy {
    /// No PCR binding (current PCR values are not checked on unseal).
    None,
    /// Bind sealed objects to current values of specified PCR slots.
    Bind(Vec<PcrSlot>),
}

impl PcrPolicy {
    /// Default production policy: bind to PCR 0 (firmware) and PCR 7 (Secure Boot).
    pub fn default_production() -> Self {
        PcrPolicy::Bind(vec![PcrSlot::Slot0, PcrSlot::Slot7])
    }
}

pub struct TpmBackend {
    context: Context,
    primary_handle: Option<KeyHandle>,
    hmac_session: Option<AuthSession>,
    pcr_policy: PcrPolicy,
}

impl TpmBackend {
    /// Create a TpmBackend with no PCR binding (backward-compatible default).
    pub fn new() -> Result<Self> {
        Self::with_pcr_policy(PcrPolicy::None)
    }

    /// Create a TpmBackend with a specified PCR policy.
    pub fn with_pcr_policy(pcr_policy: PcrPolicy) -> Result<Self> {
        let tcti = TctiNameConf::from_environment_variable()
            .or_else(|_| "swtpm".parse::<TctiNameConf>())
            .unwrap_or(TctiNameConf::Device(Default::default()));

        let mut context = Context::new(tcti).map_err(tpm_err)?;

        // Startup the TPM (idempotent — ignored if already started)
        let _ = context.startup(StartupType::Clear);

        // Set up HMAC auth session with encrypt + decrypt
        let hmac_session = setup_session(&mut context)?;

        Ok(Self {
            context,
            primary_handle: None,
            hmac_session: Some(hmac_session),
            pcr_policy,
        })
    }
}

fn setup_session(context: &mut Context) -> Result<AuthSession> {
    let session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(tpm_err)?;

    let auth_session = session.unwrap();

    let (attrs, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();

    context
        .tr_sess_set_attributes(auth_session, attrs, mask)
        .map_err(tpm_err)?;

    context.set_sessions((session, None, None));
    Ok(auth_session)
}

/// Build the public template for our Primary Key (RSA-2048 storage key).
fn primary_key_template() -> Public {
    utils::create_restricted_decryption_rsa_public(
        SymmetricDefinitionObject::AES_256_CFB,
        RsaKeyBits::Rsa2048,
        RsaExponent::default(),
    )
    .expect("Failed to create primary key template")
}

/// Build the public template for a sealed data object (no PCR policy).
fn sealed_object_template() -> Public {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_no_da(true)
        .with_user_with_auth(true)
        .build()
        .expect("sealed object attributes");

    PublicBuilder::new()
        .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
            KeyedHashScheme::Null,
        ))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()
        .expect("sealed object template")
}

/// Build the public template for a sealed data object with a PCR policy.
/// Objects created with this template can only be unsealed via a policy session
/// that satisfies the PCR policy.
fn sealed_object_template_with_policy(policy_digest: &Digest) -> Public {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_no_da(true)
        // No user_with_auth — must use policy session to unseal
        .build()
        .expect("sealed object attributes");

    PublicBuilder::new()
        .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_auth_policy(policy_digest.clone())
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
            KeyedHashScheme::Null,
        ))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()
        .expect("sealed object template with policy")
}

/// Build a PcrSelectionList for the given PCR slots using SHA-256.
fn build_pcr_selection(slots: &[PcrSlot]) -> Result<PcrSelectionList> {
    PcrSelectionList::builder()
        .with_selection(HashingAlgorithm::Sha256, slots)
        .build()
        .map_err(tpm_err)
}

impl TpmBackend {
    /// Compute the PCR policy digest by running a trial session.
    /// This digest is embedded in the sealed object's authPolicy.
    fn compute_pcr_policy_digest(&mut self, slots: &[PcrSlot]) -> Result<Digest> {
        // Trial session: computes the policy digest without enforcing
        let trial_session = self
            .context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(tpm_err)?
            .ok_or_else(|| VeilError::Backend("failed to create trial session".into()))?;

        let policy_session: PolicySession = trial_session
            .try_into()
            .map_err(tpm_err)?;

        let pcr_selection = build_pcr_selection(slots)?;

        // Empty digest = TPM uses current PCR values to compute the policy
        self.context
            .policy_pcr(policy_session, Digest::default(), pcr_selection)
            .map_err(tpm_err)?;

        let digest = self
            .context
            .policy_get_digest(policy_session)
            .map_err(tpm_err)?;

        self.context
            .flush_context(SessionHandle::from(trial_session).into())
            .map_err(tpm_err)?;

        Ok(digest)
    }

    /// Unseal a Data Key using a policy session that satisfies the PCR policy.
    fn unseal_with_pcr_policy(
        &mut self,
        parent: KeyHandle,
        private: Private,
        public: Public,
        slots: &[PcrSlot],
    ) -> Result<Vec<u8>> {
        // Load the sealed object (uses HMAC session — load doesn't require policy)
        let loaded = self
            .context
            .load(parent, private, public)
            .map_err(tpm_err)?;
        let obj_handle: tss_esapi::handles::ObjectHandle = loaded.into();

        // Create a real policy session
        let policy_auth = self
            .context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(tpm_err)?
            .ok_or_else(|| VeilError::Backend("failed to create policy session".into()))?;

        let policy_session: PolicySession = policy_auth
            .try_into()
            .map_err(tpm_err)?;

        let pcr_selection = build_pcr_selection(slots)?;

        // Assert PolicyPCR — TPM reads current PCR values and extends the policy digest.
        // If current PCRs don't match what was baked into the object's authPolicy,
        // the unseal will fail.
        self.context
            .policy_pcr(policy_session, Digest::default(), pcr_selection)
            .map_err(|_| {
                let _ = self.context.flush_context(obj_handle);
                let _ = self.context.flush_context(SessionHandle::from(policy_auth).into());
                VeilError::SealMismatch
            })?;

        // Switch to policy session for unseal
        self.context
            .set_sessions((Some(policy_auth), None, None));

        let unseal_result = self.context.unseal(obj_handle);

        // Restore HMAC session
        self.context
            .set_sessions((self.hmac_session.map(Into::into), None, None));

        // Clean up
        let _ = self.context.flush_context(obj_handle);
        let _ = self.context.flush_context(SessionHandle::from(policy_auth).into());

        let unsealed = unseal_result.map_err(|_| VeilError::SealMismatch)?;
        Ok(unsealed.to_vec())
    }

    /// Unseal a Data Key using the HMAC session (no PCR policy).
    fn unseal_without_policy(
        &mut self,
        parent: KeyHandle,
        private: Private,
        public: Public,
    ) -> Result<Vec<u8>> {
        let loaded = self
            .context
            .load(parent, private, public)
            .map_err(tpm_err)?;
        let obj_handle: tss_esapi::handles::ObjectHandle = loaded.into();
        let unsealed = self.context.unseal(obj_handle).map_err(tpm_err)?;
        let _ = self.context.flush_context(obj_handle);
        Ok(unsealed.to_vec())
    }

    /// Unseal a Data Key, dispatching based on the configured PCR policy.
    fn unseal_data_key(&mut self, key: &WrappedKey) -> Result<Vec<u8>> {
        let parent = self.primary_handle.ok_or(VeilError::PrimaryKeyNotFound)?;
        let (private, public) = decode_sealed_blobs(&key.blob)?;

        match &self.pcr_policy {
            PcrPolicy::None => self.unseal_without_policy(parent, private, public),
            PcrPolicy::Bind(slots) => {
                let slots = slots.clone();
                self.unseal_with_pcr_policy(parent, private, public, &slots)
            }
        }
    }
}

impl TeeBackend for TpmBackend {
    fn is_available() -> bool {
        #[cfg(target_os = "linux")]
        {
            std::path::Path::new("/dev/tpm0").exists()
                || std::path::Path::new("/dev/tpmrm0").exists()
                || std::net::TcpStream::connect("127.0.0.1:2321").is_ok()
        }
        #[cfg(target_os = "windows")]
        {
            true
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            false
        }
    }

    fn initialize_primary_key(&mut self) -> Result<()> {
        let persistent_tpm_handle = PersistentTpmHandle::new(PERSISTENT_HANDLE_ADDR)
            .map_err(|e| VeilError::Backend(Box::new(e)))?;

        // Try to load existing persistent handle
        let existing = self.context.execute_without_session(|ctx| {
            ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
        });

        match existing {
            Ok(obj_handle) => {
                self.primary_handle = Some(KeyHandle::from(obj_handle));
                tracing::info!("Loaded existing primary key from 0x{:08X}", PERSISTENT_HANDLE_ADDR);
                Ok(())
            }
            Err(_) => {
                tracing::info!("Creating new primary key...");

                let result = self
                    .context
                    .create_primary(Hierarchy::Owner, primary_key_template(), None, None, None, None)
                    .map_err(tpm_err)?;

                let transient_handle = result.key_handle;

                // Persist it
                let persistent = tss_esapi::interface_types::dynamic_handles::Persistent::Persistent(
                    persistent_tpm_handle,
                );
                self.context
                    .evict_control(
                        tss_esapi::interface_types::resource_handles::Provision::Owner,
                        transient_handle.into(),
                        persistent,
                    )
                    .map_err(tpm_err)?;

                // Flush transient copy
                self.context
                    .flush_context(transient_handle.into())
                    .map_err(tpm_err)?;

                // Load the persistent handle
                let obj_handle = self.context.execute_without_session(|ctx| {
                    ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
                }).map_err(tpm_err)?;

                self.primary_handle = Some(KeyHandle::from(obj_handle));
                tracing::info!("Primary key persisted at 0x{:08X}", PERSISTENT_HANDLE_ADDR);
                Ok(())
            }
        }
    }

    fn generate_data_key(&mut self) -> Result<WrappedKey> {
        let parent = self.primary_handle.ok_or(VeilError::PrimaryKeyNotFound)?;

        // Generate 32 bytes of random data from the TPM as our Data Key
        let key_material = self.context.get_random(32).map_err(tpm_err)?;
        let key_bytes: Vec<u8> = key_material.to_vec();

        let sensitive = SensitiveData::try_from(key_bytes)
            .map_err(|e| VeilError::Backend(Box::new(e)))?;

        // Choose template based on PCR policy
        let template = match &self.pcr_policy {
            PcrPolicy::None => sealed_object_template(),
            PcrPolicy::Bind(slots) => {
                let slots = slots.clone();
                let policy_digest = self.compute_pcr_policy_digest(&slots)?;
                sealed_object_template_with_policy(&policy_digest)
            }
        };

        // Seal the key material under the Primary Key (with or without PCR policy)
        let result = self
            .context
            .create(parent, template, None, Some(sensitive), None, None)
            .map_err(tpm_err)?;

        let blob = encode_sealed_blobs(&result.out_private, &result.out_public);

        Ok(WrappedKey {
            blob,
            backend: BackendType::Tpm,
        })
    }

    fn seal(&mut self, key: &WrappedKey, data: &[u8]) -> Result<Vec<u8>> {
        let mut data_key = self.unseal_data_key(key)?;
        let result = aes_gcm_encrypt(&data_key, data);
        zeroize::Zeroize::zeroize(&mut data_key);
        result
    }

    fn unseal(&mut self, key: &WrappedKey, sealed: &[u8]) -> Result<Vec<u8>> {
        let mut data_key = self.unseal_data_key(key)?;
        let result = aes_gcm_decrypt(&data_key, sealed);
        zeroize::Zeroize::zeroize(&mut data_key);
        result
    }

    fn backend_type(&self) -> BackendType {
        BackendType::Tpm
    }
}

// ---------------------------------------------------------------------------
// Helpers: sealed blob serialization
// ---------------------------------------------------------------------------

fn encode_sealed_blobs(private: &Private, public: &Public) -> Vec<u8> {
    let priv_bytes: Vec<u8> = private.to_vec();
    let pub_bytes = public.marshall().expect("marshal public");
    let mut buf = Vec::with_capacity(4 + priv_bytes.len() + pub_bytes.len());
    buf.extend_from_slice(&(priv_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&priv_bytes);
    buf.extend_from_slice(&pub_bytes);
    buf
}

fn decode_sealed_blobs(blob: &[u8]) -> Result<(Private, Public)> {
    if blob.len() < 4 {
        return Err(VeilError::InvalidKey);
    }
    let priv_len = u32::from_le_bytes(blob[..4].try_into().unwrap()) as usize;
    if blob.len() < 4 + priv_len {
        return Err(VeilError::InvalidKey);
    }
    let priv_bytes = &blob[4..4 + priv_len];
    let pub_bytes = &blob[4 + priv_len..];

    let private = Private::try_from(priv_bytes).map_err(tpm_err)?;
    let public = Public::unmarshall(pub_bytes).map_err(tpm_err)?;

    Ok((private, public))
}

// ---------------------------------------------------------------------------
// Helpers: AES-256-GCM
// ---------------------------------------------------------------------------

fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, aead::OsRng, Aes256Gcm, AeadCore, KeyInit};

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VeilError::Serialization(e.to_string()))?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| VeilError::SealMismatch)?;

    // Output: [12 bytes nonce] [ciphertext + tag]
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn aes_gcm_decrypt(key: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    if sealed.len() < 12 {
        return Err(VeilError::InvalidKey);
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VeilError::Serialization(e.to_string()))?;

    let nonce = Nonce::from_slice(&sealed[..12]);
    let ciphertext = &sealed[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VeilError::SealMismatch)
}
