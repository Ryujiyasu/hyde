use tss_esapi::{
    constants::{SessionType, StartupType},
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    handles::{KeyHandle, PersistentTpmHandle, TpmHandle},
    interface_types::{
        algorithm::HashingAlgorithm,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        KeyedHashScheme, Private, Public, PublicBuilder,
        PublicKeyedHashParameters, RsaExponent, SensitiveData,
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

pub struct TpmBackend {
    context: Context,
    primary_handle: Option<KeyHandle>,
}

impl TpmBackend {
    pub fn new() -> Result<Self> {
        let tcti = TctiNameConf::from_environment_variable()
            .or_else(|_| "swtpm".parse::<TctiNameConf>())
            .unwrap_or(TctiNameConf::Device(Default::default()));

        let mut context = Context::new(tcti).map_err(tpm_err)?;

        // Startup the TPM (idempotent — ignored if already started)
        let _ = context.startup(StartupType::Clear);

        // Set up HMAC auth session with encrypt + decrypt
        setup_session(&mut context)?;

        Ok(Self {
            context,
            primary_handle: None,
        })
    }
}

fn setup_session(context: &mut Context) -> Result<()> {
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

    let (attrs, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();

    context
        .tr_sess_set_attributes(session.unwrap(), attrs, mask)
        .map_err(tpm_err)?;

    context.set_sessions((session, None, None));
    Ok(())
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

/// Build the public template for a sealed data object.
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

        // Seal the key material under the Primary Key
        let result = self
            .context
            .create(parent, sealed_object_template(), None, Some(sensitive), None, None)
            .map_err(tpm_err)?;

        let blob = encode_sealed_blobs(&result.out_private, &result.out_public);

        Ok(WrappedKey {
            blob,
            backend: BackendType::Tpm,
        })
    }

    fn seal(&mut self, key: &WrappedKey, data: &[u8]) -> Result<Vec<u8>> {
        let parent = self.primary_handle.ok_or(VeilError::PrimaryKeyNotFound)?;
        let (private, public) = decode_sealed_blobs(&key.blob)?;

        // Load sealed object, unseal to get Data Key, then flush
        let loaded = self.context.load(parent, private, public).map_err(tpm_err)?;
        let obj_handle: tss_esapi::handles::ObjectHandle = loaded.into();
        let unsealed = self.context.unseal(obj_handle).map_err(tpm_err)?;
        // unseal consumes the loaded object, but we flush to be safe
        let _ = self.context.flush_context(obj_handle);

        let mut data_key: Vec<u8> = unsealed.to_vec();
        let result = aes_gcm_encrypt(&data_key, data);
        zeroize::Zeroize::zeroize(&mut data_key);
        result
    }

    fn unseal(&mut self, key: &WrappedKey, sealed: &[u8]) -> Result<Vec<u8>> {
        let parent = self.primary_handle.ok_or(VeilError::PrimaryKeyNotFound)?;
        let (private, public) = decode_sealed_blobs(&key.blob)?;

        // Load sealed object, unseal to get Data Key, then flush
        let loaded = self.context.load(parent, private, public).map_err(tpm_err)?;
        let obj_handle: tss_esapi::handles::ObjectHandle = loaded.into();
        let unsealed = self.context.unseal(obj_handle).map_err(tpm_err)?;
        let _ = self.context.flush_context(obj_handle);

        let mut data_key: Vec<u8> = unsealed.to_vec();
        let result = aes_gcm_decrypt(&data_key, sealed);
        zeroize::Zeroize::zeroize(&mut data_key);
        result
    }

    fn backup(&mut self, key: &WrappedKey, passphrase: &[u8]) -> Result<Vec<u8>> {
        // Encrypt the WrappedKey blob with a passphrase-derived key (Argon2id + AES-256-GCM).
        // This allows recovery on a different device if the TPM is lost.
        let mut derived_key = derive_key_from_passphrase(passphrase)?;
        let result = aes_gcm_encrypt(&derived_key.key, &key.blob);
        zeroize::Zeroize::zeroize(&mut derived_key.key);

        let encrypted = result?;

        // Output: [16 bytes salt] [encrypted blob (nonce + ciphertext + tag)]
        let mut output = Vec::with_capacity(16 + encrypted.len());
        output.extend_from_slice(&derived_key.salt);
        output.extend_from_slice(&encrypted);
        Ok(output)
    }

    fn restore(&mut self, backup: &[u8], passphrase: &[u8]) -> Result<WrappedKey> {
        if backup.len() < 16 + 12 + 16 {
            // Need at least: 16 salt + 12 nonce + 16 tag
            return Err(VeilError::RecoveryFailed("backup too short".into()));
        }

        let salt = &backup[..16];
        let encrypted = &backup[16..];

        let mut derived_key = derive_key_with_salt(passphrase, salt)?;
        let blob = aes_gcm_decrypt(&derived_key.key, encrypted)
            .map_err(|_| VeilError::RecoveryFailed("wrong passphrase or corrupted backup".into()));
        zeroize::Zeroize::zeroize(&mut derived_key.key);

        let blob = blob?;
        Ok(WrappedKey {
            blob,
            backend: BackendType::Tpm,
        })
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

// ---------------------------------------------------------------------------
// Helpers: Argon2id passphrase key derivation
// ---------------------------------------------------------------------------

struct DerivedKey {
    key: Vec<u8>,
    salt: [u8; 16],
}

fn derive_key_from_passphrase(passphrase: &[u8]) -> Result<DerivedKey> {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt)
        .map_err(|e| VeilError::RecoveryFailed(format!("random salt generation failed: {e}")))?;
    derive_key_with_salt(passphrase, &salt)
}

fn derive_key_with_salt(passphrase: &[u8], salt: &[u8]) -> Result<DerivedKey> {
    use argon2::Argon2;

    let mut key = vec![0u8; 32];
    let argon2 = Argon2::default(); // Argon2id with default params
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| VeilError::RecoveryFailed(format!("key derivation failed: {e}")))?;

    let mut salt_arr = [0u8; 16];
    salt_arr.copy_from_slice(&salt[..16]);

    Ok(DerivedKey {
        key,
        salt: salt_arr,
    })
}
