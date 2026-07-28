use std::fmt::Write as _;

use keyring::v1::{Entry, Error as KeyringError};
use openiwan::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const CREDENTIAL_VERSION: u32 = 1;
const STORAGE_VERSION: u32 = 1;
const KEYRING_SERVICE: &str = "org.openiwan.cli";
// Windows Credential Manager limits a generic credential blob to 2,560 bytes.
// Keeping chunks smaller also leaves the format independent of platform limits.
const SECRET_CHUNK_SIZE: usize = 2_048;
const MAX_CREDENTIAL_CHUNKS: u32 = 4_096;
const MAX_OBSOLETE_CHUNK_SETS: usize = 16;

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StoredCredential {
    Password {
        username: String,
        password: String,
    },
    Oidc {
        refresh_token: String,
        user_id: String,
        username: String,
    },
}

impl std::fmt::Debug for StoredCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password { username, .. } => formatter
                .debug_struct("Password")
                .field("username", username)
                .field("password", &"[REDACTED]")
                .finish(),
            Self::Oidc {
                user_id, username, ..
            } => formatter
                .debug_struct("Oidc")
                .field("refresh_token", &"[REDACTED]")
                .field("user_id", user_id)
                .field("username", username)
                .finish(),
        }
    }
}

impl Drop for StoredCredential {
    fn drop(&mut self) {
        match self {
            Self::Password { username, password } => {
                username.zeroize();
                password.zeroize();
            }
            Self::Oidc {
                refresh_token,
                user_id,
                username,
            } => {
                refresh_token.zeroize();
                user_id.zeroize();
                username.zeroize();
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialEnvelope {
    version: u32,
    credential: StoredCredential,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkSet {
    generation: String,
    chunks: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentChunkSet {
    generation: String,
    chunks: u32,
    length: u64,
    sha256: [u8; 32],
}

impl CurrentChunkSet {
    fn as_chunk_set(&self) -> ChunkSet {
        ChunkSet {
            generation: self.generation.clone(),
            chunks: self.chunks,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialManifest {
    version: u32,
    current: CurrentChunkSet,
    obsolete: Vec<ChunkSet>,
}

trait SecretStore {
    fn read(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn write(&self, account: &str, secret: &[u8]) -> Result<()>;
    fn delete(&self, account: &str) -> Result<bool>;
}

struct OperatingSystemStore;

impl SecretStore for OperatingSystemStore {
    fn read(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match entry(account)?.get_secret() {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(store_error("read", error)),
        }
    }

    fn write(&self, account: &str, secret: &[u8]) -> Result<()> {
        entry(account)?
            .set_secret(secret)
            .map_err(|error| store_error("write", error))
    }

    fn delete(&self, account: &str) -> Result<bool> {
        match entry(account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(KeyringError::NoEntry) => Ok(false),
            Err(error) => Err(store_error("delete", error)),
        }
    }
}

pub struct CredentialStore;

impl CredentialStore {
    pub fn load(account: &str) -> Result<Option<StoredCredential>> {
        validate_account(account)?;
        load_from(&OperatingSystemStore, account)
    }

    pub fn save(account: &str, credential: StoredCredential) -> Result<()> {
        validate_account(account)?;
        save_to(&OperatingSystemStore, account, credential)
    }

    pub fn delete(account: &str) -> Result<bool> {
        validate_account(account)?;
        delete_from(&OperatingSystemStore, account)
    }
}

fn load_from<S: SecretStore>(store: &S, account: &str) -> Result<Option<StoredCredential>> {
    let Some(manifest_bytes) = store.read(account)? else {
        return Ok(None);
    };
    let manifest = decode_manifest(&manifest_bytes)?;
    let length = usize::try_from(manifest.current.length)
        .map_err(|_| invalid_format("saved authentication length is too large"))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
    for index in 0..manifest.current.chunks {
        let chunk_account = chunk_account(account, &manifest.current.generation, index);
        let Some(chunk) = store.read(&chunk_account)? else {
            return Err(invalid_format(format!(
                "saved authentication chunk {index} is missing"
            )));
        };
        if chunk.len() > SECRET_CHUNK_SIZE {
            return Err(invalid_format(format!(
                "saved authentication chunk {index} is too large"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() != length {
        return Err(invalid_format(format!(
            "saved authentication length is {}; expected {length}",
            bytes.len()
        )));
    }
    if Sha256::digest(bytes.as_slice()).as_slice() != manifest.current.sha256 {
        return Err(invalid_format(
            "saved authentication failed its integrity check",
        ));
    }
    let envelope: CredentialEnvelope = serde_json::from_slice(&bytes).map_err(|error| {
        invalid_format(format!("saved authentication is not valid JSON: {error}"))
    })?;
    if envelope.version != CREDENTIAL_VERSION {
        return Err(invalid_format(format!(
            "unsupported saved authentication version {}; expected {CREDENTIAL_VERSION}",
            envelope.version
        )));
    }
    Ok(Some(envelope.credential))
}

fn save_to<S: SecretStore>(store: &S, account: &str, credential: StoredCredential) -> Result<()> {
    let previous = replacement_manifest(store, account)?;
    let obsolete = if let Some(previous) = previous.as_ref() {
        let mut remaining = cleanup_chunk_sets(store, account, &previous.obsolete);
        remaining.push(previous.current.as_chunk_set());
        remaining
    } else {
        Vec::new()
    };
    if obsolete.len() > MAX_OBSOLETE_CHUNK_SETS {
        return Err(Error::CredentialStore(
            "too many stale saved-authentication entries could not be removed".into(),
        ));
    }

    let envelope = CredentialEnvelope {
        version: CREDENTIAL_VERSION,
        credential,
    };
    let bytes =
        Zeroizing::new(serde_json::to_vec(&envelope).map_err(|error| {
            Error::CredentialStore(format!("serialize authentication: {error}"))
        })?);
    let chunk_count = bytes.len().div_ceil(SECRET_CHUNK_SIZE);
    let chunks = u32::try_from(chunk_count)
        .map_err(|_| Error::CredentialStore("saved authentication is too large to store".into()))?;
    if chunks == 0 || chunks > MAX_CREDENTIAL_CHUNKS {
        return Err(Error::CredentialStore(
            "saved authentication is too large to store".into(),
        ));
    }

    let generation = new_generation()?;
    let current = CurrentChunkSet {
        generation,
        chunks,
        length: u64::try_from(bytes.len()).map_err(|_| {
            Error::CredentialStore("saved authentication is too large to store".into())
        })?,
        sha256: Sha256::digest(bytes.as_slice()).into(),
    };
    let mut manifest = CredentialManifest {
        version: STORAGE_VERSION,
        current,
        obsolete,
    };
    let manifest_bytes = encode_manifest(&manifest)?;

    for (index, chunk) in bytes.chunks(SECRET_CHUNK_SIZE).enumerate() {
        let index = u32::try_from(index).expect("chunk count was validated above");
        if let Err(error) = store.write(
            &chunk_account(account, &manifest.current.generation, index),
            chunk,
        ) {
            cleanup_new_chunks(store, account, &manifest.current.generation, index);
            return Err(error);
        }
    }

    if let Err(error) = store.write(account, &manifest_bytes) {
        cleanup_new_chunks(
            store,
            account,
            &manifest.current.generation,
            manifest.current.chunks,
        );
        return Err(error);
    }

    let remaining = cleanup_chunk_sets(store, account, &manifest.obsolete);
    if remaining.len() != manifest.obsolete.len() {
        manifest.obsolete = remaining;
        if let Ok(manifest_bytes) = encode_manifest(&manifest) {
            let _ = store.write(account, &manifest_bytes);
        }
    }
    Ok(())
}

fn delete_from<S: SecretStore>(store: &S, account: &str) -> Result<bool> {
    let Some(manifest_bytes) = store.read(account)? else {
        return Ok(false);
    };
    let manifest = decode_manifest(&manifest_bytes)?;
    let mut sets = manifest.obsolete;
    sets.push(manifest.current.as_chunk_set());
    let remaining = cleanup_chunk_sets(store, account, &sets);
    if !remaining.is_empty() {
        return Err(Error::CredentialStore(
            "delete saved-authentication chunks from the operating-system credential store".into(),
        ));
    }
    store.delete(account)?;
    Ok(true)
}

fn replacement_manifest<S: SecretStore>(
    store: &S,
    account: &str,
) -> Result<Option<CredentialManifest>> {
    let Some(bytes) = store.read(account)? else {
        return Ok(None);
    };
    // The unreleased single-entry format is intentionally not migrated.
    Ok(decode_manifest(&bytes).ok())
}

fn encode_manifest(manifest: &CredentialManifest) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = Zeroizing::new(serde_json::to_vec(manifest).map_err(|error| {
        Error::CredentialStore(format!("serialize authentication metadata: {error}"))
    })?);
    if bytes.len() > SECRET_CHUNK_SIZE {
        return Err(Error::CredentialStore(
            "saved-authentication metadata is too large to store".into(),
        ));
    }
    Ok(bytes)
}

fn decode_manifest(bytes: &[u8]) -> Result<CredentialManifest> {
    let manifest: CredentialManifest = serde_json::from_slice(bytes).map_err(|error| {
        invalid_format(format!(
            "saved authentication metadata is not valid JSON: {error}"
        ))
    })?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &CredentialManifest) -> Result<()> {
    if manifest.version != STORAGE_VERSION {
        return Err(invalid_format(format!(
            "unsupported saved-authentication storage version {}; expected {STORAGE_VERSION}",
            manifest.version
        )));
    }
    validate_chunk_set(&manifest.current.generation, manifest.current.chunks)?;
    let length = usize::try_from(manifest.current.length)
        .map_err(|_| invalid_format("saved authentication length is too large"))?;
    if length == 0 || length.div_ceil(SECRET_CHUNK_SIZE) != manifest.current.chunks as usize {
        return Err(invalid_format(
            "saved authentication metadata has an inconsistent length",
        ));
    }
    if manifest.obsolete.len() > MAX_OBSOLETE_CHUNK_SETS {
        return Err(invalid_format(
            "saved authentication metadata contains too many stale entries",
        ));
    }
    for (index, set) in manifest.obsolete.iter().enumerate() {
        validate_chunk_set(&set.generation, set.chunks)?;
        if set.generation == manifest.current.generation
            || manifest.obsolete[..index]
                .iter()
                .any(|other| other.generation == set.generation)
        {
            return Err(invalid_format(
                "saved authentication metadata contains duplicate generations",
            ));
        }
    }
    Ok(())
}

fn validate_chunk_set(generation: &str, chunks: u32) -> Result<()> {
    if generation.len() != 32
        || !generation
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_format(
            "saved authentication metadata has an invalid generation",
        ));
    }
    if chunks == 0 || chunks > MAX_CREDENTIAL_CHUNKS {
        return Err(invalid_format(
            "saved authentication metadata has an invalid chunk count",
        ));
    }
    Ok(())
}

fn cleanup_chunk_sets<S: SecretStore>(
    store: &S,
    account: &str,
    sets: &[ChunkSet],
) -> Vec<ChunkSet> {
    let mut remaining = Vec::new();
    for set in sets {
        let mut failed = false;
        for index in 0..set.chunks {
            if store
                .delete(&chunk_account(account, &set.generation, index))
                .is_err()
            {
                failed = true;
            }
        }
        if failed {
            remaining.push(set.clone());
        }
    }
    remaining
}

fn cleanup_new_chunks<S: SecretStore>(store: &S, account: &str, generation: &str, chunks: u32) {
    for index in 0..chunks {
        let _ = store.delete(&chunk_account(account, generation, index));
    }
}

fn new_generation() -> Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| {
        Error::CredentialStore("system randomness is unavailable for credential storage".into())
    })?;
    let mut generation = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut generation, "{byte:02x}")
            .map_err(|_| Error::CredentialStore("could not format credential generation".into()))?;
    }
    Ok(generation)
}

fn chunk_account(account: &str, generation: &str, index: u32) -> String {
    format!("{account}.chunk.{generation}.{index:08x}")
}

fn validate_account(account: &str) -> Result<()> {
    if account.is_empty() {
        return Err(Error::CredentialStore(
            "profile has no credential-store identifier".into(),
        ));
    }
    Ok(())
}

fn entry(account: &str) -> Result<Entry> {
    Entry::new(KEYRING_SERVICE, account).map_err(|error| store_error("open", error))
}

fn invalid_format(message: impl Into<String>) -> Error {
    Error::CredentialStore(format!(
        "saved authentication has an invalid format: {}",
        message.into()
    ))
}

fn store_error(operation: &str, error: KeyringError) -> Error {
    Error::CredentialStore(format!(
        "{operation} the operating-system credential store: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use super::*;

    const TEST_ACCOUNT: &str = "0123456789abcdef0123456789abcdef";

    #[derive(Default)]
    struct MemoryStore {
        entries: RefCell<HashMap<String, Vec<u8>>>,
    }

    impl SecretStore for MemoryStore {
        fn read(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self
                .entries
                .borrow()
                .get(account)
                .cloned()
                .map(Zeroizing::new))
        }

        fn write(&self, account: &str, secret: &[u8]) -> Result<()> {
            self.entries
                .borrow_mut()
                .insert(account.to_owned(), secret.to_vec());
            Ok(())
        }

        fn delete(&self, account: &str) -> Result<bool> {
            Ok(self.entries.borrow_mut().remove(account).is_some())
        }
    }

    #[test]
    fn credential_envelope_round_trips_without_plaintext_debug_output() {
        let envelope = CredentialEnvelope {
            version: CREDENTIAL_VERSION,
            credential: StoredCredential::Password {
                username: "alice".into(),
                password: "secret".into(),
            },
        };
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let decoded: CredentialEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(
            decoded.credential,
            StoredCredential::Password {
                ref username,
                ref password
            } if username == "alice" && password == "secret"
        ));
        assert!(!format!("{:?}", decoded.credential).contains("secret"));
    }

    #[test]
    fn long_oidc_credential_is_chunked_and_round_trips() {
        let store = MemoryStore::default();
        let refresh_token = "token".repeat(2_000);
        save_to(
            &store,
            TEST_ACCOUNT,
            StoredCredential::Oidc {
                refresh_token: refresh_token.clone(),
                user_id: "42".into(),
                username: "alice".into(),
            },
        )
        .unwrap();

        let entries = store.entries.borrow();
        assert!(entries.len() > 2);
        assert!(
            entries
                .values()
                .all(|secret| secret.len() <= SECRET_CHUNK_SIZE)
        );
        drop(entries);

        let loaded = load_from(&store, TEST_ACCOUNT).unwrap().unwrap();
        assert!(matches!(
            loaded,
            StoredCredential::Oidc {
                refresh_token: ref loaded_token,
                ref user_id,
                ref username,
            } if loaded_token == &refresh_token && user_id == "42" && username == "alice"
        ));
    }

    #[test]
    fn saving_again_removes_the_previous_generation() {
        let store = MemoryStore::default();
        save_to(
            &store,
            TEST_ACCOUNT,
            StoredCredential::Oidc {
                refresh_token: "old".repeat(2_000),
                user_id: "42".into(),
                username: "alice".into(),
            },
        )
        .unwrap();
        let old_accounts = store.entries.borrow().keys().cloned().collect::<Vec<_>>();

        save_to(
            &store,
            TEST_ACCOUNT,
            StoredCredential::Password {
                username: "bob".into(),
                password: "new-secret".into(),
            },
        )
        .unwrap();

        let entries = store.entries.borrow();
        assert!(
            old_accounts
                .iter()
                .filter(|account| account.as_str() != TEST_ACCOUNT)
                .all(|account| !entries.contains_key(account))
        );
        drop(entries);
        assert!(matches!(
            load_from(&store, TEST_ACCOUNT).unwrap().unwrap(),
            StoredCredential::Password {
                ref username,
                ref password,
            } if username == "bob" && password == "new-secret"
        ));
    }

    #[test]
    fn delete_removes_manifest_and_all_chunks() {
        let store = MemoryStore::default();
        save_to(
            &store,
            TEST_ACCOUNT,
            StoredCredential::Oidc {
                refresh_token: "token".repeat(2_000),
                user_id: "42".into(),
                username: "alice".into(),
            },
        )
        .unwrap();

        assert!(delete_from(&store, TEST_ACCOUNT).unwrap());
        assert!(store.entries.borrow().is_empty());
        assert!(!delete_from(&store, TEST_ACCOUNT).unwrap());
    }

    #[test]
    fn missing_chunk_is_reported_as_invalid_saved_authentication() {
        let store = MemoryStore::default();
        save_to(
            &store,
            TEST_ACCOUNT,
            StoredCredential::Oidc {
                refresh_token: "token".repeat(2_000),
                user_id: "42".into(),
                username: "alice".into(),
            },
        )
        .unwrap();
        let chunk_account = store
            .entries
            .borrow()
            .keys()
            .find(|account| account.as_str() != TEST_ACCOUNT)
            .unwrap()
            .clone();
        store.entries.borrow_mut().remove(&chunk_account);

        let error = load_from(&store, TEST_ACCOUNT).unwrap_err();
        assert!(error.to_string().contains("chunk"));
        assert!(error.to_string().contains("missing"));
    }
}
