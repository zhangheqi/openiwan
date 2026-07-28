use fs2::FileExt;
use openiwan::dns::DnsOverrides;
use openiwan::managed::{LinePreference, validate_domain};
use openiwan::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const STATE_VERSION: u32 = 1;
const STATE_FILE_NAME: &str = "profiles.toml";
const LOCK_FILE_NAME: &str = "profiles.lock";
static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliState {
    version: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, ManagedProfile>,
}

impl Default for CliState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            device_id: String::new(),
            default_profile: None,
            profiles: BTreeMap::new(),
        }
    }
}

impl CliState {
    fn validate(&self) -> Result<()> {
        if self.version != STATE_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported CLI state version {}; expected {STATE_VERSION}",
                self.version
            )));
        }
        if !self.device_id.is_empty() {
            validate_device_id(&self.device_id, "generated device ID")?;
        }
        if let Some(name) = &self.default_profile
            && !self.profiles.contains_key(name)
        {
            return Err(Error::InvalidConfig(format!(
                "default profile {name:?} does not exist"
            )));
        }
        for (name, profile) in &self.profiles {
            validate_profile_name(name)?;
            profile.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedProfile {
    pub domain: String,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default)]
    pub line: LinePreference,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub credential_id: String,
    #[serde(default, skip_serializing_if = "dns_overrides_are_empty")]
    pub dns: DnsOverrides,
}

impl ManagedProfile {
    pub fn new(domain: String, device_id: String) -> Result<Self> {
        let profile = Self {
            domain,
            device_id,
            username: None,
            line: LinePreference::Auto,
            credential_id: String::new(),
            dns: DnsOverrides::default(),
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<()> {
        validate_domain(&self.domain)?;
        validate_device_id(&self.device_id, "profile device ID")?;
        if self
            .username
            .as_ref()
            .is_some_and(|username| username.trim().is_empty() || username.len() > 256)
        {
            return Err(Error::InvalidConfig(
                "profile username must contain 1..=256 characters".into(),
            ));
        }
        if !self.credential_id.is_empty()
            && (self.credential_id.len() != 32
                || !self
                    .credential_id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
        {
            return Err(Error::InvalidConfig(
                "profile credential ID must be 32 lowercase hexadecimal characters".into(),
            ));
        }
        self.dns.validate()?;
        Ok(())
    }

    pub fn ensure_credential_id(&mut self) -> Result<&str> {
        if self.credential_id.is_empty() {
            self.credential_id = new_credential_id()?;
        }
        Ok(&self.credential_id)
    }
}

#[derive(Debug, Clone)]
pub struct StateStore {
    directory: PathBuf,
}

impl StateStore {
    pub fn new(override_directory: Option<PathBuf>) -> Result<Self> {
        let directory = match override_directory {
            Some(directory) => directory,
            None => default_state_directory()?,
        };
        if directory.as_os_str().is_empty() {
            return Err(Error::InvalidConfig(
                "CLI state directory must not be empty".into(),
            ));
        }
        Ok(Self { directory })
    }

    #[cfg(test)]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn cache_directory(&self) -> PathBuf {
        self.directory.join("cache")
    }

    /// Return the installation-wide device ID, generating and persisting it
    /// atomically on first use.
    pub fn device_id(&self) -> Result<String> {
        let state = self.load()?;
        if !state.device_id.is_empty() {
            return Ok(state.device_id);
        }
        self.update(|state| {
            if state.device_id.is_empty() {
                state.device_id = new_device_id()?;
            }
            Ok(state.device_id.clone())
        })
    }

    pub fn load(&self) -> Result<CliState> {
        match fs::symlink_metadata(&self.directory) {
            Ok(_) => secure_directory(&self.directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(CliState::default());
            }
            Err(error) => return Err(error.into()),
        }
        // Writers replace a fully synced same-directory temporary file
        // atomically, so readers always observe either the old or new complete
        // document and do not need to create or acquire the writer lock.
        self.load_unlocked()
    }

    pub fn update<T>(&self, operation: impl FnOnce(&mut CliState) -> Result<T>) -> Result<T> {
        self.ensure_directory()?;
        let cache = self.cache_directory();
        fs::create_dir_all(&cache)?;
        secure_directory(&cache)?;
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let mut state = self.load_unlocked()?;
        let output = operation(&mut state)?;
        state.validate()?;
        self.write_unlocked(&state)?;
        FileExt::unlock(&lock)?;
        Ok(output)
    }

    fn ensure_directory(&self) -> Result<()> {
        fs::create_dir_all(&self.directory)?;
        secure_directory(&self.directory)
    }

    fn open_lock(&self) -> Result<File> {
        let path = self.directory.join(LOCK_FILE_NAME);
        let file = secure_open(&path, true)?;
        secure_file(&path)?;
        Ok(file)
    }

    fn load_unlocked(&self) -> Result<CliState> {
        let path = self.directory.join(STATE_FILE_NAME);
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => {
                secure_file(&path)?;
                contents
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(CliState::default());
            }
            Err(error) => return Err(error.into()),
        };
        let state = toml::from_str::<CliState>(&contents).map_err(|error| {
            Error::InvalidConfig(format!("invalid CLI state {}: {error}", path.display()))
        })?;
        state.validate()?;
        Ok(state)
    }

    fn write_unlocked(&self, state: &CliState) -> Result<()> {
        let serialized = toml::to_string_pretty(state)
            .map_err(|error| Error::InvalidConfig(format!("serialize CLI state: {error}")))?;
        let destination = self.directory.join(STATE_FILE_NAME);
        let (temporary, mut file) = self.open_temporary()?;
        let write_result = (|| {
            file.write_all(serialized.as_bytes())?;
            file.sync_all()?;
            drop(file);
            secure_file(&temporary)?;
            atomic_replace(&temporary, &destination)?;
            secure_file(&destination)?;
            sync_directory(&self.directory)?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result
    }

    fn open_temporary(&self) -> Result<(PathBuf, File)> {
        for _ in 0..16 {
            let path = self.unique_temporary_path();
            match secure_open(&path, false) {
                Ok(file) => return Ok((path, file)),
                Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(Error::InvalidConfig(
            "could not allocate a unique CLI state temporary file".into(),
        ))
    }

    fn unique_temporary_path(&self) -> PathBuf {
        let counter = TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed);
        self.directory.join(format!(
            ".{STATE_FILE_NAME}.{}.{}.tmp",
            std::process::id(),
            counter
        ))
    }
}

fn dns_overrides_are_empty(value: &DnsOverrides) -> bool {
    value == &DnsOverrides::default()
}

pub fn validate_profile_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Error::InvalidConfig(
            "profile name must contain 1..=64 ASCII letters, digits, '.', '_', or '-'".into(),
        ));
    }
    Ok(())
}

fn new_credential_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| Error::Crypto("system randomness is unavailable"))?;
    let mut identifier = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut identifier, "{byte:02x}")
            .map_err(|_| Error::Crypto("could not format credential identifier"))?;
    }
    Ok(identifier)
}

fn new_device_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| Error::Crypto("system randomness is unavailable"))?;
    // RFC 9562 UUIDv4 version and variant bits.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-\
         {:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    ))
}

fn validate_device_id(device_id: &str, label: &str) -> Result<()> {
    if device_id.trim().is_empty() || device_id.len() > 256 {
        return Err(Error::InvalidConfig(format!(
            "{label} must contain 1..=256 characters"
        )));
    }
    Ok(())
}

fn default_state_directory() -> Result<PathBuf> {
    if let Some(directory) = std::env::var_os("OPENIWAN_STATE_DIR") {
        return Ok(PathBuf::from(directory));
    }
    #[cfg(target_os = "windows")]
    {
        environment_path("LOCALAPPDATA")
            .or_else(|| environment_path("APPDATA"))
            .map(|path| path.join("OpeniWAN"))
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "LOCALAPPDATA or APPDATA is required for CLI state; use --state-dir".into(),
                )
            })
    }
    #[cfg(target_os = "macos")]
    {
        environment_path("HOME")
            .map(|path| path.join("Library/Application Support/openiwan"))
            .ok_or_else(|| {
                Error::InvalidConfig("HOME is required for CLI state; use --state-dir".into())
            })
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(directory) = environment_path("XDG_STATE_HOME") {
            return Ok(directory.join("openiwan"));
        }
        environment_path("HOME")
            .map(|path| path.join(".local/state/openiwan"))
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "XDG_STATE_HOME or HOME is required for CLI state; use --state-dir".into(),
                )
            })
    }
}

fn environment_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::InvalidConfig(format!(
            "{} must be a real directory, not a symlink",
            path.display()
        )));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn secure_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::InvalidConfig(format!(
            "{} must be a real directory, not a symlink",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn secure_open(path: &Path, allow_existing: bool) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    if allow_existing {
        options.create(true);
    } else {
        options.create_new(true);
    }
    Ok(options.open(path)?)
}

#[cfg(not(unix))]
fn secure_open(path: &Path, allow_existing: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if allow_existing {
        options.create(true);
    } else {
        options.create_new(true);
    }
    Ok(options.open(path)?)
}

#[cfg(unix)]
fn secure_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::InvalidConfig(format!(
            "{} must be a regular file",
            path.display()
        )));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(Error::InvalidConfig(format!(
            "{} must not be accessible by group or other users",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::InvalidConfig(format!(
            "{} must be a regular file",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
    fs::rename(source, destination)?;
    Ok(())
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: both paths are NUL-terminated UTF-16 buffers that remain alive
    // for the duration of MoveFileExW.
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store(name: &str) -> StateStore {
        let counter = TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed);
        StateStore::new(Some(std::env::temp_dir().join(format!(
            "openiwan-state-test-{}-{name}-{counter}",
            std::process::id()
        ))))
        .unwrap()
    }

    #[test]
    fn state_round_trip_is_versioned_and_non_secret() {
        let store = test_store("round-trip");
        store
            .update(|state| {
                let mut profile = ManagedProfile::new("iwan.example".into(), "device-1".into())?;
                profile.username = Some("alice".into());
                profile.line = "iwan:7".parse().unwrap();
                state.profiles.insert("work".into(), profile);
                state.default_profile = Some("work".into());
                Ok(())
            })
            .unwrap();

        let state = store.load().unwrap();
        let profile = &state.profiles["work"];
        assert_eq!(profile.username.as_deref(), Some("alice"));
        assert_eq!(profile.line, "iwan:7".parse().unwrap());
        let raw = fs::read_to_string(store.directory().join(STATE_FILE_NAME)).unwrap();
        assert!(raw.contains(&format!("version = {STATE_VERSION}")));
        assert!(!raw.contains("password"));
        assert!(!raw.contains("token"));

        fs::remove_dir_all(store.directory()).unwrap();
    }

    #[test]
    fn update_preserves_existing_profiles() {
        let store = test_store("preserve");
        store
            .update(|state| {
                state.profiles.insert(
                    "one".into(),
                    ManagedProfile::new("one.example".into(), "device-1".into())?,
                );
                Ok(())
            })
            .unwrap();
        store
            .update(|state| {
                state.profiles.insert(
                    "two".into(),
                    ManagedProfile::new("two.example".into(), "device-2".into())?,
                );
                Ok(())
            })
            .unwrap();
        assert_eq!(store.load().unwrap().profiles.len(), 2);
        fs::remove_dir_all(store.directory()).unwrap();
    }

    #[test]
    fn credential_identifier_is_created_lazily_and_remains_stable() {
        let mut profile = ManagedProfile::new("iwan.example".into(), "device-1".into()).unwrap();
        assert!(profile.credential_id.is_empty());
        let identifier = profile.ensure_credential_id().unwrap().to_owned();
        assert_eq!(identifier.len(), 32);
        assert!(
            identifier
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert_eq!(profile.ensure_credential_id().unwrap(), identifier);
    }

    #[test]
    fn device_identifier_is_created_lazily_and_remains_stable() {
        let store = test_store("device-id");
        let first = store.device_id().unwrap();
        let second = store.device_id().unwrap();

        assert_eq!(first, second);
        assert_eq!(first.len(), 36);
        assert_eq!(first.as_bytes()[8], b'-');
        assert_eq!(first.as_bytes()[13], b'-');
        assert_eq!(first.as_bytes()[14], b'4');
        assert_eq!(first.as_bytes()[18], b'-');
        assert!(matches!(first.as_bytes()[19], b'8' | b'9' | b'A' | b'B'));
        assert_eq!(first.as_bytes()[23], b'-');
        assert_eq!(store.load().unwrap().device_id, first);

        fs::remove_dir_all(store.directory()).unwrap();
    }

    #[test]
    fn profile_names_are_portable() {
        assert!(validate_profile_name("work-1.example").is_ok());
        assert!(validate_profile_name("").is_err());
        assert!(validate_profile_name("../escape").is_err());
        assert!(validate_profile_name("中文").is_err());
    }

    #[test]
    fn rejects_unknown_state_versions() {
        let store = test_store("unknown-version");
        store
            .update(|state| {
                state.profiles.insert(
                    "work".into(),
                    ManagedProfile::new("iwan.example".into(), "device-1".into())?,
                );
                Ok(())
            })
            .unwrap();
        let path = store.directory().join(STATE_FILE_NAME);
        let invalid = fs::read_to_string(&path)
            .unwrap()
            .replacen("version = 1", "version = 99", 1);
        fs::write(&path, invalid).unwrap();
        let error = store.load().unwrap_err().to_string();
        assert!(error.contains("unsupported CLI state version 99"));
        assert!(error.contains("expected 1"));
        fs::remove_dir_all(store.directory()).unwrap();
    }
}
