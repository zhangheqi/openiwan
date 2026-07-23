use crate::{Error, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const STATE_VERSION: u32 = 1;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedServer {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    #[serde(rename = "encrypted_password")]
    pub(crate) encrypted_password: String,
}

impl std::fmt::Debug for ManagedServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedServer")
            .field("name", &self.name)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("encrypted_password", &"[REDACTED]")
            .finish()
    }
}

impl ManagedServer {
    pub fn endpoint(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedState {
    pub version: u32,
    pub provider_id: String,
    pub domain: String,
    pub device_id: String,
    pub fetched_at_unix: u64,
    pub servers: Vec<ManagedServer>,
}

impl ManagedState {
    pub fn validate_for(&self, provider_id: &str, domain: &str) -> Result<()> {
        if self.version != STATE_VERSION {
            return Err(Error::ManagedProvider(format!(
                "unsupported managed state version {}; expected {STATE_VERSION}",
                self.version
            )));
        }
        if self.provider_id != provider_id || self.domain != domain {
            return Err(Error::ManagedProvider(
                "managed state does not match the selected provider".into(),
            ));
        }
        if self.device_id.is_empty() {
            return Err(Error::ManagedProvider(
                "managed state has an empty device id".into(),
            ));
        }
        if self.servers.is_empty() {
            return Err(Error::ManagedProvider(
                "managed state contains no lines".into(),
            ));
        }
        for server in &self.servers {
            if server.name.trim().is_empty()
                || server.host.trim().is_empty()
                || server.port == 0
                || server.username.trim().is_empty()
                || server.encrypted_password.is_empty()
            {
                return Err(Error::ManagedProvider(
                    "managed state contains an incomplete line".into(),
                ));
            }
        }
        Ok(())
    }
}

pub fn load_state(path: &Path) -> Result<ManagedState> {
    validate_state_file(path)?;
    let contents = fs::read_to_string(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Error::ManagedProvider(format!(
                "{} does not exist; run `openiwan managed fetch` first",
                path.display()
            ))
        } else {
            Error::Io(error)
        }
    })?;
    serde_json::from_str(&contents)
        .map_err(|error| Error::ManagedProvider(format!("{}: {error}", path.display())))
}

pub fn save_state(path: &Path, state: &ManagedState) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        Error::ManagedProvider(format!("{} has no parent directory", path.display()))
    })?;
    fs::create_dir_all(parent)?;
    set_private_directory(parent)?;

    let mut random = [0_u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let suffix = hex_lower(&random);
    let temporary = parent.join(format!(".openiwan-state-{suffix}.tmp"));
    let serialized = serde_json::to_vec_pretty(state)
        .map_err(|error| Error::ManagedProvider(format!("serialize managed state: {error}")))?;
    let result = write_private_file(&temporary, &serialized)
        .and_then(|()| fs::rename(&temporary, path).map_err(Error::Io))
        .and_then(|()| sync_directory(parent));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn default_state_path(provider_id: &str, override_dir: Option<&Path>) -> Result<PathBuf> {
    let directory = if let Some(directory) = override_dir {
        directory.to_path_buf()
    } else {
        effective_home()?
            .join(".config")
            .join("openiwan")
            .join("managed")
    };
    Ok(directory.join(format!("{provider_id}.json")))
}

pub fn new_device_id() -> String {
    let mut bytes = [0_u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex_lower(&bytes)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(unix)]
fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn effective_home() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        let sudo_user = std::env::var("SUDO_USER").ok();
        let home = std::env::var_os("HOME").map(PathBuf::from);
        effective_home_from(sudo_user.as_deref(), home, passwd_home)
    }
    #[cfg(not(unix))]
    {
        std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
            Error::ManagedProvider("cannot determine the user home directory".into())
        })
    }
}

#[cfg(unix)]
fn effective_home_from<F>(
    sudo_user: Option<&str>,
    home: Option<PathBuf>,
    lookup: F,
) -> Result<PathBuf>
where
    F: FnOnce(&str) -> Option<PathBuf>,
{
    if let Some(user) = sudo_user.filter(|user| !user.is_empty() && *user != "root") {
        return lookup(user).ok_or_else(|| {
            Error::ManagedProvider(format!(
                "cannot determine home directory for SUDO_USER {user:?}"
            ))
        });
    }
    home.ok_or_else(|| Error::ManagedProvider("cannot determine the user home directory".into()))
}

#[cfg(unix)]
fn validate_state_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Error::ManagedProvider(format!(
                "{} does not exist; run `openiwan managed fetch` first",
                path.display()
            ))
        } else {
            Error::Io(error)
        }
    })?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(Error::ManagedProvider(format!(
            "{} must not be accessible by group or other users",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_state_file(path: &Path) -> Result<()> {
    if path.exists() {
        Ok(())
    } else {
        Err(Error::ManagedProvider(format!(
            "{} does not exist; run `openiwan managed fetch` first",
            path.display()
        )))
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn passwd_home(user: &str) -> Option<PathBuf> {
    use std::ffi::{CStr, CString};

    let user = CString::new(user).ok()?;
    let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    // SAFETY: all pointers reference writable storage for the duration of the
    // call; getpwnam_r initializes `record` only when `result` is non-null.
    let status = unsafe {
        libc::getpwnam_r(
            user.as_ptr(),
            record.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &raw mut result,
        )
    };
    if status != 0 || result.is_null() {
        return None;
    }
    // SAFETY: getpwnam_r succeeded and returned a non-null pw_dir pointer owned
    // by `buffer`, which remains alive through conversion.
    let directory = unsafe { CStr::from_ptr((*record.as_ptr()).pw_dir) };
    Some(PathBuf::from(directory.to_string_lossy().into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trip_is_private() {
        let directory =
            std::env::temp_dir().join(format!("openiwan-store-test-{}", new_device_id()));
        let path = directory.join("test.json");
        let state = ManagedState {
            version: STATE_VERSION,
            provider_id: "test".into(),
            domain: "iwan.test".into(),
            device_id: "0102030405060708".into(),
            fetched_at_unix: 1,
            servers: vec![ManagedServer {
                name: "Line".into(),
                host: "192.0.2.1".into(),
                port: 6001,
                username: "line-user".into(),
                encrypted_password: "opaque".into(),
            }],
        };
        save_state(&path, &state).unwrap();
        assert_eq!(load_state(&path).unwrap(), state);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sudo_home_resolution_never_falls_back_to_root_home() {
        let resolved = effective_home_from(Some("alice"), Some(PathBuf::from("/root")), |user| {
            (user == "alice").then(|| PathBuf::from("/home/alice"))
        })
        .unwrap();
        assert_eq!(resolved, PathBuf::from("/home/alice"));
        assert!(
            effective_home_from(Some("missing"), Some(PathBuf::from("/root")), |_| None,).is_err()
        );
    }
}
