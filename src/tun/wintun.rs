use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0};
use windows_sys::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, INFINITE, ReleaseMutex, WaitForSingleObject,
};

const WINTUN_VERSION: &str = "0.14.1";
static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("OpenIWAN supports Windows only on x86_64 and aarch64");

#[cfg(target_arch = "x86_64")]
const ARCHITECTURE: &str = "x86_64";
#[cfg(target_arch = "x86_64")]
const EMBEDDED_DLL: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/wintun/0.14.1/x86_64/wintun.dll"
));
#[cfg(target_arch = "x86_64")]
const EMBEDDED_SHA256: &str = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";

#[cfg(target_arch = "aarch64")]
const ARCHITECTURE: &str = "aarch64";
#[cfg(target_arch = "aarch64")]
const EMBEDDED_DLL: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/wintun/0.14.1/aarch64/wintun.dll"
));
#[cfg(target_arch = "aarch64")]
const EMBEDDED_SHA256: &str = "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80";

pub(super) fn ensure_wintun() -> Result<PathBuf> {
    let root = local_app_data_from(
        std::env::var_os("LOCALAPPDATA"),
        std::env::var_os("USERPROFILE"),
    )?;
    install_into(&root)
}

fn local_app_data_from(
    local_app_data: Option<OsString>,
    user_profile: Option<OsString>,
) -> Result<PathBuf> {
    let path = local_app_data
        .map(PathBuf::from)
        .or_else(|| {
            user_profile.map(|profile| PathBuf::from(profile).join("AppData").join("Local"))
        })
        .ok_or_else(|| {
            Error::Tun(
                "cannot determine Windows LocalAppData from LOCALAPPDATA or USERPROFILE".into(),
            )
        })?;
    if !path.is_absolute() {
        return Err(Error::Tun(format!(
            "Windows LocalAppData path is not absolute: {}",
            path.display()
        )));
    }
    Ok(path)
}

fn install_into(local_app_data: &Path) -> Result<PathBuf> {
    let directory = local_app_data
        .join("openiwan")
        .join("wintun")
        .join(WINTUN_VERSION)
        .join(ARCHITECTURE);
    fs::create_dir_all(&directory).map_err(|error| {
        Error::Tun(format!(
            "create Wintun cache directory {}: {error}",
            directory.display()
        ))
    })?;
    let destination = directory.join("wintun.dll");
    let _install_lock = InstallMutex::acquire()?;
    if validate_file(&destination)? {
        return absolute_path(&destination);
    }

    let temporary = directory.join(format!(
        ".wintun.dll.{}.{}.tmp",
        std::process::id(),
        TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = write_embedded(&temporary)
        .and_then(|()| atomic_replace(&temporary, &destination))
        .and_then(|()| {
            if validate_file(&destination)? {
                Ok(())
            } else {
                Err(Error::Tun(format!(
                    "Wintun cache verification failed after installing {}",
                    destination.display()
                )))
            }
        });
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    absolute_path(&destination)
}

struct InstallMutex(HANDLE);

impl InstallMutex {
    fn acquire() -> Result<Self> {
        let name = format!("Local\\OpenIWAN-Wintun-{WINTUN_VERSION}-{ARCHITECTURE}");
        let name = wide_null(OsStr::new(&name));
        // SAFETY: the optional security descriptor is null and `name` is a
        // NUL-terminated UTF-16 buffer that remains alive for the call.
        let handle = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(Error::Tun(format!(
                "create Wintun installation mutex: {}",
                std::io::Error::last_os_error()
            )));
        }

        // SAFETY: `handle` is a live mutex handle returned by CreateMutexW.
        let wait_result = unsafe { WaitForSingleObject(handle, INFINITE) };
        if wait_result == WAIT_OBJECT_0 || wait_result == WAIT_ABANDONED {
            Ok(Self(handle))
        } else {
            // SAFETY: `handle` is live and must be closed on the error path.
            unsafe {
                CloseHandle(handle);
            }
            Err(Error::Tun(format!(
                "wait for Wintun installation mutex failed with status {wait_result}"
            )))
        }
    }
}

impl Drop for InstallMutex {
    fn drop(&mut self) {
        // SAFETY: this instance owns the mutex after a successful wait and
        // closes the live handle exactly once.
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}

fn write_embedded(path: &Path) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| {
            Error::Tun(format!(
                "create temporary Wintun file {}: {error}",
                path.display()
            ))
        })?;
    file.write_all(EMBEDDED_DLL).map_err(|error| {
        Error::Tun(format!(
            "write temporary Wintun file {}: {error}",
            path.display()
        ))
    })?;
    file.sync_all().map_err(|error| {
        Error::Tun(format!(
            "sync temporary Wintun file {}: {error}",
            path.display()
        ))
    })
}

fn validate_file(path: &Path) -> Result<bool> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(Error::Tun(format!(
                "inspect cached Wintun file {}: {error}",
                path.display()
            )));
        }
    };
    if metadata.len() != EMBEDDED_DLL.len() as u64 {
        return Ok(false);
    }

    let mut file = File::open(path).map_err(|error| {
        Error::Tun(format!(
            "open cached Wintun file {}: {error}",
            path.display()
        ))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let length = file.read(&mut buffer).map_err(|error| {
            Error::Tun(format!(
                "read cached Wintun file {}: {error}",
                path.display()
            ))
        })?;
        if length == 0 {
            break;
        }
        hasher.update(&buffer[..length]);
    }
    let digest = hasher.finalize();
    let mut digest_hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut digest_hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(digest_hex == EMBEDDED_SHA256)
}

fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
    let source = wide_null(source.as_os_str());
    let destination = wide_null(destination.as_os_str());
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
        Err(Error::Tun(format!(
            "atomically install Wintun DLL: {}",
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(())
    }
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    path.canonicalize().map_err(|error| {
        Error::Tun(format!(
            "resolve installed Wintun path {}: {error}",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "openiwan-wintun-{label}-{}-{}",
            std::process::id(),
            TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn chooses_local_app_data_with_profile_fallback() {
        let local = PathBuf::from(r"C:\Users\alice\AppData\Local");
        assert_eq!(
            local_app_data_from(Some(local.clone().into_os_string()), None).unwrap(),
            local
        );
        assert_eq!(
            local_app_data_from(None, Some(OsString::from(r"C:\Users\alice"))).unwrap(),
            PathBuf::from(r"C:\Users\alice\AppData\Local")
        );
    }

    #[test]
    fn extraction_is_idempotent_and_repairs_corruption() {
        let root = test_root("repair");
        let path = install_into(&root).unwrap();
        assert!(validate_file(&path).unwrap());
        assert_eq!(install_into(&root).unwrap(), path);
        fs::write(&path, b"corrupt").unwrap();
        assert_eq!(install_into(&root).unwrap(), path);
        assert!(validate_file(&path).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_extraction_produces_one_valid_file() {
        let root = test_root("concurrent");
        let threads = (0..4)
            .map(|_| {
                let root = root.clone();
                std::thread::spawn(move || install_into(&root).unwrap())
            })
            .collect::<Vec<_>>();
        let paths = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert!(paths.windows(2).all(|pair| pair[0] == pair[1]));
        assert!(validate_file(&paths[0]).unwrap());
        fs::remove_dir_all(root).unwrap();
    }
}
