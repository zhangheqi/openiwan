use keyring::v1::{Entry, Error as KeyringError};
use openiwan::{Error, Result};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const CREDENTIAL_VERSION: u32 = 1;
const KEYRING_SERVICE: &str = "org.openiwan.cli";

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

pub struct CredentialStore;

impl CredentialStore {
    pub fn load(account: &str) -> Result<Option<StoredCredential>> {
        let entry = entry(account)?;
        let bytes = match entry.get_secret() {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(KeyringError::NoEntry) => return Ok(None),
            Err(error) => return Err(store_error("read", error)),
        };
        let envelope: CredentialEnvelope = serde_json::from_slice(&bytes).map_err(|error| {
            Error::CredentialStore(format!(
                "saved authentication has an invalid format: {error}"
            ))
        })?;
        if envelope.version != CREDENTIAL_VERSION {
            return Err(Error::CredentialStore(format!(
                "unsupported saved authentication version {}; expected {CREDENTIAL_VERSION}",
                envelope.version
            )));
        }
        Ok(Some(envelope.credential))
    }

    pub fn save(account: &str, credential: StoredCredential) -> Result<()> {
        let envelope = CredentialEnvelope {
            version: CREDENTIAL_VERSION,
            credential,
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&envelope).map_err(|error| {
            Error::CredentialStore(format!("serialize authentication: {error}"))
        })?);
        entry(account)?
            .set_secret(&bytes)
            .map_err(|error| store_error("write", error))
    }

    pub fn delete(account: &str) -> Result<bool> {
        match entry(account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(KeyringError::NoEntry) => Ok(false),
            Err(error) => Err(store_error("delete", error)),
        }
    }
}

fn entry(account: &str) -> Result<Entry> {
    if account.is_empty() {
        return Err(Error::CredentialStore(
            "profile has no credential-store identifier".into(),
        ));
    }
    Entry::new(KEYRING_SERVICE, account).map_err(|error| store_error("open", error))
}

fn store_error(operation: &str, error: KeyringError) -> Error {
    Error::CredentialStore(format!(
        "{operation} the operating-system credential store: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
