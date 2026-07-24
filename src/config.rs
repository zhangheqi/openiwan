use crate::{EncryptionMethod, Error, Result};
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

fn default_mtu() -> u16 {
    1400
}

fn default_auth_timeout_ms() -> u64 {
    3_000
}

fn default_auth_attempts() -> u32 {
    3
}

fn default_heartbeat_interval_ms() -> u64 {
    5_000
}

fn default_heartbeat_timeout_ms() -> u64 {
    30_000
}

fn default_receive_poll_ms() -> u64 {
    250
}

/// Reconnection controls used after a network or heartbeat failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconnectPolicy {
    #[serde(default = "ReconnectPolicy::default_attempts")]
    pub attempts: u32,
    #[serde(default = "ReconnectPolicy::default_initial_delay_ms")]
    pub initial_delay_ms: u64,
    #[serde(default = "ReconnectPolicy::default_max_delay_ms")]
    pub max_delay_ms: u64,
}

impl ReconnectPolicy {
    const fn default_attempts() -> u32 {
        10
    }

    const fn default_initial_delay_ms() -> u64 {
        1_000
    }

    const fn default_max_delay_ms() -> u64 {
        30_000
    }
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            attempts: Self::default_attempts(),
            initial_delay_ms: Self::default_initial_delay_ms(),
            max_delay_ms: Self::default_max_delay_ms(),
        }
    }
}

/// Settings for the traditional single-path iWAN UDP client.
///
/// Passwords are deliberately not serializable as part of this structure. Pass
/// them to [`crate::Client::new`] from a protected source such as a prompt,
/// keychain, or environment variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default)]
    pub encryption: EncryptionMethod,
    #[serde(default = "default_auth_timeout_ms")]
    pub auth_timeout_ms: u64,
    #[serde(default = "default_auth_attempts")]
    pub auth_attempts: u32,
    /// Require OPENACK to echo the `AUTH_VERIFY` nonce sent in OPEN.
    ///
    /// Some compatible deployments omit the echo. A present echo is always
    /// validated, regardless of this setting.
    pub require_auth_verify_echo: bool,
    /// Number of derived session-key bytes repeated by the XOR data cipher.
    ///
    /// The traditional client uses 16; some compatible deployments use 8.
    pub xor_key_bytes: u8,
    #[serde(default = "default_heartbeat_interval_ms")]
    pub heartbeat_interval_ms: u64,
    #[serde(default = "default_heartbeat_timeout_ms")]
    pub heartbeat_timeout_ms: u64,
    #[serde(default = "default_receive_poll_ms")]
    pub receive_poll_ms: u64,
    #[serde(default)]
    pub reconnect: ReconnectPolicy,
}

impl ClientConfig {
    pub fn new(
        server: impl Into<String>,
        require_auth_verify_echo: bool,
        xor_key_bytes: u8,
    ) -> Self {
        Self {
            server: server.into(),
            mtu: default_mtu(),
            encryption: EncryptionMethod::default(),
            auth_timeout_ms: default_auth_timeout_ms(),
            auth_attempts: default_auth_attempts(),
            require_auth_verify_echo,
            xor_key_bytes,
            heartbeat_interval_ms: default_heartbeat_interval_ms(),
            heartbeat_timeout_ms: default_heartbeat_timeout_ms(),
            receive_poll_ms: default_receive_poll_ms(),
            reconnect: ReconnectPolicy::default(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !(576..=9_000).contains(&self.mtu) {
            return Err(Error::InvalidConfig(format!(
                "MTU {} is outside 576..=9000",
                self.mtu
            )));
        }
        if self.auth_attempts == 0 {
            return Err(Error::InvalidConfig(
                "auth_attempts must be greater than zero".into(),
            ));
        }
        if self.auth_timeout_ms == 0 {
            return Err(Error::InvalidConfig(
                "auth_timeout_ms must be greater than zero".into(),
            ));
        }
        if !matches!(self.xor_key_bytes, 8 | 16) {
            return Err(Error::InvalidConfig(
                "xor_key_bytes must be either 8 or 16".into(),
            ));
        }
        if self.heartbeat_interval_ms == 0 {
            return Err(Error::InvalidConfig(
                "heartbeat_interval_ms must be greater than zero".into(),
            ));
        }
        if self.heartbeat_timeout_ms <= self.heartbeat_interval_ms {
            return Err(Error::InvalidConfig(
                "heartbeat_timeout_ms must exceed heartbeat_interval_ms".into(),
            ));
        }
        if self.receive_poll_ms == 0 {
            return Err(Error::InvalidConfig(
                "receive_poll_ms must be greater than zero".into(),
            ));
        }
        if self.reconnect.max_delay_ms == 0 {
            return Err(Error::InvalidConfig(
                "reconnect.max_delay_ms must be greater than zero".into(),
            ));
        }
        if self.reconnect.initial_delay_ms > self.reconnect.max_delay_ms {
            return Err(Error::InvalidConfig(
                "reconnect.initial_delay_ms must not exceed reconnect.max_delay_ms".into(),
            ));
        }
        let _ = self.resolve_server()?;
        Ok(())
    }

    pub fn resolve_server(&self) -> Result<SocketAddr> {
        self.server
            .to_socket_addrs()
            .map_err(Error::Io)?
            .next()
            .ok_or_else(|| Error::InvalidConfig("server resolved to no address".into()))
    }

    pub const fn auth_timeout(&self) -> Duration {
        Duration::from_millis(self.auth_timeout_ms)
    }

    pub const fn heartbeat_interval(&self) -> Duration {
        Duration::from_millis(self.heartbeat_interval_ms)
    }

    pub const fn heartbeat_timeout(&self) -> Duration {
        Duration::from_millis(self.heartbeat_timeout_ms)
    }

    pub const fn receive_poll(&self) -> Duration {
        Duration::from_millis(self.receive_poll_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_incoherent_timeouts() {
        let mut config = ClientConfig::new("127.0.0.1:6001", true, 16);
        config.auth_timeout_ms = 0;
        assert!(config.validate().is_err());

        config.auth_timeout_ms = 1;
        config.reconnect.initial_delay_ms = 2;
        config.reconnect.max_delay_ms = 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn current_compatibility_fields_are_required() {
        let complete = r#"
server = "127.0.0.1:6001"
require_auth_verify_echo = true
xor_key_bytes = 16
"#;
        assert!(toml::from_str::<ClientConfig>(complete).is_ok());
        assert!(
            toml::from_str::<ClientConfig>("server = \"127.0.0.1:6001\"\nxor_key_bytes = 16")
                .is_err()
        );
        assert!(
            toml::from_str::<ClientConfig>(
                "server = \"127.0.0.1:6001\"\nrequire_auth_verify_echo = true"
            )
            .is_err()
        );
    }
}
