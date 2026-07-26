use crate::sr::{SrEncryptionAlgorithm, SrOuterCipher};
use crate::{EncryptionMethod, Error, Result};
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use zeroize::Zeroize;

fn default_mtu() -> u16 {
    1400
}

fn default_receive_poll_ms() -> u64 {
    250
}

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

/// Runtime SR path selected from an Android-compatible controller entry.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentRoutingConfig {
    pub id: u32,
    #[serde(default)]
    pub keepalive: bool,
    #[serde(default)]
    pub encrypt_algo: SrEncryptionAlgorithm,
    #[serde(default)]
    pub encrypt_key: String,
    pub links: Vec<u32>,
    /// Runtime-only value. The serialized Android `SREntry` does not contain it.
    #[serde(skip)]
    pub local_sr_id: Option<u32>,
}

impl std::fmt::Debug for SegmentRoutingConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SegmentRoutingConfig")
            .field("id", &self.id)
            .field("keepalive", &self.keepalive)
            .field("encrypt_algo", &self.encrypt_algo)
            .field("encrypt_key", &"[REDACTED]")
            .field("links", &self.links)
            .field("local_sr_id", &self.local_sr_id)
            .finish()
    }
}

impl Drop for SegmentRoutingConfig {
    fn drop(&mut self) {
        self.encrypt_key.zeroize();
    }
}

impl SegmentRoutingConfig {
    pub fn validate(&self) -> Result<()> {
        if !(1..=6).contains(&self.links.len())
            || self
                .links
                .iter()
                .any(|link| !(1..=0x00ff_ffff).contains(link))
        {
            return Err(Error::InvalidConfig(
                "segment-routing links must contain 1..=6 IDs in 1..=0x00ffffff".into(),
            ));
        }
        let _ = SrOuterCipher::new(self.encrypt_algo, &self.encrypt_key)?;
        Ok(())
    }

    pub const fn monitor_sr_id(&self) -> u32 {
        match self.local_sr_id {
            Some(value) if value != 0 => value,
            _ => self.id,
        }
    }
}

/// Android iWAN 2.3.0 data-plane settings.
///
/// Authentication and heartbeat timing are protocol constants rather than
/// deployment knobs. Passwords are passed separately to [`crate::Client::new`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub server: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default)]
    pub encryption: EncryptionMethod,
    #[serde(default = "default_receive_poll_ms")]
    pub receive_poll_ms: u64,
    #[serde(default)]
    pub reconnect: ReconnectPolicy,
    #[serde(default)]
    pub segment_routing: Option<SegmentRoutingConfig>,
}

impl ClientConfig {
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            mtu: default_mtu(),
            encryption: EncryptionMethod::default(),
            receive_poll_ms: default_receive_poll_ms(),
            reconnect: ReconnectPolicy::default(),
            segment_routing: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !(576..=9_000).contains(&self.mtu) {
            return Err(Error::InvalidConfig(format!(
                "MTU {} is outside 576..=9000",
                self.mtu
            )));
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
        if let Some(sr) = &self.segment_routing {
            sr.validate()?;
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

    pub const fn receive_poll(&self) -> Duration {
        Duration::from_millis(self.receive_poll_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_configuration_has_only_confirmed_protocol_knobs() {
        let config: ClientConfig = toml::from_str("server = \"127.0.0.1:6001\"").unwrap();
        assert_eq!(config.mtu, 1400);
        assert_eq!(config.encryption, EncryptionMethod::Xor);
        config.validate().unwrap();
    }

    #[test]
    fn validates_sr_path_and_raw_key_length() {
        let mut config = ClientConfig::new("127.0.0.1:6001");
        config.segment_routing = Some(SegmentRoutingConfig {
            id: 7,
            keepalive: true,
            encrypt_algo: SrEncryptionAlgorithm::Aes128,
            encrypt_key: "0123456789abcdef".into(),
            links: vec![1, 2],
            local_sr_id: None,
        });
        config.validate().unwrap();
    }
}
