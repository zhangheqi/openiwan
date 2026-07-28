use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;

fn default_timeout() -> Duration {
    Duration::from_secs(3)
}

const fn default_include_session_servers() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveVia {
    #[default]
    Auto,
    Tunnel,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverConfig {
    #[serde(default)]
    pub via: ResolveVia,
    #[serde(default)]
    pub servers: Vec<SocketAddr>,
    #[serde(default = "default_include_session_servers")]
    pub include_session_servers: bool,
    #[serde(default = "default_timeout", with = "duration_millis")]
    pub timeout: Duration,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            via: ResolveVia::Auto,
            servers: Vec::new(),
            include_session_servers: true,
            timeout: default_timeout(),
        }
    }
}

impl ResolverConfig {
    pub fn new(via: ResolveVia, servers: Vec<SocketAddr>, timeout: Duration) -> Result<Self> {
        let config = Self {
            via,
            servers,
            include_session_servers: true,
            timeout,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.timeout.is_zero() {
            return Err(Error::InvalidConfig(
                "DNS resolver timeout must be greater than zero".into(),
            ));
        }
        if self.servers.iter().any(|server| {
            server.port() == 0 || server.ip().is_unspecified() || server.ip().is_multicast()
        }) {
            return Err(Error::InvalidConfig(
                "DNS resolvers must be unicast addresses with a nonzero port".into(),
            ));
        }
        Ok(())
    }

    pub const fn with_session_servers(mut self, include: bool) -> Self {
        self.include_session_servers = include;
        self
    }
}

mod duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(value.as_millis().try_into().unwrap_or(u64::MAX))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Duration::from_millis(u64::deserialize(deserializer)?))
    }
}
