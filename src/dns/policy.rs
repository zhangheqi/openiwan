use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

pub const MAX_DOMAIN_RULES: usize = 100_000;
const DEFAULT_DOH_CANARY: &str = "use-application-dns.net";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsServerMode {
    #[default]
    Server,
    Custom,
    Disabled,
}

impl FromStr for DnsServerMode {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "server" => Ok(Self::Server),
            "custom" => Ok(Self::Custom),
            "disabled" | "disable" => Ok(Self::Disabled),
            _ => Err(Error::InvalidConfig(format!(
                "invalid DNS mode {value:?}; expected server, custom, or disabled"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerListDnsMode {
    #[default]
    Auto,
    Custom,
    Disabled,
}

impl ServerListDnsMode {
    /// Parse the server-list value with the official fail-open behavior:
    /// unknown values are treated as `auto`.
    pub fn from_server_value(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "custom" => Self::Custom,
            "disable" | "disabled" => Self::Disabled,
            _ => Self::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitDnsMode {
    #[default]
    Off,
    TunnelAll,
    Managed,
    Custom,
}

impl FromStr for SplitDnsMode {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "off" | "disabled" => Ok(Self::Off),
            "tunnel_all" => Ok(Self::TunnelAll),
            "managed" => Ok(Self::Managed),
            "custom" => Ok(Self::Custom),
            _ => Err(Error::InvalidConfig(format!(
                "invalid split-DNS mode {value:?}; expected off, tunnel-all, managed, or custom"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedDnsMode {
    #[default]
    Inherit,
    Block,
    Allow,
}

impl FromStr for EncryptedDnsMode {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "inherit" => Ok(Self::Inherit),
            "block" => Ok(Self::Block),
            "allow" => Ok(Self::Allow),
            _ => Err(Error::InvalidConfig(format!(
                "invalid encrypted-DNS mode {value:?}; expected inherit, block, or allow"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainRuleKind {
    /// Official `*` and unprefixed behavior: raw string suffix match.
    Suffix,
    /// Official `@` behavior: exact domain or a label-boundary subdomain.
    Domain,
    /// Official `^` behavior: exact normalized name only.
    Exact,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DomainRule {
    kind: DomainRuleKind,
    domain: String,
    explicit_prefix: bool,
}

impl DomainRule {
    pub fn parse(value: &str) -> Result<Self> {
        let normalized = normalize_name(value);
        if normalized.is_empty() {
            return Err(Error::InvalidConfig(
                "DNS domain rule must not be empty".into(),
            ));
        }
        let (kind, domain, explicit_prefix) = match normalized.as_bytes()[0] {
            b'*' => (DomainRuleKind::Suffix, &normalized[1..], true),
            b'@' => (DomainRuleKind::Domain, &normalized[1..], true),
            b'^' => (DomainRuleKind::Exact, &normalized[1..], true),
            _ => (DomainRuleKind::Suffix, normalized.as_str(), false),
        };
        validate_name(domain, "DNS domain rule")?;
        Ok(Self {
            kind,
            domain: domain.to_owned(),
            explicit_prefix,
        })
    }

    pub const fn kind(&self) -> DomainRuleKind {
        self.kind
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn matches(&self, candidate: &str) -> bool {
        let candidate = normalize_name(candidate);
        match self.kind {
            DomainRuleKind::Suffix => candidate.ends_with(&self.domain),
            DomainRuleKind::Domain => {
                candidate == self.domain
                    || candidate
                        .strip_suffix(&self.domain)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
            DomainRuleKind::Exact => candidate == self.domain,
        }
    }
}

impl fmt::Display for DomainRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = match (self.kind, self.explicit_prefix) {
            (DomainRuleKind::Suffix, false) => "",
            (DomainRuleKind::Suffix, true) => "*",
            (DomainRuleKind::Domain, _) => "@",
            (DomainRuleKind::Exact, _) => "^",
        };
        write!(formatter, "{prefix}{}", self.domain)
    }
}

impl FromStr for DomainRule {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl TryFrom<String> for DomainRule {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

impl From<DomainRule> for String {
    fn from(value: DomainRule) -> Self {
        value.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsDefaults {
    pub server_mode: ServerListDnsMode,
    pub server_dns: Vec<Ipv4Addr>,
    pub local_mode: DnsServerMode,
    pub local_dns: Vec<Ipv4Addr>,
    pub split_mode: SplitDnsMode,
    pub custom_domains: Vec<DomainRule>,
    pub managed_domain_filter: bool,
    pub managed_inclusive: Vec<DomainRule>,
    pub managed_exclusive: Vec<DomainRule>,
    pub block_encrypted_dns: bool,
    pub secure_dns_hosts: Vec<String>,
    pub controller_service: bool,
}

impl Default for DnsDefaults {
    fn default() -> Self {
        Self {
            server_mode: ServerListDnsMode::Auto,
            server_dns: Vec::new(),
            local_mode: DnsServerMode::Server,
            local_dns: Vec::new(),
            split_mode: SplitDnsMode::Off,
            custom_domains: Vec::new(),
            managed_domain_filter: false,
            managed_inclusive: Vec::new(),
            managed_exclusive: Vec::new(),
            block_encrypted_dns: false,
            secure_dns_hosts: Vec::new(),
            controller_service: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_mode: Option<DnsServerMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servers: Option<Vec<Ipv4Addr>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_mode: Option<SplitDnsMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_domains: Option<Vec<DomainRule>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_dns: Option<EncryptedDnsMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doh_hosts: Option<Vec<String>>,
}

impl DnsOverrides {
    /// Merge two layers, taking every explicitly present value from `higher`.
    pub fn layered(lower: &Self, higher: &Self) -> Self {
        Self {
            server_mode: higher.server_mode.or(lower.server_mode),
            servers: higher.servers.clone().or_else(|| lower.servers.clone()),
            split_mode: higher.split_mode.or(lower.split_mode),
            split_domains: higher
                .split_domains
                .clone()
                .or_else(|| lower.split_domains.clone()),
            encrypted_dns: higher.encrypted_dns.or(lower.encrypted_dns),
            doh_hosts: higher.doh_hosts.clone().or_else(|| lower.doh_hosts.clone()),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self
            .servers
            .as_ref()
            .is_some_and(|servers| servers.len() > 2)
        {
            return Err(Error::InvalidConfig(
                "custom DNS accepts at most two IPv4 servers".into(),
            ));
        }
        if self.server_mode == Some(DnsServerMode::Custom)
            && self.servers.as_ref().is_none_or(Vec::is_empty)
        {
            return Err(Error::InvalidConfig(
                "custom DNS mode requires at least one --dns-server".into(),
            ));
        }
        if self.split_mode == Some(SplitDnsMode::Custom)
            && self.split_domains.as_ref().is_none_or(Vec::is_empty)
        {
            return Err(Error::InvalidConfig(
                "custom split DNS requires at least one domain rule".into(),
            ));
        }
        if self
            .split_domains
            .as_ref()
            .is_some_and(|domains| domains.len() > MAX_DOMAIN_RULES)
        {
            return Err(Error::InvalidConfig(format!(
                "split-DNS rule count exceeds {MAX_DOMAIN_RULES}"
            )));
        }
        if let Some(hosts) = &self.doh_hosts {
            if hosts.len() > MAX_DOMAIN_RULES {
                return Err(Error::InvalidConfig(format!(
                    "DoH host count exceeds {MAX_DOMAIN_RULES}"
                )));
            }
            for host in hosts {
                validate_name(&normalize_name(host), "DoH hostname")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveDnsPolicy {
    pub server_mode: DnsServerMode,
    pub servers: Vec<Ipv4Addr>,
    pub split_mode: SplitDnsMode,
    pub inclusive: Vec<DomainRule>,
    pub exclusive: Vec<DomainRule>,
    pub block_encrypted_dns: bool,
    pub doh_hosts: Vec<String>,
}

impl EffectiveDnsPolicy {
    pub fn direct(open_ack_dns: &[IpAddr]) -> Self {
        DnsPolicyResolver::resolve(
            &DnsDefaults::default(),
            &DnsOverrides::default(),
            open_ack_dns,
        )
        .expect("default DNS policy is valid")
    }

    pub const fn engine_enabled(&self) -> bool {
        self.block_encrypted_dns || self.dns_routing_enabled()
    }

    pub const fn dns_routing_enabled(&self) -> bool {
        !matches!(self.server_mode, DnsServerMode::Disabled)
            && !self.servers.is_empty()
            && !matches!(self.split_mode, SplitDnsMode::Off)
    }

    pub fn routes_through_tunnel(&self, name: &str) -> bool {
        match self.split_mode {
            SplitDnsMode::Off | SplitDnsMode::TunnelAll => true,
            SplitDnsMode::Managed | SplitDnsMode::Custom => {
                if self.exclusive.iter().any(|rule| rule.matches(name)) {
                    false
                } else {
                    self.inclusive.is_empty()
                        || self.inclusive.iter().any(|rule| rule.matches(name))
                }
            }
        }
    }

    pub fn blocks_doh_host(&self, name: &str) -> bool {
        let name = normalize_name(name);
        self.block_encrypted_dns && self.doh_hosts.iter().any(|blocked| blocked == &name)
    }
}

pub struct DnsPolicyResolver;

impl DnsPolicyResolver {
    pub fn resolve(
        defaults: &DnsDefaults,
        overrides: &DnsOverrides,
        open_ack_dns: &[IpAddr],
    ) -> Result<EffectiveDnsPolicy> {
        overrides.validate()?;
        let requested_server_mode = overrides.server_mode.unwrap_or(defaults.local_mode);
        let server_mode = if requested_server_mode == DnsServerMode::Server
            && defaults.server_mode == ServerListDnsMode::Disabled
        {
            DnsServerMode::Disabled
        } else {
            requested_server_mode
        };
        let servers = match server_mode {
            DnsServerMode::Disabled => Vec::new(),
            DnsServerMode::Custom => {
                let servers = overrides
                    .servers
                    .clone()
                    .unwrap_or_else(|| defaults.local_dns.clone());
                validate_custom_servers(&servers)?;
                dedup(servers)
            }
            DnsServerMode::Server => resolve_server_dns(defaults, open_ack_dns),
        };

        let split_mode = overrides.split_mode.unwrap_or(defaults.split_mode);
        let local_domains = overrides
            .split_domains
            .clone()
            .unwrap_or_else(|| defaults.custom_domains.clone());
        let (inclusive, exclusive) = match split_mode {
            SplitDnsMode::Off | SplitDnsMode::TunnelAll => (Vec::new(), Vec::new()),
            SplitDnsMode::Managed => (
                dedup_capped(defaults.managed_inclusive.clone()),
                dedup_capped(defaults.managed_exclusive.clone()),
            ),
            SplitDnsMode::Custom => {
                let mut inclusive = local_domains;
                if defaults.managed_domain_filter {
                    inclusive.extend(defaults.managed_inclusive.iter().cloned());
                }
                (
                    dedup_capped(inclusive),
                    dedup_capped(defaults.managed_exclusive.clone()),
                )
            }
        };
        let block_encrypted_dns = match overrides.encrypted_dns.unwrap_or(EncryptedDnsMode::Inherit)
        {
            EncryptedDnsMode::Inherit => defaults.block_encrypted_dns,
            EncryptedDnsMode::Block => true,
            EncryptedDnsMode::Allow => false,
        };
        let mut doh_hosts = defaults.secure_dns_hosts.clone();
        if let Some(extra) = &overrides.doh_hosts {
            doh_hosts.extend(extra.iter().cloned());
        }
        doh_hosts.push(DEFAULT_DOH_CANARY.into());
        let doh_hosts = normalize_names(doh_hosts)?;

        Ok(EffectiveDnsPolicy {
            server_mode,
            servers,
            split_mode,
            inclusive,
            exclusive,
            block_encrypted_dns,
            doh_hosts,
        })
    }
}

fn resolve_server_dns(defaults: &DnsDefaults, open_ack_dns: &[IpAddr]) -> Vec<Ipv4Addr> {
    if defaults.server_mode == ServerListDnsMode::Disabled {
        return Vec::new();
    }
    let mut configured = dedup(
        defaults
            .server_dns
            .iter()
            .copied()
            .filter(|address| is_usable_server(*address))
            .collect(),
    );
    configured.truncate(2);
    if defaults.server_mode == ServerListDnsMode::Custom && !configured.is_empty() {
        return configured;
    }
    let mut open_ack = dedup(
        open_ack_dns
            .iter()
            .filter_map(|address| match address {
                IpAddr::V4(address) if is_usable_server(*address) => Some(*address),
                _ => None,
            })
            .collect(),
    );
    open_ack.truncate(2);
    if !open_ack.is_empty() {
        return open_ack;
    }
    if defaults.controller_service {
        vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(114, 114, 114, 114)]
    } else {
        Vec::new()
    }
}

fn validate_custom_servers(servers: &[Ipv4Addr]) -> Result<()> {
    if servers.is_empty() || servers.len() > 2 {
        return Err(Error::InvalidConfig(
            "custom DNS requires one or two IPv4 servers".into(),
        ));
    }
    if let Some(server) = servers.iter().find(|server| !is_usable_server(**server)) {
        return Err(Error::InvalidConfig(format!(
            "custom DNS server {server} is not a usable unicast IPv4 address"
        )));
    }
    Ok(())
}

fn is_usable_server(address: Ipv4Addr) -> bool {
    !address.is_unspecified() && !address.is_multicast() && address != Ipv4Addr::BROADCAST
}

fn normalize_names(values: Vec<String>) -> Result<Vec<String>> {
    let mut output = Vec::new();
    let mut seen = HashSet::new();
    for value in values {
        let value = normalize_name(&value);
        validate_name(&value, "DoH hostname")?;
        if seen.insert(value.clone()) {
            output.push(value);
        }
    }
    Ok(output)
}

fn normalize_name(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn validate_name(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 253
        || value.starts_with('.')
        || value.ends_with('.')
        || value.split('.').any(|part| {
            part.is_empty()
                || part.len() > 63
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        return Err(Error::InvalidConfig(format!("invalid {label} {value:?}")));
    }
    Ok(())
}

fn dedup<T: Eq + std::hash::Hash + Clone>(values: Vec<T>) -> Vec<T> {
    let mut seen = HashSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn dedup_capped(values: Vec<DomainRule>) -> Vec<DomainRule> {
    let received = values.len();
    let mut values = dedup(values);
    if values.len() > MAX_DOMAIN_RULES {
        tracing::warn!(
            received,
            cap = MAX_DOMAIN_RULES,
            "domain-filter rule list exceeds cap; truncating"
        );
        values.truncate(MAX_DOMAIN_RULES);
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(value: &str) -> DomainRule {
        value.parse().unwrap()
    }

    #[test]
    fn implements_official_domain_prefixes() {
        assert!(rule("*example.com").matches("notexample.com"));
        assert!(rule("example.com").matches("notexample.com"));
        assert!(rule("@example.com").matches("www.example.com"));
        assert!(rule("@example.com").matches("example.com."));
        assert!(!rule("@example.com").matches("notexample.com"));
        assert!(rule("^example.com").matches("EXAMPLE.COM."));
        assert!(!rule("^example.com").matches("www.example.com"));
    }

    #[test]
    fn exclusion_wins_and_empty_inclusive_tunnels() {
        let mut policy = EffectiveDnsPolicy::direct(&[]);
        policy.split_mode = SplitDnsMode::Managed;
        policy.exclusive = vec![rule("@local.test")];
        assert!(!policy.routes_through_tunnel("host.local.test"));
        assert!(policy.routes_through_tunnel("public.test"));
        policy.inclusive = vec![rule("@corp.test")];
        assert!(policy.routes_through_tunnel("api.corp.test"));
        assert!(!policy.routes_through_tunnel("public.test"));
    }

    #[test]
    fn resolves_serverlist_custom_openack_and_controller_fallback() {
        let mut defaults = DnsDefaults {
            server_mode: ServerListDnsMode::Custom,
            server_dns: vec![Ipv4Addr::UNSPECIFIED],
            controller_service: true,
            ..DnsDefaults::default()
        };
        let policy = DnsPolicyResolver::resolve(
            &defaults,
            &DnsOverrides::default(),
            &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))],
        )
        .unwrap();
        assert_eq!(policy.servers, [Ipv4Addr::new(192, 0, 2, 53)]);

        defaults.server_dns = vec![
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 2),
            Ipv4Addr::new(192, 0, 2, 3),
        ];
        let policy = DnsPolicyResolver::resolve(&defaults, &DnsOverrides::default(), &[]).unwrap();
        assert_eq!(
            policy.servers,
            [Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)]
        );

        defaults.server_dns.clear();
        let policy = DnsPolicyResolver::resolve(&defaults, &DnsOverrides::default(), &[]).unwrap();
        assert_eq!(
            policy.servers,
            [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(114, 114, 114, 114)]
        );
    }

    #[test]
    fn layers_profile_below_cli() {
        let profile = DnsOverrides {
            server_mode: Some(DnsServerMode::Custom),
            servers: Some(vec![Ipv4Addr::new(192, 0, 2, 1)]),
            ..DnsOverrides::default()
        };
        let cli = DnsOverrides {
            server_mode: Some(DnsServerMode::Disabled),
            ..DnsOverrides::default()
        };
        let merged = DnsOverrides::layered(&profile, &cli);
        assert_eq!(merged.server_mode, Some(DnsServerMode::Disabled));
        assert_eq!(merged.servers, profile.servers);
    }

    #[test]
    fn disabled_serverlist_disables_dns_routing_but_not_encrypted_dns_blocking() {
        let defaults = DnsDefaults {
            server_mode: ServerListDnsMode::Disabled,
            split_mode: SplitDnsMode::TunnelAll,
            ..DnsDefaults::default()
        };
        let policy = DnsPolicyResolver::resolve(&defaults, &DnsOverrides::default(), &[]).unwrap();
        assert_eq!(policy.server_mode, DnsServerMode::Disabled);
        assert!(!policy.engine_enabled());

        let policy = DnsPolicyResolver::resolve(
            &defaults,
            &DnsOverrides {
                encrypted_dns: Some(EncryptedDnsMode::Block),
                ..DnsOverrides::default()
            },
            &[],
        )
        .unwrap();
        assert!(policy.engine_enabled());
        assert!(!policy.dns_routing_enabled());
    }
}
