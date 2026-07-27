use super::auth::{self, AuthMethod, ControllerAuth};
use super::controller::{self, ControllerConfiguration, ServerInfo, SrEntry, SrGroup};
use super::http::{HttpRequest, HttpTransport, UreqTransport};
use super::keepalive::{self, KeepaliveCredentials, KeepaliveRequest, KeepaliveResponse};
use super::lookup::{LookupClient, LookupResult, ServiceType};
use super::oidc::OidcConfig;
use super::oidc::{self, OidcIdentity, PendingAuthorization};
use super::posture;
use crate::client;
use crate::config::SegmentRoutingConfig;
use crate::sr::SrEncryptionAlgorithm;
use crate::{Client, ClientConfig, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::Ipv4Addr;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use std::thread;
use std::time::Duration;
use url::Url;
use zeroize::Zeroize;

static NEXT_LOCAL_SR_ID: AtomicU32 = AtomicU32::new(0);
const MAX_CONCURRENT_LINE_PROBES: usize = 16;

#[derive(Debug)]
pub struct DiscoveredDomain {
    pub lookup: LookupResult,
    pub auth: ControllerAuth,
}

impl DiscoveredDomain {
    pub fn active_domain(&self) -> &str {
        self.lookup.active_domain()
    }
}

pub struct PendingDomainAuthorization {
    config: OidcConfig,
    pending: PendingAuthorization,
}

impl std::fmt::Debug for PendingDomainAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingDomainAuthorization")
            .field("authorization_url", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl PendingDomainAuthorization {
    pub fn authorization_url(&self) -> &url::Url {
        self.pending.authorization_url()
    }
}

/// A stable, non-secret preference for a controller-managed line.
///
/// Traditional lines are keyed by the controller's server ID. Segment-routing
/// lines are keyed by group because entries inside a group are ordered
/// primary/failover paths and may receive runtime-only IDs during validation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LinePreference {
    #[default]
    Auto,
    Iwan {
        server_id: String,
    },
    SegmentRouting {
        group_id: i32,
    },
}

impl fmt::Display for LinePreference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => formatter.write_str("auto"),
            Self::Iwan { server_id } => write!(formatter, "iwan:{server_id}"),
            Self::SegmentRouting { group_id } => write!(formatter, "sr:{group_id}"),
        }
    }
}

impl FromStr for LinePreference {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let value = value.trim();
        if value.eq_ignore_ascii_case("auto") {
            return Ok(Self::Auto);
        }
        let (kind, id) = value
            .split_once(':')
            .ok_or_else(|| "line must be auto, iwan:<server-id>, or sr:<group-id>".to_owned())?;
        match kind.to_ascii_lowercase().as_str() {
            "iwan" => {
                let id = id
                    .parse::<i32>()
                    .ok()
                    .filter(|id| *id != -1)
                    .ok_or_else(|| "iWAN server ID must be an integer other than -1".to_owned())?;
                Ok(Self::Iwan {
                    server_id: id.to_string(),
                })
            }
            "sr" => {
                let group_id = id
                    .parse::<i32>()
                    .map_err(|_| "SR group ID must be an integer".to_owned())?;
                Ok(Self::SegmentRouting { group_id })
            }
            _ => Err("line must be auto, iwan:<server-id>, or sr:<group-id>".to_owned()),
        }
    }
}

/// Reachability result for one selectable controller-managed line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineProbe {
    pub preference: LinePreference,
    pub name: String,
    pub name_en: String,
    pub endpoint: Option<String>,
    pub latency: Option<Duration>,
    pub error: Option<String>,
}

impl LineProbe {
    pub const fn reachable(&self) -> bool {
        self.latency.is_some()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OidcLoginOptions<'a> {
    pub posture_check_results: &'a [Value],
    pub posture_version: Option<i64>,
    pub ping_timeout: Duration,
    pub line: &'a LinePreference,
}

#[derive(Debug, Clone)]
pub enum SelectedIngress {
    Iwan {
        server: ServerInfo,
        latency: Duration,
    },
    SegmentRouting {
        group_id: i32,
        entry: SrEntry,
        latency: Duration,
    },
}

impl SelectedIngress {
    pub const fn latency(&self) -> Duration {
        match self {
            Self::Iwan { latency, .. } | Self::SegmentRouting { latency, .. } => *latency,
        }
    }

    pub fn line_preference(&self) -> LinePreference {
        match self {
            Self::Iwan { server, .. } => LinePreference::Iwan {
                server_id: server.id.clone(),
            },
            Self::SegmentRouting { group_id, .. } => LinePreference::SegmentRouting {
                group_id: *group_id,
            },
        }
    }
}

struct ConnectionCredentials {
    username: String,
    password: String,
}

impl std::fmt::Debug for ConnectionCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectionCredentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ConnectionCredentials {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

#[derive(Debug)]
pub struct PreparedConnection {
    pub domain: String,
    pub ingress: SelectedIngress,
    pub configuration: ControllerConfiguration,
    credentials: ConnectionCredentials,
}

impl PreparedConnection {
    pub fn client(&self) -> Result<Client> {
        self.configuration.enforce_device_binding()?;
        let config = match &self.ingress {
            SelectedIngress::Iwan { server, .. } => ClientConfig::new(server.endpoint()),
            SelectedIngress::SegmentRouting { entry, .. } => {
                let mut config = ClientConfig::new(format_endpoint(
                    &entry.ingress.server_name,
                    entry.ingress.server_port,
                )?);
                if let Ok(mtu) = u16::try_from(entry.ingress.mtu)
                    && mtu >= 576
                {
                    config.mtu = mtu;
                }
                config.segment_routing = Some(segment_routing_config(entry)?);
                config
            }
        };
        config.validate()?;
        Client::new(
            config,
            self.credentials.username.clone(),
            self.credentials.password.clone(),
        )
    }

    /// Probe all selectable lines in the retained controller configuration.
    ///
    /// Probes are bounded to avoid creating an unbounded number of threads for
    /// a malformed controller response. Result order matches controller order.
    pub fn probe_lines(&self, timeout: Duration) -> Result<Vec<LineProbe>> {
        probe_lines(&self.configuration, timeout)
    }
}

pub struct DomainClient<T = UreqTransport> {
    lookup: LookupClient<T>,
}

impl DomainClient<UreqTransport> {
    pub fn new(cache_directory: Option<PathBuf>) -> Self {
        let lookup = LookupClient::with_transport(UreqTransport::new());
        Self {
            lookup: match cache_directory {
                Some(directory) => lookup.with_cache(directory),
                None => lookup,
            },
        }
    }
}

impl<T: HttpTransport> DomainClient<T> {
    pub fn with_transport(transport: T, cache_directory: Option<PathBuf>) -> Self {
        let lookup = LookupClient::with_transport(transport);
        Self {
            lookup: match cache_directory {
                Some(directory) => lookup.with_cache(directory),
                None => lookup,
            },
        }
    }

    pub fn discover(&self, domain: &str, device_id: &str) -> Result<DiscoveredDomain> {
        let lookup = self.lookup.lookup(domain, device_id)?;
        let auth = auth::fetch_or_credential(&lookup, device_id, self.lookup.transport());
        Ok(DiscoveredDomain { lookup, auth })
    }

    pub fn send_keepalive(
        &self,
        endpoint: &str,
        credentials: &KeepaliveCredentials,
        request: &KeepaliveRequest,
    ) -> Result<KeepaliveResponse> {
        keepalive::send(self.lookup.transport(), endpoint, credentials, request)
    }

    pub fn begin_oidc(
        &self,
        domain: &DiscoveredDomain,
        redirect_uri: &str,
    ) -> Result<PendingDomainAuthorization> {
        if domain.auth.method != AuthMethod::Oidc {
            return Err(Error::Oidc(
                "the discovered domain does not use OIDC".into(),
            ));
        }
        let config = domain
            .auth
            .oidc
            .as_ref()
            .ok_or_else(|| Error::Oidc("OIDC auth response has no configuration".into()))?
            .provider_config(redirect_uri);
        config.validate()?;
        let pending = oidc::begin(&config)?;
        Ok(PendingDomainAuthorization { config, pending })
    }

    pub fn complete_oidc(
        &self,
        pending: &PendingDomainAuthorization,
        redirect_url: &str,
    ) -> Result<OidcIdentity> {
        oidc::complete(
            &pending.config,
            self.lookup.transport(),
            &pending.pending,
            redirect_url,
        )
    }

    pub fn refresh_oidc(
        &self,
        domain: &DiscoveredDomain,
        redirect_uri: &str,
        refresh_token: &str,
        user_id: &str,
        username: &str,
    ) -> Result<OidcIdentity> {
        if domain.auth.method != AuthMethod::Oidc {
            return Err(Error::Oidc(
                "the discovered domain does not use OIDC".into(),
            ));
        }
        let config = domain
            .auth
            .oidc
            .as_ref()
            .ok_or_else(|| Error::Oidc("OIDC auth response has no configuration".into()))?
            .provider_config(redirect_uri);
        oidc::refresh(
            &config,
            self.lookup.transport(),
            refresh_token,
            user_id,
            username,
        )
    }

    pub fn password_login(
        &self,
        domain: &DiscoveredDomain,
        device_id: &str,
        username: impl Into<String>,
        password: impl Into<String>,
        ping_timeout: Duration,
    ) -> Result<PreparedConnection> {
        self.password_login_with_line(
            domain,
            device_id,
            username,
            password,
            ping_timeout,
            &LinePreference::Auto,
        )
    }

    pub fn password_login_with_line(
        &self,
        domain: &DiscoveredDomain,
        device_id: &str,
        username: impl Into<String>,
        password: impl Into<String>,
        ping_timeout: Duration,
        line: &LinePreference,
    ) -> Result<PreparedConnection> {
        if domain.auth.method == AuthMethod::Oidc {
            return Err(Error::ManagedFlow(
                "this domain uses single sign-on authentication".into(),
            ));
        }
        let username = username.into();
        let password = password.into();
        if username.is_empty() || password.is_empty() {
            return Err(Error::ManagedFlow(
                "username and password must not be empty".into(),
            ));
        }
        let configuration = self.fetch_configuration(domain, device_id, None, None, None)?;
        let ingress = select_ingress(&configuration, ping_timeout, line)?;
        let credentials =
            credentials_for_ingress(&ingress, Some((&username, &password)), &configuration)?;
        // The login-screen OPEN is a one-shot authentication probe. Closing
        // this session is intentional; the actual VPN connection performs OPEN again.
        let probe = client_for(&ingress, &credentials)?.authenticate_once()?;
        probe.close_probe()?;
        Ok(PreparedConnection {
            domain: domain.active_domain().to_owned(),
            ingress,
            configuration,
            credentials,
        })
    }

    pub fn oidc_login(
        &self,
        domain: &DiscoveredDomain,
        device_id: &str,
        identity: &OidcIdentity,
        posture_check_results: &[Value],
        posture_version: Option<i64>,
        ping_timeout: Duration,
    ) -> Result<PreparedConnection> {
        self.oidc_login_with_options(
            domain,
            device_id,
            identity,
            OidcLoginOptions {
                posture_check_results,
                posture_version,
                ping_timeout,
                line: &LinePreference::Auto,
            },
        )
    }

    pub fn oidc_login_with_options(
        &self,
        domain: &DiscoveredDomain,
        device_id: &str,
        identity: &OidcIdentity,
        options: OidcLoginOptions<'_>,
    ) -> Result<PreparedConnection> {
        if domain.auth.method != AuthMethod::Oidc {
            return Err(Error::ManagedFlow(
                "this domain uses credential authentication".into(),
            ));
        }
        let configuration = self.fetch_configuration(
            domain,
            device_id,
            Some(identity.access_token.as_str()),
            Some(&identity.username),
            options.posture_version,
        )?;
        let posture_version = match configuration.posture() {
            Some(posture_config) => posture::posture_gate_version(posture_config)?,
            None => options.posture_version,
        };
        if let Some(version) = posture_version {
            let evaluation = posture::evaluate(
                self.lookup.transport(),
                config_url(&domain.lookup)?,
                Some(identity.access_token.as_str()),
                &identity.user_id,
                version,
                options.posture_check_results,
            )?;
            if !evaluation.allowed() {
                return Err(Error::PostureDenied);
            }
        }
        let ingress = select_ingress(&configuration, options.ping_timeout, options.line)?;
        let credentials = credentials_for_ingress(&ingress, None, &configuration)?;
        Ok(PreparedConnection {
            domain: domain.active_domain().to_owned(),
            ingress,
            configuration,
            credentials,
        })
    }

    fn fetch_configuration(
        &self,
        domain: &DiscoveredDomain,
        device_id: &str,
        access_token: Option<&str>,
        username: Option<&str>,
        posture_version: Option<i64>,
    ) -> Result<ControllerConfiguration> {
        let configuration = if domain.lookup.service_type == ServiceType::Controller
            && domain.auth.method == AuthMethod::Oidc
        {
            let access_token = access_token
                .filter(|token| !token.is_empty())
                .ok_or_else(|| {
                    Error::Oidc("OIDC config request requires an access token".into())
                })?;
            controller::fetch(
                config_url(&domain.lookup)?,
                self.lookup.transport(),
                controller::ConfigParameters {
                    domain: domain.active_domain(),
                    client_type: super::auth::client_platform(),
                    controller_app_id: domain.lookup.controller_app_id().ok_or_else(|| {
                        Error::Controller("controller lookup has no app_id".into())
                    })?,
                    access_token: Some(access_token),
                    username,
                    device_id,
                    posture_version,
                },
            )?
        } else {
            // The credential path uses the controller-provided serverlist
            // endpoint. `/config` belongs to the OIDC path.
            fetch_serverlist(&domain.lookup, self.lookup.transport())?
        };
        configuration.enforce_device_binding()?;
        Ok(configuration)
    }
}

fn fetch_serverlist<T: HttpTransport>(
    lookup: &LookupResult,
    transport: &T,
) -> Result<ControllerConfiguration> {
    let endpoint = lookup
        .resolved_server_list_url()
        .ok_or_else(|| Error::Controller("lookup has no server list URL".into()))?;
    validate_https_endpoint("server list", endpoint)?;
    let response = transport.execute(HttpRequest {
        method: "GET",
        url: endpoint.to_owned(),
        headers: Vec::new(),
        body: Vec::new(),
        timeout: None,
    })?;
    if response.status != 200 {
        return Err(Error::Controller(format!(
            "server list returned HTTP {}",
            response.status
        )));
    }
    let raw: Value = serde_json::from_slice(&response.body)
        .map_err(|error| Error::Controller(format!("invalid server list: {error}")))?;
    let raw = raw.get("data").cloned().unwrap_or(raw);
    let raw = if raw.is_array() {
        serde_json::json!({"serverlist": raw})
    } else {
        raw
    };
    Ok(ControllerConfiguration::from_raw(raw))
}

fn config_url(lookup: &LookupResult) -> Result<&str> {
    lookup
        .config_url()
        .ok_or_else(|| Error::Controller("controller lookup has no config URL".into()))
}

fn validate_https_endpoint(name: &str, value: &str) -> Result<()> {
    let url = Url::parse(value)
        .map_err(|error| Error::Controller(format!("invalid {name} URL: {error}")))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Controller(format!(
            "{name} URL must be HTTPS without credentials or a fragment"
        )));
    }
    Ok(())
}

fn select_ingress(
    configuration: &ControllerConfiguration,
    timeout: Duration,
    preference: &LinePreference,
) -> Result<SelectedIngress> {
    select_ingress_with_preference(configuration, preference, |endpoint| {
        ping_endpoint(endpoint, timeout).map(|(_, latency)| latency)
    })
}

fn select_ingress_with(
    configuration: &ControllerConfiguration,
    mut ping: impl FnMut(&str) -> Result<Duration>,
) -> Result<SelectedIngress> {
    let mut candidates = Vec::new();
    for server in configuration.iwan_servers()? {
        if let Ok(latency) = ping(&server.endpoint()) {
            candidates.push(SelectedIngress::Iwan { server, latency });
        }
    }
    for group in sanitize_sr_groups(configuration.sr_groups()?) {
        for entry in ordered_sr_entries(&group) {
            let Ok(endpoint) =
                format_endpoint(&entry.ingress.server_name, entry.ingress.server_port)
            else {
                continue;
            };
            if let Ok(latency) = ping(&endpoint) {
                candidates.push(SelectedIngress::SegmentRouting {
                    group_id: group.id,
                    entry,
                    latency,
                });
                // `primary_index` is the preferred SR for this group. Other
                // entries are failover choices, not competing groups.
                break;
            }
        }
    }
    candidates
        .into_iter()
        .min_by(|left, right| {
            left.latency()
                .partial_cmp(&right.latency())
                .unwrap_or(Ordering::Equal)
        })
        .ok_or(Error::Timeout("no ingress server answered ping"))
}

fn select_ingress_with_preference(
    configuration: &ControllerConfiguration,
    preference: &LinePreference,
    mut ping: impl FnMut(&str) -> Result<Duration>,
) -> Result<SelectedIngress> {
    match preference {
        LinePreference::Auto => select_ingress_with(configuration, ping),
        LinePreference::Iwan { server_id } => {
            let server = configuration
                .iwan_servers()?
                .into_iter()
                .find(|server| &server.id == server_id)
                .ok_or_else(|| Error::LineNotFound(preference.to_string()))?;
            let endpoint = server.endpoint();
            let latency = ping(&endpoint).map_err(|error| Error::LineUnavailable {
                line: preference.to_string(),
                reason: error.to_string(),
            })?;
            Ok(SelectedIngress::Iwan { server, latency })
        }
        LinePreference::SegmentRouting { group_id } => {
            let mut groups = sanitize_sr_groups(configuration.sr_groups()?)
                .into_iter()
                .filter(|group| group.id == *group_id);
            let group = groups
                .next()
                .ok_or_else(|| Error::LineNotFound(preference.to_string()))?;
            if groups.next().is_some() {
                return Err(Error::InvalidConfig(format!(
                    "controller returned duplicate SR group ID {group_id}"
                )));
            }
            select_sr_group_with(group, &mut ping).map_err(|error| Error::LineUnavailable {
                line: preference.to_string(),
                reason: error.to_string(),
            })
        }
    }
}

fn select_sr_group_with(
    group: SrGroup,
    ping: &mut impl FnMut(&str) -> Result<Duration>,
) -> Result<SelectedIngress> {
    let group_id = group.id;
    let mut last_error = None;
    for entry in ordered_sr_entries(&group) {
        let endpoint = match format_endpoint(&entry.ingress.server_name, entry.ingress.server_port)
        {
            Ok(endpoint) => endpoint,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        match ping(&endpoint) {
            Ok(latency) => {
                return Ok(SelectedIngress::SegmentRouting {
                    group_id,
                    entry,
                    latency,
                });
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        Error::InvalidConfig(format!("SR group {group_id} contains no valid entry"))
    }))
}

fn ordered_sr_entries(group: &SrGroup) -> Vec<SrEntry> {
    let mut entries = group.entries.clone();
    let primary = usize::try_from(group.primary_index)
        .ok()
        .filter(|index| *index < entries.len())
        .unwrap_or(0);
    if primary < entries.len() {
        entries.swap(0, primary);
    }
    entries
}

#[derive(Debug)]
enum LineTarget {
    Iwan(ServerInfo),
    SegmentRouting(SrGroup),
}

fn probe_lines(
    configuration: &ControllerConfiguration,
    timeout: Duration,
) -> Result<Vec<LineProbe>> {
    let mut targets = configuration
        .iwan_servers()?
        .into_iter()
        .map(LineTarget::Iwan)
        .collect::<Vec<_>>();
    targets.extend(
        sanitize_sr_groups(configuration.sr_groups()?)
            .into_iter()
            .map(LineTarget::SegmentRouting),
    );

    let mut targets = targets.into_iter();
    let mut probes = Vec::new();
    loop {
        let batch = targets
            .by_ref()
            .take(MAX_CONCURRENT_LINE_PROBES)
            .collect::<Vec<_>>();
        if batch.is_empty() {
            break;
        }
        let batch_probes = thread::scope(|scope| {
            batch
                .into_iter()
                .map(|target| scope.spawn(move || probe_line_target(target, timeout)))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|worker| {
                    worker.join().map_err(|_| {
                        Error::ManagedFlow("managed line probe worker panicked".into())
                    })
                })
                .collect::<Result<Vec<_>>>()
        })?;
        probes.extend(batch_probes);
    }
    Ok(probes)
}

fn probe_line_target(target: LineTarget, timeout: Duration) -> LineProbe {
    match target {
        LineTarget::Iwan(server) => {
            let endpoint = server.endpoint();
            let result = ping_endpoint(&endpoint, timeout).map(|(_, latency)| latency);
            LineProbe {
                preference: LinePreference::Iwan {
                    server_id: server.id,
                },
                name: server.name,
                name_en: server.name_en,
                endpoint: Some(endpoint),
                latency: result.as_ref().ok().copied(),
                error: result.err().map(|error| error.to_string()),
            }
        }
        LineTarget::SegmentRouting(group) => {
            let preference = LinePreference::SegmentRouting { group_id: group.id };
            let name = group.name.clone();
            let name_en = group.name_en.clone();
            let mut selected_endpoint = None;
            let mut latency = None;
            let mut last_error = None;
            for entry in ordered_sr_entries(&group) {
                let endpoint =
                    match format_endpoint(&entry.ingress.server_name, entry.ingress.server_port) {
                        Ok(endpoint) => endpoint,
                        Err(error) => {
                            last_error = Some(error.to_string());
                            continue;
                        }
                    };
                match ping_endpoint(&endpoint, timeout) {
                    Ok((_, measured)) => {
                        selected_endpoint = Some(endpoint);
                        latency = Some(measured);
                        last_error = None;
                        break;
                    }
                    Err(error) => {
                        selected_endpoint = Some(endpoint);
                        last_error = Some(error.to_string());
                    }
                }
            }
            LineProbe {
                preference,
                name,
                name_en,
                endpoint: selected_endpoint,
                latency,
                error: if latency.is_some() {
                    None
                } else {
                    last_error.or_else(|| {
                        Some(format!("SR group {} contains no reachable entry", group.id))
                    })
                },
            }
        }
    }
}

fn ping_endpoint(endpoint: &str, timeout: Duration) -> Result<(SocketAddr, Duration)> {
    let address = endpoint
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::InvalidConfig("server resolved to no address".into()))?;
    // Launch three independent PING_REQUEST probes and use the lowest
    // successful RTT. Failed probes do not discard successful ones.
    let latency = thread::scope(|scope| {
        let attempts = (0..3)
            .map(|_| scope.spawn(move || client::ping(address, timeout)))
            .collect::<Vec<_>>();
        attempts
            .into_iter()
            .filter_map(|attempt| attempt.join().ok()?.ok())
            .min()
    })
    .ok_or(Error::Timeout("ping"))?;
    Ok((address, latency))
}

fn credentials_for_ingress(
    ingress: &SelectedIngress,
    global: Option<(&str, &str)>,
    configuration: &ControllerConfiguration,
) -> Result<ConnectionCredentials> {
    match ingress {
        SelectedIngress::Iwan { server, .. } => {
            if let Some((username, password)) = global {
                return Ok(ConnectionCredentials {
                    username: username.to_owned(),
                    password: password.to_owned(),
                });
            }
            let mut credentials = configuration.server_credentials()?;
            let credentials = credentials.remove(&server.id).ok_or_else(|| {
                Error::Controller(format!(
                    "configuration has no credentials for server {}",
                    server.id
                ))
            })?;
            Ok(ConnectionCredentials {
                username: credentials.username.clone(),
                password: credentials.password.clone(),
            })
        }
        SelectedIngress::SegmentRouting { entry, .. } => {
            if entry.ingress.username.is_empty() || entry.ingress.password.is_empty() {
                return Err(Error::Controller(
                    "selected SR ingress has no credentials".into(),
                ));
            }
            Ok(ConnectionCredentials {
                username: entry.ingress.username.clone(),
                password: entry.ingress.password.clone(),
            })
        }
    }
}

fn client_for(ingress: &SelectedIngress, credentials: &ConnectionCredentials) -> Result<Client> {
    let prepared = PreparedConnection {
        domain: String::new(),
        ingress: ingress.clone(),
        configuration: ControllerConfiguration::from_raw(Value::Null),
        credentials: ConnectionCredentials {
            username: credentials.username.clone(),
            password: credentials.password.clone(),
        },
    };
    prepared.client()
}

fn segment_routing_config(entry: &SrEntry) -> Result<SegmentRoutingConfig> {
    let encrypt_algo = match entry.encrypt_algo.as_str() {
        "" | "null" => SrEncryptionAlgorithm::None,
        "aes128" => SrEncryptionAlgorithm::Aes128,
        "aes256" => SrEncryptionAlgorithm::Aes256,
        _ => {
            return Err(Error::InvalidConfig(format!(
                "unsanitized SR encryption algorithm {:?}",
                entry.encrypt_algo
            )));
        }
    };
    let local_sr_id = entry
        .local_sr_id
        .ok_or_else(|| Error::InvalidConfig("SR entry has no runtime local SRID".into()))?;
    Ok(SegmentRoutingConfig {
        id: u32::try_from(entry.id)
            .ok()
            .filter(|id| *id != 0)
            .unwrap_or(local_sr_id),
        keepalive: entry.keepalive.unwrap_or(false),
        encrypt_algo,
        encrypt_key: entry.encrypt_key.clone(),
        links: entry
            .path
            .links
            .iter()
            .copied()
            .map(|link| {
                u32::try_from(link)
                    .map_err(|_| Error::InvalidConfig("SR link must be positive".into()))
            })
            .collect::<Result<_>>()?,
        local_sr_id: Some(local_sr_id),
    })
}

fn sanitize_sr_groups(
    mut groups: Vec<super::controller::SrGroup>,
) -> Vec<super::controller::SrGroup> {
    let mut global_id_counts = HashMap::new();
    for entry in groups.iter().flat_map(|group| &group.entries) {
        *global_id_counts.entry(entry.id).or_insert(0_usize) += 1;
    }
    let reserved_ids = global_id_counts
        .into_iter()
        .filter_map(|(id, count)| {
            if count != 1 {
                return None;
            }
            u32::try_from(id).ok().filter(|id| *id != 0)
        })
        .collect::<HashSet<_>>();
    let mut assigned_ids = HashSet::new();
    let mut sanitized = Vec::new();

    for mut group in groups.drain(..) {
        group.entries.truncate(5);
        if group.entries.is_empty() {
            continue;
        }
        let primary = usize::try_from(group.primary_index)
            .ok()
            .filter(|index| *index < group.entries.len())
            .unwrap_or(0);
        let mut group_id_counts = HashMap::new();
        for entry in &group.entries {
            *group_id_counts.entry(entry.id).or_insert(0_usize) += 1;
        }
        for entry in &mut group.entries {
            normalize_sr_entry(entry);
            let original = u32::try_from(entry.id).ok().filter(|id| *id != 0);
            let local_sr_id = original
                .filter(|_| group_id_counts.get(&entry.id) == Some(&1))
                .filter(|id| assigned_ids.insert(*id))
                .unwrap_or_else(|| next_local_sr_id(&mut assigned_ids, &reserved_ids));
            entry.local_sr_id = Some(local_sr_id);
        }
        let primary_local_sr_id = group.entries[primary].local_sr_id;
        group.entries.retain(valid_sr_entry);
        if group.entries.is_empty() {
            continue;
        }
        group.primary_index = primary_local_sr_id
            .and_then(|id| {
                group
                    .entries
                    .iter()
                    .position(|entry| entry.local_sr_id == Some(id))
            })
            .and_then(|index| i32::try_from(index).ok())
            .unwrap_or(0);
        sanitized.push(group);
    }
    sanitized
}

fn normalize_sr_entry(entry: &mut SrEntry) {
    if !(576..=1_500).contains(&entry.ingress.mtu) {
        entry.ingress.mtu = 1_392;
    }
    let required_key_units = match entry.encrypt_algo.as_str() {
        "aes128" => Some(16),
        "aes256" => Some(32),
        _ => {
            entry.encrypt_algo = "null".into();
            entry.encrypt_key.zeroize();
            entry.encrypt_key.clear();
            None
        }
    };
    if required_key_units.is_some_and(|minimum| entry.encrypt_key.encode_utf16().count() < minimum)
    {
        entry.encrypt_algo = "null".into();
        entry.encrypt_key.zeroize();
        entry.encrypt_key.clear();
    }
    if entry.keepalive == Some(true) && entry.path.links.len() < 6 {
        entry.keepalive = Some(false);
    }
}

fn valid_sr_entry(entry: &SrEntry) -> bool {
    !entry.ingress.server_name.is_empty()
        && (1..=65_535).contains(&entry.ingress.server_port)
        && !entry.ingress.username.is_empty()
        && !entry.ingress.password.is_empty()
        && (1..=6).contains(&entry.path.links.len())
        && entry
            .path
            .links
            .iter()
            .all(|link| (1..=0x00ff_ffff).contains(link))
        && entry.ip.parse::<Ipv4Addr>().is_ok()
}

fn next_local_sr_id(assigned: &mut HashSet<u32>, reserved: &HashSet<u32>) -> u32 {
    loop {
        let candidate = NEXT_LOCAL_SR_ID
            .fetch_add(1, AtomicOrdering::Relaxed)
            .wrapping_add(1);
        if candidate != 0 && !reserved.contains(&candidate) && assigned.insert(candidate) {
            return candidate;
        }
    }
}

fn format_endpoint(host: &str, port: i32) -> Result<String> {
    let port = u16::try_from(port)
        .map_err(|_| Error::InvalidConfig(format!("invalid server port {port}")))?;
    if host.is_empty() || port == 0 {
        return Err(Error::InvalidConfig(
            "server host must be non-empty and port must be 1..=65535".into(),
        ));
    }
    if host.contains(':') && !host.starts_with('[') {
        Ok(format!("[{host}]:{port}"))
    } else {
        Ok(format!("{host}:{port}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::HttpResponse;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct MockTransport {
        responses: Mutex<VecDeque<Result<HttpResponse>>>,
        requests: Mutex<Vec<HttpRequest>>,
    }

    impl HttpTransport for MockTransport {
        fn execute(&self, request: HttpRequest) -> Result<HttpResponse> {
            self.requests.lock().unwrap().push(request);
            self.responses.lock().unwrap().pop_front().unwrap()
        }
    }

    fn http_json(body: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            body: body.as_bytes().to_vec(),
        }
    }

    fn controller_configuration(mut raw: Value) -> ControllerConfiguration {
        if let Some(serverlist) = raw.get_mut("serverlist") {
            let servers = match serverlist {
                Value::Array(servers) => Some(servers),
                Value::Object(serverlist) => serverlist
                    .get_mut("serverlist")
                    .and_then(Value::as_array_mut),
                _ => None,
            };
            if let Some(servers) = servers {
                for server in servers {
                    encrypt_entry_password(server);
                }
            }
        }
        if let Some(sites) = raw.get_mut("sites").and_then(Value::as_array_mut) {
            for entry in sites
                .iter_mut()
                .filter_map(Value::as_object_mut)
                .filter_map(|site| site.get_mut("sr"))
                .filter_map(Value::as_array_mut)
                .flatten()
            {
                if let Some(ingress) = entry.get_mut("ingress") {
                    encrypt_entry_password(ingress);
                }
            }
        }
        ControllerConfiguration::from_controller_raw(raw, "controller-example", "example.test")
    }

    fn encrypt_entry_password(entry: &mut Value) {
        let Some(object) = entry.as_object_mut() else {
            return;
        };
        let Some(username) = object
            .get("userName")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return;
        };
        let Some(plaintext) = object
            .get("passWord")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return;
        };
        object.insert(
            "passWord".into(),
            Value::String(crate::managed::password::encrypt_for_test(
                "controller-example",
                "example.test",
                &username,
                plaintext.as_bytes(),
            )),
        );
    }

    #[test]
    fn controller_credential_path_uses_serverlist_instead_of_config() {
        let transport = MockTransport {
            responses: Mutex::new(VecDeque::from([
                Ok(http_json(
                    r#"{"success":true,"data":{"type":"controller","serverlistaddress":"https://controller.example/serverlist","controller_info":{"app_id":"controller-example","url":{"auth":"https://controller.example/auth","config":"https://controller.example/config","serverlist":"https://controller.example/serverlist"}}}}"#,
                )),
                Ok(http_json(r#"{"auth":{"method":"credential"}}"#)),
                Ok(http_json(
                    r#"{"serverlist":[{"id":1,"name":"Line","serverName":"edge.example","serverPort":6001}]}"#,
                )),
            ])),
            requests: Mutex::new(Vec::new()),
        };
        let client = DomainClient::with_transport(transport, None);
        let discovered = client.discover("example", "device").unwrap();
        let configuration = client
            .fetch_configuration(&discovered, "device", None, None, None)
            .unwrap();
        assert_eq!(configuration.iwan_servers().unwrap().len(), 1);
        let requests = client.lookup.transport().requests.lock().unwrap();
        assert_eq!(requests[2].url, "https://controller.example/serverlist");
        assert!(
            requests
                .iter()
                .all(|request| !request.url.ends_with("/config"))
        );
    }

    #[test]
    fn selects_lowest_latency_and_uses_credentials_for_that_server_id() {
        let configuration = controller_configuration(serde_json::json!({
            "serverlist": [
                {
                    "id": 1,
                    "name": "slow",
                    "serverName": "slow.example",
                    "serverPort": 6001,
                    "userName": "slow-user",
                    "passWord": "slow-pass"
                },
                {
                    "id": 2,
                    "name": "fast",
                    "serverName": "fast.example",
                    "serverPort": 6002,
                    "userName": "fast-user",
                    "passWord": "fast-pass"
                }
            ]
        }));
        let selected = select_ingress_with(&configuration, |endpoint| {
            Ok(if endpoint.starts_with("fast") {
                Duration::from_millis(2)
            } else {
                Duration::from_millis(20)
            })
        })
        .unwrap();
        let credentials = credentials_for_ingress(&selected, None, &configuration).unwrap();
        assert!(matches!(
            selected,
            SelectedIngress::Iwan {
                server: ServerInfo { ref id, .. },
                ..
            } if id == "2"
        ));
        assert_eq!(credentials.username, "fast-user");
    }

    #[test]
    fn line_preferences_have_stable_cli_and_state_representations() {
        let auto = "AUTO".parse::<LinePreference>().unwrap();
        let iwan = "iwan:007".parse::<LinePreference>().unwrap();
        let sr = "SR:9".parse::<LinePreference>().unwrap();
        assert_eq!(auto.to_string(), "auto");
        assert_eq!(iwan.to_string(), "iwan:7");
        assert_eq!(sr.to_string(), "sr:9");
        assert!("iwan:-1".parse::<LinePreference>().is_err());
        assert_eq!(
            "iwan:-2".parse::<LinePreference>().unwrap().to_string(),
            "iwan:-2"
        );
        assert!("unknown:1".parse::<LinePreference>().is_err());

        let encoded = toml::to_string(&iwan).unwrap();
        assert_eq!(toml::from_str::<LinePreference>(&encoded).unwrap(), iwan);
    }

    #[test]
    fn manual_iwan_preference_overrides_latency_order() {
        let configuration = controller_configuration(serde_json::json!({
            "serverlist": [
                {
                    "id": 1,
                    "name": "slow",
                    "serverName": "slow.example",
                    "serverPort": 6001,
                    "userName": "slow-user",
                    "passWord": "slow-pass"
                },
                {
                    "id": 2,
                    "name": "fast",
                    "serverName": "fast.example",
                    "serverPort": 6002,
                    "userName": "fast-user",
                    "passWord": "fast-pass"
                }
            ]
        }));
        let preference = LinePreference::Iwan {
            server_id: "1".into(),
        };
        let selected = select_ingress_with_preference(&configuration, &preference, |endpoint| {
            Ok(if endpoint.starts_with("slow") {
                Duration::from_millis(20)
            } else {
                Duration::from_millis(1)
            })
        })
        .unwrap();
        assert_eq!(selected.line_preference(), preference);
        assert_eq!(selected.latency(), Duration::from_millis(20));

        let missing = LinePreference::Iwan {
            server_id: "99".into(),
        };
        assert!(matches!(
            select_ingress_with_preference(&configuration, &missing, |_| {
                Ok(Duration::from_millis(1))
            }),
            Err(Error::LineNotFound(line)) if line == "iwan:99"
        ));
    }

    #[test]
    fn manual_sr_preference_keeps_group_failover_semantics() {
        let configuration = controller_configuration(serde_json::json!({
            "sites": [{
                "id": 9,
                "name": "group",
                "primary_index": 0,
                "sr": [
                    {
                        "id": 1,
                        "ip": "192.0.2.1",
                        "ingress": {
                            "serverName": "primary.example",
                            "serverPort": 6001,
                            "userName": "primary",
                            "passWord": "primary"
                        },
                        "path": {"links": [11]}
                    },
                    {
                        "id": 2,
                        "ip": "192.0.2.2",
                        "ingress": {
                            "serverName": "fallback.example",
                            "serverPort": 6002,
                            "userName": "fallback",
                            "passWord": "fallback"
                        },
                        "path": {"links": [12]}
                    }
                ]
            }]
        }));
        let preference = LinePreference::SegmentRouting { group_id: 9 };
        let selected = select_ingress_with_preference(&configuration, &preference, |endpoint| {
            if endpoint.starts_with("primary") {
                Err(Error::Timeout("test primary"))
            } else {
                Ok(Duration::from_millis(3))
            }
        })
        .unwrap();
        assert!(matches!(
            selected,
            SelectedIngress::SegmentRouting {
                entry: SrEntry { id: 2, .. },
                ..
            }
        ));
    }

    #[test]
    fn sr_connection_uses_embedded_ingress_credentials_and_path() {
        let configuration = controller_configuration(serde_json::json!({
            "sites": [{
                "id": 9,
                "name": "group",
                "sr": [{
                    "id": 5,
                    "keepalive": true,
                    "encrypt_algo": "aes128",
                    "encrypt_key": "0123456789abcdef",
                    "ip": "192.0.2.5",
                    "ingress": {
                        "serverName": "127.0.0.1",
                        "serverPort": 6001,
                        "userName": "entry-user",
                        "passWord": "entry-pass",
                        "mtu": 1400
                    },
                    "path": {"links": [11, 12]}
                }]
            }]
        }));
        let selected =
            select_ingress_with(&configuration, |_| Ok(Duration::from_millis(1))).unwrap();
        let credentials = credentials_for_ingress(&selected, None, &configuration).unwrap();
        assert_eq!(credentials.username, "entry-user");
        let SelectedIngress::SegmentRouting { entry, .. } = &selected else {
            panic!("expected SR ingress");
        };
        let config = segment_routing_config(entry).unwrap();
        assert_eq!(config.links, [11, 12]);
        assert_eq!(config.encrypt_algo, SrEncryptionAlgorithm::Aes128);
        assert!(!config.keepalive);
        assert_eq!(config.local_sr_id, Some(5));
    }

    #[test]
    fn sr_sanitizer_applies_mtu_crypto_keepalive_and_local_id_rules() {
        let configuration = controller_configuration(serde_json::json!({
            "sites": [{
                "id": 9,
                "sr": [{
                    "id": 0,
                    "keepalive": true,
                    "encrypt_algo": "aes128",
                    "encrypt_key": "short",
                    "ip": "192.0.2.5",
                    "ingress": {
                        "serverName": "127.0.0.1",
                        "serverPort": 6001,
                        "userName": "entry-user",
                        "passWord": "entry-pass",
                        "mtu": 0
                    },
                    "path": {"links": [11, 12]}
                }]
            }]
        }));
        let selected =
            select_ingress_with(&configuration, |_| Ok(Duration::from_millis(1))).unwrap();
        let SelectedIngress::SegmentRouting { entry, .. } = &selected else {
            panic!("expected SR ingress");
        };
        assert_eq!(entry.ingress.mtu, 1_392);
        assert_eq!(entry.encrypt_algo, "null");
        assert!(entry.encrypt_key.is_empty());
        assert_eq!(entry.keepalive, Some(false));
        assert!(entry.local_sr_id.is_some_and(|id| id != 0));
        let credentials = credentials_for_ingress(&selected, None, &configuration).unwrap();
        let client = client_for(&selected, &credentials).unwrap();
        assert_eq!(client.config().mtu, 1_392);
        let sr = client.config().segment_routing.as_ref().unwrap();
        assert_eq!(sr.encrypt_algo, SrEncryptionAlgorithm::None);
        assert_eq!(sr.id, sr.local_sr_id.unwrap());
    }

    #[test]
    fn sr_selection_honors_primary_index_before_group_failovers() {
        let configuration = controller_configuration(serde_json::json!({
            "sites": [{
                "id": 9,
                "name": "group",
                "primary_index": 1,
                "sr": [
                    {
                        "id": 1,
                        "ip": "192.0.2.1",
                        "ingress": {
                            "serverName": "fallback.example",
                            "serverPort": 6001,
                            "userName": "fallback",
                            "passWord": "fallback"
                        },
                        "path": {"links": [11]}
                    },
                    {
                        "id": 2,
                        "ip": "192.0.2.2",
                        "ingress": {
                            "serverName": "primary.example",
                            "serverPort": 6002,
                            "userName": "primary",
                            "passWord": "primary"
                        },
                        "path": {"links": [12]}
                    }
                ]
            }]
        }));
        let selected = select_ingress_with(&configuration, |endpoint| {
            Ok(if endpoint.starts_with("fallback") {
                Duration::from_millis(1)
            } else {
                Duration::from_millis(20)
            })
        })
        .unwrap();
        assert!(matches!(
            selected,
            SelectedIngress::SegmentRouting {
                entry: SrEntry { id: 2, .. },
                ..
            }
        ));
    }

    #[test]
    fn sr_selection_skips_invalid_primary_and_uses_group_failover() {
        let configuration = controller_configuration(serde_json::json!({
            "sites": [{
                "id": 9,
                "primary_index": 0,
                "sr": [
                    {
                        "id": 1,
                        "ip": "192.0.2.1",
                        "ingress": {
                            "serverName": "",
                            "serverPort": 0,
                            "userName": "invalid",
                            "passWord": "invalid"
                        },
                        "path": {"links": [11]}
                    },
                    {
                        "id": 2,
                        "ip": "192.0.2.2",
                        "ingress": {
                            "serverName": "fallback.example",
                            "serverPort": 6002,
                            "userName": "fallback",
                            "passWord": "fallback"
                        },
                        "path": {"links": [12]}
                    }
                ]
            }]
        }));
        let selected =
            select_ingress_with(&configuration, |_| Ok(Duration::from_millis(1))).unwrap();
        assert!(matches!(
            selected,
            SelectedIngress::SegmentRouting {
                entry: SrEntry { id: 2, .. },
                ..
            }
        ));
    }
}
