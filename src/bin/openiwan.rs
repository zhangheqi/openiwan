#[cfg(feature = "managed")]
#[path = "openiwan/credentials.rs"]
mod credentials;
#[cfg(feature = "forward")]
#[path = "openiwan/forward.rs"]
mod forward;
#[cfg(feature = "managed")]
#[path = "openiwan/state.rs"]
mod state;

use clap::{Args, Parser, Subcommand};
use openiwan::client;
#[cfg(feature = "managed")]
use openiwan::dns::PhysicalResolver;
use openiwan::dns::{
    DnsDefaults, DnsOverrides, DnsPacketDevice, DnsPolicyResolver, DnsRuntime, DnsServerMode,
    DomainRule, EffectiveDnsPolicy, EncryptedDnsMode, RelayConfig, SplitDnsMode,
    discover_physical_resolvers,
};
#[cfg(feature = "forward")]
use openiwan::dns::{ResolveVia, ResolverConfig};
#[cfg(feature = "managed")]
use openiwan::managed::{
    AuthMethod, DiscoveredDomain, DomainClient, LinePreference, LineProbe, OidcLoginOptions,
    PreparedConnection, RoutingMode, SelectedIngress, ServiceType,
};
use openiwan::protocol::{self, Tlv};
use openiwan::tun::resolve_route_policy;
#[cfg(feature = "managed")]
use openiwan::tun::resolve_route_targets;
use openiwan::tun::{RouteGuard, TunDevice};
use openiwan::{Client, ClientConfig, EncryptionMethod, Error, PacketDevice, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
#[cfg(feature = "managed")]
use std::io::Write;
#[cfg(feature = "forward")]
use std::net::SocketAddr;
#[cfg(feature = "managed")]
use std::net::ToSocketAddrs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroize;

#[derive(Debug, Parser)]
#[command(name = "openiwan", version, about = "iWAN command-line client")]
struct Cli {
    /// Increase verbosity (-vv for more).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Probe an iWAN server.
    Ping(PingArgs),
    /// Authenticate and exit.
    Auth(ConnectionArgs),
    /// Open an iWAN tunnel.
    Connect(ConnectArgs),
    /// Forward TCP or HTTP traffic through iWAN.
    #[cfg(feature = "forward")]
    Forward(ForwardArgs),
    /// Decode an iWAN packet.
    Decode(DecodeArgs),
    /// Manage controller-based connections.
    #[cfg(feature = "managed")]
    Managed(ManagedArgs),
    /// Manage profiles.
    #[cfg(feature = "managed")]
    Profile(ProfileArgs),
}

#[derive(Debug, Args)]
struct PingArgs {
    /// iWAN server (HOST:PORT).
    server: String,
    /// Set the reply timeout.
    #[arg(
        long,
        value_name = "DURATION",
        default_value = "3s",
        value_parser = parse_duration
    )]
    timeout: Duration,
}

#[derive(Debug, Clone, Args)]
struct ConnectionArgs {
    /// Read settings from FILE.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Connect to HOST:PORT.
    #[arg(long, value_name = "HOST:PORT")]
    server: Option<String>,
    /// Log in as USER.
    #[arg(long, value_name = "USER")]
    username: String,
    /// Read the password from ENV.
    #[arg(long, value_name = "ENV", default_value = "OPENIWAN_PASSWORD")]
    password_env: String,
    /// Read the password from the first line of FILE.
    #[arg(long, value_name = "FILE")]
    password_file: Option<PathBuf>,
    /// Set the packet MTU to BYTES.
    #[arg(long, value_name = "BYTES")]
    mtu: Option<u16>,
    /// Use CIPHER for the session.
    #[arg(long, value_name = "CIPHER")]
    encryption: Option<EncryptionMethod>,
}

#[derive(Debug, Args)]
struct ConnectArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Use NAME for the TUN interface.
    #[arg(long, value_name = "NAME")]
    tun: Option<String>,
    #[command(flatten)]
    routes: RouteArgs,
    #[command(flatten)]
    dns: DnsOverrideArgs,
}

#[cfg(feature = "forward")]
#[derive(Debug, Args)]
struct ForwardArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    #[command(flatten)]
    forward: ForwardOptions,
}

#[cfg(feature = "forward")]
#[derive(Debug, Clone, Args)]
struct ForwardOptions {
    /// Forward to URI (tcp://, http://, or https://).
    #[arg(long, value_name = "URI", value_parser = forward::parse_target_argument)]
    target: String,
    /// Resolve the target with MODE.
    #[arg(long, value_name = "MODE", value_enum, default_value = "auto")]
    resolve: ResolveViaArg,
    /// Query HOST[:PORT] through iWAN. May be repeated.
    #[arg(
        long = "dns-server",
        value_name = "HOST[:PORT]",
        value_parser = parse_resolver
    )]
    dns_servers: Vec<SocketAddr>,
    /// Set the timeout for each DNS server.
    #[arg(
        long,
        value_name = "DURATION",
        default_value = "3s",
        value_parser = parse_duration
    )]
    dns_timeout: Duration,
    /// Listen on loopback HOST:PORT.
    #[arg(long, value_name = "HOST:PORT", default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    /// Trust the PEM certificate in FILE. May be repeated.
    #[arg(long = "ca-cert", value_name = "FILE")]
    ca_certificates: Vec<PathBuf>,
    /// Set the DNS, TCP, and TLS setup timeout.
    #[arg(
        long,
        value_name = "DURATION",
        default_value = "10s",
        value_parser = parse_duration
    )]
    connect_timeout: Duration,
}

#[cfg(feature = "forward")]
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ResolveViaArg {
    Auto,
    Tunnel,
    System,
}

#[cfg(feature = "forward")]
impl From<ResolveViaArg> for ResolveVia {
    fn from(value: ResolveViaArg) -> Self {
        match value {
            ResolveViaArg::Auto => Self::Auto,
            ResolveViaArg::Tunnel => Self::Tunnel,
            ResolveViaArg::System => Self::System,
        }
    }
}

#[cfg(feature = "forward")]
fn parse_resolver(value: &str) -> std::result::Result<SocketAddr, String> {
    if let Ok(address) = value.parse::<IpAddr>() {
        return Ok(SocketAddr::new(address, 53));
    }
    value
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid DNS server {value}: {error}"))
}

fn parse_duration(value: &str) -> std::result::Result<Duration, String> {
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60_000)
    } else {
        return Err("duration must end in ms, s, or m".into());
    };
    let number = number
        .parse::<u64>()
        .map_err(|_| format!("invalid duration {value:?}"))?;
    let milliseconds = number
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration {value:?} is too large"))?;
    if milliseconds == 0 {
        return Err("duration must be greater than zero".into());
    }
    Ok(Duration::from_millis(milliseconds))
}

#[derive(Debug, Clone, Default, Args)]
struct DnsOverrideArgs {
    /// Select the DNS source.
    #[arg(long, value_name = "MODE", value_enum)]
    dns_mode: Option<DnsServerModeArg>,
    /// Use IP as a DNS server. May be repeated.
    #[arg(long = "dns-server", value_name = "IP")]
    dns_servers: Vec<Ipv4Addr>,
    /// Set the split DNS mode.
    #[arg(long, value_name = "MODE", value_enum)]
    split_dns_mode: Option<SplitDnsModeArg>,
    /// Add split DNS rule RULE. May be repeated.
    #[arg(long = "split-dns-domain", value_name = "RULE")]
    split_dns_domains: Vec<DomainRule>,
    /// Set the encrypted DNS mode.
    #[arg(long, value_name = "MODE", value_enum)]
    encrypted_dns: Option<EncryptedDnsModeArg>,
    /// Block DNS-over-HTTPS host HOST. May be repeated.
    #[arg(long = "doh-host", value_name = "HOST")]
    doh_hosts: Vec<String>,
}

impl DnsOverrideArgs {
    fn applied_to(&self, lower: &DnsOverrides) -> DnsOverrides {
        let mut target = lower.clone();
        if let Some(mode) = self.dns_mode {
            target.server_mode = mode.into_policy();
            if matches!(mode, DnsServerModeArg::Inherit) {
                target.servers = None;
            }
        }
        if !self.dns_servers.is_empty() {
            target.servers = Some(self.dns_servers.clone());
            if self.dns_mode.is_none() {
                target.server_mode = Some(DnsServerMode::Custom);
            }
        }
        if let Some(mode) = self.split_dns_mode {
            target.split_mode = mode.into_policy();
            if matches!(mode, SplitDnsModeArg::Inherit) {
                target.split_domains = None;
            }
        }
        if !self.split_dns_domains.is_empty() {
            target.split_domains = Some(self.split_dns_domains.clone());
            if self.split_dns_mode.is_none() {
                target.split_mode = Some(SplitDnsMode::Custom);
            }
        }
        if let Some(mode) = self.encrypted_dns {
            target.encrypted_dns = Some(mode.into_policy());
        }
        if !self.doh_hosts.is_empty() {
            target.doh_hosts = Some(self.doh_hosts.clone());
        }
        target
    }

    #[cfg(feature = "managed")]
    fn patch_profile(&self, target: &mut DnsOverrides) {
        if let Some(mode) = self.dns_mode {
            target.server_mode = mode.into_policy();
        }
        if !self.dns_servers.is_empty() {
            target.servers = Some(self.dns_servers.clone());
            if self.dns_mode.is_none() {
                target.server_mode = Some(DnsServerMode::Custom);
            }
        }
        if let Some(mode) = self.split_dns_mode {
            target.split_mode = mode.into_policy();
        }
        if !self.split_dns_domains.is_empty() {
            target.split_domains = Some(self.split_dns_domains.clone());
            if self.split_dns_mode.is_none() {
                target.split_mode = Some(SplitDnsMode::Custom);
            }
        }
        if let Some(mode) = self.encrypted_dns {
            target.encrypted_dns = match mode {
                EncryptedDnsModeArg::Inherit => None,
                _ => Some(mode.into_policy()),
            };
        }
        if !self.doh_hosts.is_empty() {
            target.doh_hosts = Some(self.doh_hosts.clone());
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum DnsServerModeArg {
    Inherit,
    Server,
    Custom,
    Disabled,
}

impl DnsServerModeArg {
    const fn into_policy(self) -> Option<DnsServerMode> {
        match self {
            Self::Inherit => None,
            Self::Server => Some(DnsServerMode::Server),
            Self::Custom => Some(DnsServerMode::Custom),
            Self::Disabled => Some(DnsServerMode::Disabled),
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum SplitDnsModeArg {
    Inherit,
    Off,
    TunnelAll,
    Managed,
    Custom,
}

impl SplitDnsModeArg {
    const fn into_policy(self) -> Option<SplitDnsMode> {
        match self {
            Self::Inherit => None,
            Self::Off => Some(SplitDnsMode::Off),
            Self::TunnelAll => Some(SplitDnsMode::TunnelAll),
            Self::Managed => Some(SplitDnsMode::Managed),
            Self::Custom => Some(SplitDnsMode::Custom),
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum EncryptedDnsModeArg {
    Inherit,
    Block,
    Allow,
}

impl EncryptedDnsModeArg {
    const fn into_policy(self) -> EncryptedDnsMode {
        match self {
            Self::Inherit => EncryptedDnsMode::Inherit,
            Self::Block => EncryptedDnsMode::Block,
            Self::Allow => EncryptedDnsMode::Allow,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(crate) enum UserRoutingMode {
    All,
    Custom,
}

impl std::fmt::Display for UserRoutingMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::All => formatter.write_str("all"),
            Self::Custom => formatter.write_str("custom"),
        }
    }
}

#[derive(Debug, Clone, Default, Args)]
struct RoutingOverrideArgs {
    /// Set the routing mode.
    #[arg(long, value_name = "MODE", value_enum)]
    routing_mode: Option<UserRoutingMode>,
    /// Block IPv6 outside the tunnel.
    #[arg(long, conflicts_with = "allow_ipv6")]
    block_ipv6: bool,
    /// Allow IPv6 outside the tunnel.
    #[arg(long, conflicts_with = "block_ipv6")]
    allow_ipv6: bool,
}

impl RoutingOverrideArgs {
    const fn ipv6_override(&self) -> Option<bool> {
        if self.block_ipv6 {
            Some(true)
        } else if self.allow_ipv6 {
            Some(false)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Default, Args)]
struct RouteArgs {
    #[command(flatten)]
    policy: RoutingOverrideArgs,
    /// Route CIDR through iWAN. May be repeated.
    #[arg(long = "route", value_name = "CIDR", value_delimiter = ',')]
    routes: Vec<String>,
    /// Route IP through iWAN. May be repeated.
    #[arg(long = "route-ip", value_name = "IP", value_delimiter = ',')]
    route_ips: Vec<String>,
    /// Route addresses resolved for DOMAIN. May be repeated.
    #[arg(long = "route-domain", value_name = "DOMAIN", value_delimiter = ',')]
    route_domains: Vec<String>,
}

#[derive(Debug, Args)]
struct DecodeArgs {
    /// Hexadecimal packet. Whitespace, ':' and '-' are ignored.
    hex: String,
}

#[cfg(feature = "managed")]
#[derive(Debug, Args)]
struct ManagedArgs {
    #[command(subcommand)]
    action: ManagedCommand,
}

#[cfg(feature = "managed")]
#[derive(Debug, Subcommand)]
enum ManagedCommand {
    /// Show discovered domain settings.
    Discover(ManagedDiscoverArgs),
    /// Log in and save credentials.
    Login(ManagedLoginArgs),
    /// Open a managed tunnel.
    Connect(ManagedConnectArgs),
    /// Forward traffic through a managed connection.
    #[cfg(feature = "forward")]
    Forward(ManagedForwardArgs),
    /// List available lines.
    Lines(ManagedLinesArgs),
}

#[cfg(feature = "managed")]
#[derive(Debug, Clone, Default, Args)]
struct ManagedTargetArgs {
    /// Use profile NAME.
    #[arg(long, value_name = "NAME", conflicts_with = "domain")]
    profile: Option<String>,
    /// Use DOMAIN without a profile.
    #[arg(long, value_name = "DOMAIN", conflicts_with = "profile")]
    domain: Option<String>,
}

#[cfg(feature = "managed")]
#[derive(Debug, Clone, Default, Args)]
struct ManagedProfileTargetArgs {
    /// Use profile NAME. Uses the default if omitted.
    #[arg(long, value_name = "NAME")]
    profile: Option<String>,
}

#[cfg(feature = "managed")]
#[derive(Debug, Clone, Default, Args)]
struct ManagedAuthArgs {
    /// Log in as USER.
    #[arg(long, value_name = "USER")]
    username: Option<String>,
    /// Read the password from the first line of FILE.
    #[arg(long, value_name = "FILE")]
    password_file: Option<PathBuf>,
    /// Read posture results from FILE.
    #[arg(long, value_name = "FILE")]
    posture_results: Option<PathBuf>,
    /// Disable interactive authentication.
    #[arg(long)]
    non_interactive: bool,
}

#[cfg(feature = "managed")]
#[derive(Debug, Args)]
struct ManagedDiscoverArgs {
    #[command(flatten)]
    target: ManagedTargetArgs,
}

#[cfg(feature = "managed")]
#[derive(Debug, Clone, Args)]
struct ManagedLoginArgs {
    #[command(flatten)]
    target: ManagedProfileTargetArgs,
    #[command(flatten)]
    auth: ManagedAuthArgs,
}

#[cfg(feature = "managed")]
#[derive(Debug, Clone, Default, Args)]
struct ManagedConnectionOverrideArgs {
    /// Use LINE for this command (auto, iwan:ID, or sr:ID).
    #[arg(long, value_name = "LINE")]
    line: Option<LinePreference>,
}

#[cfg(feature = "managed")]
#[derive(Debug, Args)]
struct ManagedConnectArgs {
    #[command(flatten)]
    target: ManagedTargetArgs,
    #[command(flatten)]
    auth: ManagedAuthArgs,
    #[command(flatten)]
    connection: ManagedConnectionOverrideArgs,
    /// Use NAME for the TUN interface.
    #[arg(long, value_name = "NAME")]
    tun: Option<String>,
    #[command(flatten)]
    routes: RouteArgs,
    #[command(flatten)]
    dns: DnsOverrideArgs,
}

#[cfg(all(feature = "managed", feature = "forward"))]
#[derive(Debug, Args)]
struct ManagedForwardArgs {
    #[command(flatten)]
    target: ManagedTargetArgs,
    #[command(flatten)]
    auth: ManagedAuthArgs,
    #[command(flatten)]
    connection: ManagedConnectionOverrideArgs,
    #[command(flatten)]
    forward: ForwardOptions,
}

#[cfg(feature = "managed")]
#[derive(Debug, Args)]
struct ManagedLinesArgs {
    #[command(flatten)]
    target: ManagedTargetArgs,
    #[command(flatten)]
    auth: ManagedAuthArgs,
    /// Output JSON.
    #[arg(long)]
    json: bool,
}

#[cfg(feature = "managed")]
#[derive(Debug, Args)]
struct ProfileArgs {
    #[command(subcommand)]
    command: ProfileCommand,
}

#[cfg(feature = "managed")]
#[derive(Debug, Subcommand)]
enum ProfileCommand {
    /// List profiles.
    List {
        /// Output JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show a profile.
    Show {
        /// Profile name. Uses the default if omitted.
        name: Option<String>,
        /// Output JSON.
        #[arg(long)]
        json: bool,
    },
    /// Create or update a profile.
    Set(Box<ProfileSetArgs>),
    /// Set the default profile.
    Use {
        /// Profile name.
        name: String,
    },
    /// Remove a profile.
    Remove {
        /// Profile name.
        name: String,
    },
    /// Delete saved credentials.
    Logout {
        /// Profile name. Uses the default if omitted.
        name: Option<String>,
    },
}

#[cfg(feature = "managed")]
#[derive(Debug, Default, Args)]
struct ProfileRoutingArgs {
    #[command(flatten)]
    overrides: RoutingOverrideArgs,
    /// Clear the saved routing mode.
    #[arg(long, conflicts_with = "routing_mode")]
    unset_routing_mode: bool,
    /// Replace saved routes. May be repeated.
    #[arg(
        long = "route",
        value_name = "CIDR",
        value_delimiter = ',',
        conflicts_with = "unset_routes"
    )]
    routes: Vec<String>,
    /// Clear saved routes.
    #[arg(long)]
    unset_routes: bool,
}

#[cfg(feature = "managed")]
#[derive(Debug, Args)]
struct ProfileSetArgs {
    /// Profile name.
    name: String,
    /// Set the domain.
    #[arg(long, value_name = "DOMAIN")]
    domain: Option<String>,
    /// Set the device ID.
    #[arg(long, value_name = "ID")]
    device_id: Option<String>,
    /// Set the username.
    #[arg(long, value_name = "USER", conflicts_with = "unset_username")]
    username: Option<String>,
    /// Clear the saved username.
    #[arg(long)]
    unset_username: bool,
    /// Set the preferred line.
    #[arg(long, value_name = "LINE")]
    line: Option<LinePreference>,
    #[command(flatten)]
    routing: ProfileRoutingArgs,
    #[command(flatten)]
    dns: DnsOverrideArgs,
    /// Clear saved DNS settings.
    #[arg(long)]
    reset_dns: bool,
    /// Clear saved DNS list FIELD. May be repeated.
    #[arg(long, value_name = "FIELD", value_enum)]
    unset_dns: Vec<ProfileDnsListArg>,
}

#[cfg(feature = "managed")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ProfileDnsListArg {
    Servers,
    SplitDomains,
    DohHosts,
}

fn main() {
    if let Err(error) = run() {
        if let Error::InvalidConfig(message) = &error {
            eprintln!("openiwan: {message}");
        } else {
            eprintln!("openiwan: {error}");
        }
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose);
    match cli.command {
        Command::Ping(arguments) => {
            let address = ClientConfig::new(arguments.server).resolve_server()?;
            let elapsed = client::ping(address, arguments.timeout)?;
            println!(
                "reply from {address}: {:.3} ms",
                elapsed.as_secs_f64() * 1_000.0
            );
        }
        Command::Auth(arguments) => {
            let client = build_client(&arguments)?;
            let session = client.authenticate()?;
            print_session(session.info());
            session.close()?;
        }
        Command::Connect(arguments) => connect(arguments)?,
        #[cfg(feature = "forward")]
        Command::Forward(arguments) => forward(arguments)?,
        Command::Decode(arguments) => decode(&arguments.hex)?,
        #[cfg(feature = "managed")]
        Command::Managed(arguments) => {
            let store = state::StateStore::new(None)?;
            managed(arguments, &store)?;
        }
        #[cfg(feature = "managed")]
        Command::Profile(arguments) => {
            let store = state::StateStore::new(None)?;
            profile(arguments, &store)?;
        }
    }
    Ok(())
}

fn connect(arguments: ConnectArgs) -> Result<()> {
    let client = build_client(&arguments.connection)?;
    run_client(
        client,
        arguments.tun.as_deref(),
        &arguments.routes,
        &arguments.dns,
    )
}

const IPV6_CAPTURE_ROUTES: [&str; 2] = ["::/1", "8000::/1"];

fn append_ipv6_capture_routes(routes: &mut Vec<String>, block_ipv6: bool) {
    if block_ipv6 {
        routes.extend(IPV6_CAPTURE_ROUTES.into_iter().map(str::to_owned));
    }
}

fn base_full_ipv4_exclusions() -> Vec<String> {
    vec![
        "169.254.0.0/16".into(),
        "224.0.0.0/4".into(),
        "127.0.0.0/8".into(),
    ]
}

struct Ipv6BlockingDevice<D: PacketDevice + ?Sized> {
    inner: Arc<D>,
    block_ipv6: bool,
}

impl<D: PacketDevice + ?Sized> Ipv6BlockingDevice<D> {
    fn new(inner: Arc<D>, block_ipv6: bool) -> Self {
        Self { inner, block_ipv6 }
    }
}

impl<D: PacketDevice + ?Sized> PacketDevice for Ipv6BlockingDevice<D> {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn activate_session(&self, session: &openiwan::SessionInfo) -> Result<()> {
        self.inner.activate_session(session)
    }

    fn deactivate_session(&self) -> Result<()> {
        self.inner.deactivate_session()
    }

    fn read_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let length = self.inner.read_packet(buffer)?;
            if !self.block_ipv6 || !is_ipv6_packet(&buffer[..length]) {
                return Ok(length);
            }
        }
    }

    fn write_packet(&self, packet: &[u8]) -> io::Result<usize> {
        if self.block_ipv6 && is_ipv6_packet(packet) {
            Ok(packet.len())
        } else {
            self.inner.write_packet(packet)
        }
    }
}

fn is_ipv6_packet(packet: &[u8]) -> bool {
    packet.first().is_some_and(|byte| byte >> 4 == 6)
}

#[cfg(feature = "forward")]
fn forward(arguments: ForwardArgs) -> Result<()> {
    let client = build_client(&arguments.connection)?;
    run_forward(client, &arguments.forward, &[])
}

fn run_client(
    client: Client,
    tun: Option<&str>,
    route_arguments: &RouteArgs,
    dns_arguments: &DnsOverrideArgs,
) -> Result<()> {
    let session = client.authenticate()?;
    print_session(session.info());
    let routing_mode = route_arguments
        .policy
        .routing_mode
        .unwrap_or(UserRoutingMode::Custom);
    let block_ipv6 = route_arguments.policy.ipv6_override().unwrap_or(false);
    let overrides = dns_arguments.applied_to(&DnsOverrides::default());
    if overrides.split_mode == Some(SplitDnsMode::Managed) {
        return Err(Error::InvalidConfig(
            "direct connect cannot use managed split DNS without controller domain rules".into(),
        ));
    }
    let defaults = DnsDefaults::default();
    let policy = DnsPolicyResolver::resolve(&defaults, &overrides, &session.info().dns_servers)?;
    let physical = discover_physical_resolvers()?;

    let mut route_ips = route_arguments.route_ips.clone();
    route_ips.extend(
        policy
            .servers
            .iter()
            .map(|server| IpAddr::V4(*server))
            .filter(|server| *server != session.info().peer.ip())
            .map(|server| server.to_string()),
    );
    let mut exclusions = if policy.server_mode == DnsServerMode::Disabled
        || matches!(
            policy.split_mode,
            SplitDnsMode::Managed | SplitDnsMode::Custom
        ) {
        physical
            .iter()
            .filter(|resolver| !block_ipv6 || resolver.address.ip().is_ipv4())
            .map(|resolver| {
                let address = resolver.address.ip();
                format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 })
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    if routing_mode == UserRoutingMode::All {
        exclusions.extend(base_full_ipv4_exclusions());
    }
    let mut cidrs = route_arguments.routes.clone();
    append_ipv6_capture_routes(&mut cidrs, block_ipv6);
    let routes = resolve_route_policy(
        &cidrs,
        &route_ips,
        &route_arguments.route_domains,
        &exclusions,
        session.info().peer.ip(),
        routing_mode == UserRoutingMode::All,
    )?;
    let mut interface_session = session.info().clone();
    interface_session.dns_servers = policy.servers.iter().copied().map(IpAddr::V4).collect();
    let device = Arc::new(TunDevice::open(tun, &interface_session)?);
    let _routes = RouteGuard::configure(&device, &routes)?;
    let runtime = Arc::new(
        DnsRuntime::new(
            device.dns_platform_target(),
            defaults,
            overrides,
            physical,
            RelayConfig::default(),
        )?
        .with_physical_ipv6(!block_ipv6),
    );
    let dns_device = Arc::new(DnsPacketDevice::new(Arc::clone(&device), runtime));
    let packet_device = Arc::new(Ipv6BlockingDevice::new(dns_device, block_ipv6));
    for route in &routes {
        tracing::debug!(%route, interface = device.name(), "installed route");
    }
    println!(
        "routing: mode={routing_mode}, ipv6={}",
        if block_ipv6 { "blocked" } else { "allowed" }
    );
    print_dns_policy(&policy);
    println!("interface: {}", device.name());
    println!("connected; press Ctrl-C to disconnect");

    let shutdown = install_shutdown_handler()?;
    let end = client.run_reconnecting_from(session, packet_device, shutdown)?;
    println!("disconnected: {}", session_end_label(end));
    Ok(())
}

fn install_shutdown_handler() -> Result<Arc<AtomicBool>> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&shutdown);
    ctrlc::set_handler(move || signal.store(true, Ordering::Release))
        .map_err(|error| Error::InvalidConfig(format!("install signal handler: {error}")))?;
    Ok(shutdown)
}

#[cfg(feature = "forward")]
fn run_forward(
    client: Client,
    arguments: &ForwardOptions,
    configured_dns_servers: &[IpAddr],
) -> Result<()> {
    let config = build_forward_config(arguments, configured_dns_servers)?;
    let session = client.authenticate()?;
    print_session(session.info());
    let shutdown = install_shutdown_handler()?;
    let end = forward::run(client, session, config, shutdown)?;
    println!("disconnected: {}", session_end_label(end));
    Ok(())
}

#[cfg(feature = "forward")]
fn build_forward_config(
    arguments: &ForwardOptions,
    configured_dns_servers: &[IpAddr],
) -> Result<forward::ForwardConfig> {
    build_forward_config_with_route(arguments, configured_dns_servers, None)
}

#[cfg(feature = "forward")]
fn build_forward_config_with_route(
    arguments: &ForwardOptions,
    configured_dns_servers: &[IpAddr],
    auto_tunnel: Option<bool>,
) -> Result<forward::ForwardConfig> {
    let include_session_servers = arguments.dns_servers.is_empty()
        && configured_dns_servers.is_empty()
        && auto_tunnel.is_none();
    let mut dns_servers = arguments.dns_servers.clone();
    if dns_servers.is_empty() {
        dns_servers.extend(
            configured_dns_servers
                .iter()
                .copied()
                .map(|address| SocketAddr::new(address, 53)),
        );
    }
    let mode = match (arguments.resolve, auto_tunnel, dns_servers.is_empty()) {
        (ResolveViaArg::Auto, Some(true), false) => ResolveVia::Tunnel,
        (ResolveViaArg::Auto, Some(_), _) => ResolveVia::System,
        (mode, _, _) => mode.into(),
    };
    let dns = ResolverConfig::new(mode, dns_servers, arguments.dns_timeout)?
        .with_session_servers(include_session_servers);
    forward::ForwardConfig::new(
        arguments.listen,
        &arguments.target,
        dns,
        arguments.ca_certificates.clone(),
        arguments.connect_timeout,
    )
}

fn print_dns_policy(policy: &EffectiveDnsPolicy) {
    let servers = if policy.servers.is_empty() {
        "none".into()
    } else {
        policy
            .servers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!(
        "dns: mode={}, servers={servers}, split={}, encrypted={}",
        dns_server_mode_label(policy.server_mode),
        split_dns_mode_label(policy.split_mode),
        if policy.block_encrypted_dns {
            "blocked"
        } else {
            "allowed"
        }
    );
}

const fn dns_server_mode_label(mode: DnsServerMode) -> &'static str {
    match mode {
        DnsServerMode::Server => "server",
        DnsServerMode::Custom => "custom",
        DnsServerMode::Disabled => "disabled",
    }
}

const fn split_dns_mode_label(mode: SplitDnsMode) -> &'static str {
    match mode {
        SplitDnsMode::Off => "off",
        SplitDnsMode::TunnelAll => "tunnel-all",
        SplitDnsMode::Managed => "managed",
        SplitDnsMode::Custom => "custom",
    }
}

const fn session_end_label(end: openiwan::SessionEnd) -> &'static str {
    match end {
        openiwan::SessionEnd::LocalShutdown => "local shutdown",
        openiwan::SessionEnd::ServerClose => "server closed the session",
        openiwan::SessionEnd::HeartbeatTimeout => "heartbeat timeout",
        openiwan::SessionEnd::TransportFailure => "transport failure",
    }
}

#[cfg(feature = "managed")]
#[derive(Debug)]
struct ManagedContext {
    profile_name: Option<String>,
    domain: String,
    device_id: String,
    username: Option<String>,
    line: LinePreference,
    credential_id: Option<String>,
    dns: DnsOverrides,
    routing: state::RoutingOverrides,
}

#[cfg(feature = "managed")]
const MANAGED_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(feature = "managed")]
const MANAGED_OIDC_REDIRECT_URI: &str = "com.panabit.mobile://oauth2redirect";
#[cfg(feature = "managed")]
const MANAGED_PASSWORD_ENV: &str = "OPENIWAN_PASSWORD";

#[cfg(feature = "managed")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedAuthenticationIntent {
    FreshAndPersist,
    ReuseOrEphemeral,
}

#[cfg(feature = "managed")]
fn managed(arguments: ManagedArgs, store: &state::StateStore) -> Result<()> {
    match arguments.action {
        ManagedCommand::Discover(discover) => {
            let (context, _, discovered) = load_managed_domain(&discover.target, store, false)?;
            print_discovery(&discovered, &context.device_id);
        }
        ManagedCommand::Login(login) => {
            let target = ManagedTargetArgs {
                profile: login.target.profile,
                domain: None,
            };
            let (mut context, client, discovered) = load_managed_domain(&target, store, true)?;
            let line = context.line.clone();
            let prepared = prepare_managed(
                &client,
                &discovered,
                store,
                &mut context,
                &login.auth,
                &line,
                ManagedAuthenticationIntent::FreshAndPersist,
            )?;
            print_prepared(&prepared);
        }
        ManagedCommand::Connect(connect) => {
            let (mut context, client, discovered) =
                load_managed_domain(&connect.target, store, false)?;
            let line = connect
                .connection
                .line
                .clone()
                .unwrap_or_else(|| context.line.clone());
            let prepared = prepare_managed(
                &client,
                &discovered,
                store,
                &mut context,
                &connect.auth,
                &line,
                ManagedAuthenticationIntent::ReuseOrEphemeral,
            )?;
            print_prepared(&prepared);
            run_managed_client(
                prepared,
                connect.tun.as_deref(),
                &connect.routes,
                &context.dns,
                &connect.dns,
                &context.routing,
            )?;
        }
        #[cfg(feature = "forward")]
        ManagedCommand::Forward(forward) => {
            let (mut context, client, discovered) =
                load_managed_domain(&forward.target, store, false)?;
            let line = forward
                .connection
                .line
                .clone()
                .unwrap_or_else(|| context.line.clone());
            let prepared = prepare_managed(
                &client,
                &discovered,
                store,
                &mut context,
                &forward.auth,
                &line,
                ManagedAuthenticationIntent::ReuseOrEphemeral,
            )?;
            print_prepared(&prepared);
            run_managed_forward(&prepared, &forward.forward, &context.dns)?;
        }
        ManagedCommand::Lines(lines) => {
            let (mut context, client, discovered) =
                load_managed_domain(&lines.target, store, false)?;
            // A stale saved preference must not prevent the recovery command
            // from listing current controller lines.
            let prepared = prepare_managed(
                &client,
                &discovered,
                store,
                &mut context,
                &lines.auth,
                &LinePreference::Auto,
                ManagedAuthenticationIntent::ReuseOrEphemeral,
            )?;
            let probes = prepared.probe_lines(MANAGED_PROBE_TIMEOUT)?;
            print_line_probes(&probes, lines.json)?;
        }
    }
    Ok(())
}

#[cfg(feature = "managed")]
fn load_managed_domain(
    target: &ManagedTargetArgs,
    store: &state::StateStore,
    profile_required: bool,
) -> Result<(ManagedContext, DomainClient, DiscoveredDomain)> {
    let context = resolve_managed_context(target, store, profile_required)?;
    let client = DomainClient::new(Some(store.cache_directory()));
    let discovered = client.discover(&context.domain, &context.device_id)?;
    Ok((context, client, discovered))
}

#[cfg(feature = "managed")]
fn profile_not_found(name: &str) -> Error {
    Error::InvalidConfig(format!("profile not found: {name}"))
}

#[cfg(feature = "managed")]
fn resolve_managed_context(
    target: &ManagedTargetArgs,
    store: &state::StateStore,
    profile_required: bool,
) -> Result<ManagedContext> {
    let persisted = store.load()?;
    let explicit_domain = target.domain.is_some();
    let profile_name = if let Some(name) = &target.profile {
        state::validate_profile_name(name)?;
        Some(name.clone())
    } else if !explicit_domain {
        persisted.default_profile.clone()
    } else {
        None
    };
    let profile = profile_name
        .as_ref()
        .map(|name| {
            persisted
                .profiles
                .get(name)
                .cloned()
                .ok_or_else(|| profile_not_found(name))
        })
        .transpose()?;

    if profile_required && profile.is_none() {
        return Err(Error::InvalidConfig(
            "no profile specified and no default profile is set".into(),
        ));
    }
    let domain = target
        .domain
        .clone()
        .or_else(|| profile.as_ref().map(|profile| profile.domain.clone()))
        .ok_or_else(|| {
            Error::InvalidConfig("no domain specified and no default profile is set".into())
        })?;
    let device_id = profile
        .as_ref()
        .map(|profile| profile.device_id.clone())
        .map_or_else(|| store.device_id(), Ok)?;
    openiwan::managed::validate_domain(&domain)?;
    if device_id.trim().is_empty() {
        return Err(Error::InvalidConfig("device ID is empty".into()));
    }
    Ok(ManagedContext {
        profile_name,
        domain,
        device_id,
        username: profile
            .as_ref()
            .and_then(|profile| profile.username.clone()),
        line: profile
            .as_ref()
            .map_or_else(LinePreference::default, |profile| profile.line.clone()),
        credential_id: profile
            .as_ref()
            .map(|profile| profile.credential_id.clone())
            .filter(|identifier| !identifier.is_empty()),
        dns: profile
            .as_ref()
            .map_or_else(DnsOverrides::default, |profile| profile.dns.clone()),
        routing: profile
            .as_ref()
            .map_or_else(state::RoutingOverrides::default, |profile| {
                profile.routing.clone()
            }),
    })
}

#[cfg(feature = "managed")]
fn profile(arguments: ProfileArgs, store: &state::StateStore) -> Result<()> {
    match arguments.command {
        ProfileCommand::List { json } => {
            let persisted = store.load()?;
            print_profiles(&persisted, json)?;
        }
        ProfileCommand::Show { name, json } => {
            let persisted = store.load()?;
            let name = name
                .or_else(|| persisted.default_profile.clone())
                .ok_or_else(|| {
                    Error::InvalidConfig(
                        "no profile specified and no default profile is set".into(),
                    )
                })?;
            let profile = persisted
                .profiles
                .get(&name)
                .ok_or_else(|| profile_not_found(&name))?;
            print_profile(&name, profile, persisted.default_profile.as_deref(), json)?;
        }
        ProfileCommand::Set(arguments) => set_profile(*arguments, store)?,
        ProfileCommand::Use { name } => {
            state::validate_profile_name(&name)?;
            store.update(|persisted| {
                if !persisted.profiles.contains_key(&name) {
                    return Err(profile_not_found(&name));
                }
                persisted.default_profile = Some(name.clone());
                Ok(())
            })?;
            println!("default profile: {name}");
        }
        ProfileCommand::Remove { name } => remove_profile(store, &name)?,
        ProfileCommand::Logout { name } => logout_profile(store, name)?,
    }
    Ok(())
}

#[cfg(feature = "managed")]
fn set_profile(arguments: ProfileSetArgs, store: &state::StateStore) -> Result<()> {
    let name = arguments.name.clone();
    state::validate_profile_name(&name)?;
    let existing = store.load()?.profiles.get(&name).cloned();
    let generated_device_id = if existing.is_none() && arguments.device_id.is_none() {
        Some(store.device_id()?)
    } else {
        None
    };
    let authentication_changed = existing.as_ref().is_some_and(|profile| {
        arguments
            .domain
            .as_ref()
            .is_some_and(|domain| domain != &profile.domain)
            || arguments
                .device_id
                .as_ref()
                .is_some_and(|device_id| device_id != &profile.device_id)
            || arguments
                .username
                .as_ref()
                .is_some_and(|username| Some(username) != profile.username.as_ref())
            || (arguments.unset_username && profile.username.is_some())
    });
    if authentication_changed
        && let Some(identifier) = existing
            .as_ref()
            .map(|profile| profile.credential_id.as_str())
            .filter(|identifier| !identifier.is_empty())
    {
        credentials::CredentialStore::delete(identifier)?;
    }
    store.update(|persisted| {
        let was_empty = persisted.profiles.is_empty();
        let mut profile = if let Some(profile) = persisted.profiles.get(&name) {
            profile.clone()
        } else {
            let domain = arguments.domain.clone().ok_or_else(|| {
                Error::InvalidConfig("--domain is required to create a profile".into())
            })?;
            let device_id = arguments
                .device_id
                .clone()
                .or_else(|| generated_device_id.clone())
                .expect("generated above for a new profile");
            state::ManagedProfile::new(domain, device_id)?
        };
        if let Some(domain) = &arguments.domain {
            profile.domain.clone_from(domain);
        }
        if let Some(device_id) = &arguments.device_id {
            profile.device_id.clone_from(device_id);
        }
        if let Some(username) = &arguments.username {
            profile.username = Some(username.clone());
        } else if arguments.unset_username {
            profile.username = None;
        }
        if let Some(line) = &arguments.line {
            profile.line = line.clone();
        }
        patch_profile_routing(&mut profile.routing, &arguments.routing)?;
        if arguments.reset_dns {
            profile.dns = DnsOverrides::default();
        }
        arguments.dns.patch_profile(&mut profile.dns);
        if arguments.unset_dns.contains(&ProfileDnsListArg::Servers) {
            profile.dns.servers = None;
        }
        if arguments
            .unset_dns
            .contains(&ProfileDnsListArg::SplitDomains)
        {
            profile.dns.split_domains = None;
        }
        if arguments.unset_dns.contains(&ProfileDnsListArg::DohHosts) {
            profile.dns.doh_hosts = None;
        }
        if authentication_changed {
            profile.credential_id.clear();
        }
        profile.validate()?;
        persisted.profiles.insert(name.clone(), profile);
        if was_empty && persisted.default_profile.is_none() {
            persisted.default_profile = Some(name.clone());
        }
        Ok(())
    })?;
    let persisted = store.load()?;
    print_profile(
        &name,
        &persisted.profiles[&name],
        persisted.default_profile.as_deref(),
        false,
    )
}

#[cfg(feature = "managed")]
fn patch_profile_routing(
    target: &mut state::RoutingOverrides,
    arguments: &ProfileRoutingArgs,
) -> Result<()> {
    if arguments.unset_routing_mode {
        target.mode = None;
    } else if let Some(mode) = arguments.overrides.routing_mode {
        target.mode = Some(mode);
    }
    if arguments.unset_routes {
        target.routes.clear();
    } else if !arguments.routes.is_empty() {
        target.routes = resolve_route_targets(&arguments.routes, &[], &[], None)?;
    }
    if let Some(block_ipv6) = arguments.overrides.ipv6_override() {
        target.block_ipv6 = block_ipv6;
    }
    Ok(())
}

#[cfg(feature = "managed")]
fn remove_profile(store: &state::StateStore, name: &str) -> Result<()> {
    state::validate_profile_name(name)?;
    let persisted = store.load()?;
    let profile = persisted
        .profiles
        .get(name)
        .ok_or_else(|| profile_not_found(name))?;
    if !profile.credential_id.is_empty() {
        credentials::CredentialStore::delete(&profile.credential_id)?;
    }
    store.update(|persisted| {
        if persisted.profiles.remove(name).is_none() {
            return Err(profile_not_found(name));
        }
        if persisted.default_profile.as_deref() == Some(name) {
            persisted.default_profile = None;
        }
        Ok(())
    })?;
    println!("removed: {name}");
    Ok(())
}

#[cfg(feature = "managed")]
fn logout_profile(store: &state::StateStore, name: Option<String>) -> Result<()> {
    let persisted = store.load()?;
    let name = name
        .or_else(|| persisted.default_profile.clone())
        .ok_or_else(|| {
            Error::InvalidConfig("no profile specified and no default profile is set".into())
        })?;
    state::validate_profile_name(&name)?;
    let profile = persisted
        .profiles
        .get(&name)
        .ok_or_else(|| profile_not_found(&name))?;
    let credential_id = profile.credential_id.clone();
    let removed = if credential_id.is_empty() {
        false
    } else {
        credentials::CredentialStore::delete(&credential_id)?
    };
    if !credential_id.is_empty() {
        store.update(|persisted| {
            let profile = persisted
                .profiles
                .get_mut(&name)
                .ok_or_else(|| profile_not_found(&name))?;
            profile.credential_id.clear();
            Ok(())
        })?;
    }
    if removed {
        println!("credentials removed: {name}");
    } else {
        println!("no saved credentials: {name}");
    }
    Ok(())
}

#[cfg(feature = "managed")]
fn print_profiles(persisted: &state::CliState, json: bool) -> Result<()> {
    if json {
        let profiles = persisted
            .profiles
            .iter()
            .map(|(name, profile)| {
                profile_json(name, profile, persisted.default_profile.as_deref())
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string_pretty(&profiles).map_err(|error| {
                Error::InvalidConfig(format!("serialize profile output: {error}"))
            })?
        );
        return Ok(());
    }
    if persisted.profiles.is_empty() {
        println!("no profiles");
        return Ok(());
    }
    for (name, profile) in &persisted.profiles {
        let marker = if persisted.default_profile.as_deref() == Some(name.as_str()) {
            "*"
        } else {
            " "
        };
        println!(
            "{marker} {name}: domain={} user={} line={}",
            profile.domain,
            profile.username.as_deref().unwrap_or("-"),
            profile.line
        );
    }
    Ok(())
}

#[cfg(feature = "managed")]
fn print_profile(
    name: &str,
    profile: &state::ManagedProfile,
    default_profile: Option<&str>,
    json: bool,
) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&profile_json(name, profile, default_profile)).map_err(
                |error| Error::InvalidConfig(format!("serialize profile output: {error}"))
            )?
        );
        return Ok(());
    }
    println!("profile: {name}");
    println!(
        "  default: {}",
        if default_profile == Some(name) {
            "yes"
        } else {
            "no"
        }
    );
    println!("  domain: {}", profile.domain);
    println!("  device-id: {}", profile.device_id);
    println!("  username: {}", profile.username.as_deref().unwrap_or("-"));
    println!("  line: {}", profile.line);
    println!(
        "  dns: {}",
        if profile.dns == DnsOverrides::default() {
            "inherit".into()
        } else {
            serde_json::to_string(&profile.dns).map_err(|error| {
                Error::InvalidConfig(format!("serialize profile DNS output: {error}"))
            })?
        }
    );
    println!(
        "  routing: {}",
        if profile.routing == state::RoutingOverrides::default() {
            "inherit".into()
        } else {
            serde_json::to_string(&profile.routing).map_err(|error| {
                Error::InvalidConfig(format!("serialize profile routing output: {error}"))
            })?
        }
    );
    Ok(())
}

#[cfg(feature = "managed")]
fn profile_json(
    name: &str,
    profile: &state::ManagedProfile,
    default_profile: Option<&str>,
) -> serde_json::Value {
    let routing_mode = profile
        .routing
        .mode
        .map_or_else(|| "inherit".into(), |mode| mode.to_string());
    serde_json::json!({
        "name": name,
        "default": default_profile == Some(name),
        "domain": profile.domain,
        "device_id": profile.device_id,
        "username": profile.username,
        "line": profile.line.to_string(),
        "dns": profile.dns,
        "routing": {
            "mode": routing_mode,
            "routes": profile.routing.routes,
            "block_ipv6": profile.routing.block_ipv6,
        },
    })
}

#[cfg(feature = "managed")]
fn print_line_probes(probes: &[LineProbe], json: bool) -> Result<()> {
    if json {
        let output = probes
            .iter()
            .map(|probe| {
                serde_json::json!({
                    "id": probe.preference.to_string(),
                    "name": probe.name,
                    "name_en": probe.name_en,
                    "endpoint": probe.endpoint,
                    "reachable": probe.reachable(),
                    "latency_us": probe.latency.map(|latency| latency.as_micros()),
                    "error": probe.error,
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|error| {
                Error::InvalidConfig(format!("serialize line output: {error}"))
            })?
        );
        return Ok(());
    }
    print!("{}", format_line_probes(probes));
    Ok(())
}

#[cfg(feature = "managed")]
fn format_line_probes(probes: &[LineProbe]) -> String {
    use std::fmt::Write as _;

    let rows = probes
        .iter()
        .map(|probe| {
            (
                probe.preference.to_string(),
                probe.latency.map_or_else(
                    || "unreachable".into(),
                    |latency| format!("{:.3} ms", latency.as_secs_f64() * 1_000.0),
                ),
                probe.endpoint.as_deref().unwrap_or("-"),
                probe.name.as_str(),
                probe.error.as_deref(),
            )
        })
        .collect::<Vec<_>>();
    let id_width = rows
        .iter()
        .map(|row| row.0.len())
        .max()
        .unwrap_or_default()
        .max("ID".len());
    let latency_width = rows
        .iter()
        .map(|row| row.1.len())
        .max()
        .unwrap_or_default()
        .max("LATENCY".len());
    let endpoint_width = rows
        .iter()
        .map(|row| row.2.len())
        .max()
        .unwrap_or_default()
        .max("ENDPOINT".len());

    let mut output = String::new();
    writeln!(
        output,
        "{:<id_width$}  {:<latency_width$}  {:<endpoint_width$}  NAME",
        "ID", "LATENCY", "ENDPOINT"
    )
    .expect("writing to a String cannot fail");
    for (id, latency, endpoint, name, error) in rows {
        writeln!(
            output,
            "{id:<id_width$}  {latency:<latency_width$}  {endpoint:<endpoint_width$}  {name}"
        )
        .expect("writing to a String cannot fail");
        if let Some(error) = error {
            writeln!(output, "  error: {error}").expect("writing to a String cannot fail");
        }
    }
    output
}

#[cfg(feature = "managed")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ManagedRoutingSelection {
    mode: RoutingMode,
    user_overridden: bool,
    block_ipv6: bool,
}

#[cfg(feature = "managed")]
fn select_managed_routing(
    route_arguments: &RouteArgs,
    profile_routing: &state::RoutingOverrides,
    controller_routing: Option<&openiwan::managed::RoutingConfiguration>,
) -> ManagedRoutingSelection {
    let user_mode = route_arguments.policy.routing_mode.or(profile_routing.mode);
    let mode = user_mode.map_or_else(
        || controller_routing.map_or(RoutingMode::All, |routing| routing.mode),
        |mode| match mode {
            UserRoutingMode::All => RoutingMode::All,
            UserRoutingMode::Custom => RoutingMode::Custom,
        },
    );
    ManagedRoutingSelection {
        mode,
        user_overridden: user_mode.is_some(),
        block_ipv6: route_arguments
            .policy
            .ipv6_override()
            .unwrap_or(profile_routing.block_ipv6),
    }
}

#[cfg(feature = "managed")]
fn collect_managed_cidrs(
    route_arguments: &RouteArgs,
    profile_routing: &state::RoutingOverrides,
    controller_routing: Option<&openiwan::managed::RoutingConfiguration>,
    ip_filter_inclusive: &[String],
    selection: ManagedRoutingSelection,
) -> Vec<String> {
    let mut cidrs = profile_routing.routes.clone();
    cidrs.extend(route_arguments.routes.iter().cloned());
    cidrs.extend(valid_filter_cidrs(ip_filter_inclusive));
    if !selection.user_overridden
        && controller_routing.is_some_and(|routing| routing.mode == RoutingMode::Custom)
        && let Some(routing) = controller_routing
    {
        cidrs.extend(routing.custom_routes.iter().cloned());
    }
    append_ipv6_capture_routes(&mut cidrs, selection.block_ipv6);
    cidrs
}

#[cfg(feature = "managed")]
fn managed_route_exclusions(
    prepared: &PreparedConnection,
    ip_filter: Option<&openiwan::managed::IpFilterConfiguration>,
    physical: &[PhysicalResolver],
    policy: &EffectiveDnsPolicy,
    block_ipv6: bool,
) -> Result<Vec<String>> {
    let mut exclusions =
        ip_filter.map_or_else(Vec::new, |filter| valid_filter_cidrs(&filter.exclusive));
    exclusions.extend(managed_server_exclusions(&prepared.configuration)?);
    if policy.server_mode == DnsServerMode::Disabled
        || matches!(
            policy.split_mode,
            SplitDnsMode::Managed | SplitDnsMode::Custom
        )
    {
        exclusions.extend(
            physical
                .iter()
                .filter(|resolver| !block_ipv6 || resolver.address.ip().is_ipv4())
                .map(|resolver| {
                    let address = resolver.address.ip();
                    format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 })
                }),
        );
    }
    Ok(exclusions)
}

#[cfg(feature = "managed")]
fn run_managed_client(
    prepared: PreparedConnection,
    tun: Option<&str>,
    route_arguments: &RouteArgs,
    profile_dns: &DnsOverrides,
    dns_arguments: &DnsOverrideArgs,
    profile_routing: &state::RoutingOverrides,
) -> Result<()> {
    let client = prepared.client()?;
    let session = client.authenticate()?;
    print_session(session.info());
    let defaults = prepared
        .configuration
        .dns_defaults(prepared.service_type() == ServiceType::Controller)?;
    let overrides = dns_arguments.applied_to(profile_dns);
    let policy = DnsPolicyResolver::resolve(&defaults, &overrides, &session.info().dns_servers)?;
    let physical = discover_physical_resolvers()?;

    let controller_routing = prepared.configuration.routing()?;
    let routing_selection = select_managed_routing(
        route_arguments,
        profile_routing,
        controller_routing.as_ref(),
    );
    let mode = routing_selection.mode;
    let block_ipv6 = routing_selection.block_ipv6;
    let ip_filter = if mode == RoutingMode::All {
        None
    } else {
        prepared.configuration.ip_filter()?
    };
    let has_ip_filter = ip_filter
        .as_ref()
        .is_some_and(|filter| !filter.inclusive.is_empty() || !filter.exclusive.is_empty());
    let full_ipv4 = mode == RoutingMode::All || (mode == RoutingMode::IpFilter && !has_ip_filter);

    let effective_ip_filter = ip_filter.as_ref().filter(|_| has_ip_filter);
    let ip_filter_inclusive =
        effective_ip_filter.map_or(&[][..], |filter| filter.inclusive.as_slice());
    let mut cidrs = collect_managed_cidrs(
        route_arguments,
        profile_routing,
        controller_routing.as_ref(),
        ip_filter_inclusive,
        routing_selection,
    );

    if mode != RoutingMode::All {
        cidrs.extend(policy.servers.iter().map(|server| format!("{server}/32")));
    }
    let exclusions = managed_route_exclusions(
        &prepared,
        effective_ip_filter,
        &physical,
        &policy,
        block_ipv6,
    )?;
    let routes = resolve_route_policy(
        &cidrs,
        &route_arguments.route_ips,
        &route_arguments.route_domains,
        &exclusions,
        session.info().peer.ip(),
        full_ipv4,
    )?;

    let mut interface_session = session.info().clone();
    if let Some(routing) = &controller_routing
        && routing.mtu_mode == "custom"
        && let Ok(mtu) = u16::try_from(routing.custom_mtu)
        && (576..=9_000).contains(&mtu)
    {
        interface_session.mtu = mtu;
    }
    interface_session.dns_servers = policy.servers.iter().copied().map(IpAddr::V4).collect();
    let device = Arc::new(TunDevice::open(tun, &interface_session)?);
    let _routes = RouteGuard::configure(&device, &routes)?;
    let runtime = Arc::new(
        DnsRuntime::new(
            device.dns_platform_target(),
            defaults,
            overrides,
            physical,
            RelayConfig::default(),
        )?
        .with_physical_ipv6(!block_ipv6),
    );
    let dns_device = Arc::new(DnsPacketDevice::new(Arc::clone(&device), runtime));
    let packet_device = Arc::new(Ipv6BlockingDevice::new(dns_device, block_ipv6));
    for route in &routes {
        tracing::debug!(%route, interface = device.name(), "installed route");
    }
    let mode_label = match mode {
        RoutingMode::All => "all",
        RoutingMode::IpFilter => "ipfilter",
        RoutingMode::Custom => "custom",
    };
    println!(
        "routing: mode={mode_label}, ipv6={}",
        if block_ipv6 { "blocked" } else { "allowed" }
    );
    print_dns_policy(&policy);
    println!("interface: {}", device.name());
    println!("connected; press Ctrl-C to disconnect");

    let shutdown = install_shutdown_handler()?;
    let end = client.run_reconnecting_from(session, packet_device, shutdown)?;
    println!("disconnected: {}", session_end_label(end));
    Ok(())
}

#[cfg(all(feature = "managed", feature = "forward"))]
fn run_managed_forward(
    prepared: &PreparedConnection,
    arguments: &ForwardOptions,
    profile_dns: &DnsOverrides,
) -> Result<()> {
    let client = prepared.client()?;
    let session = client.authenticate()?;
    print_session(session.info());
    let defaults = prepared
        .configuration
        .dns_defaults(prepared.service_type() == ServiceType::Controller)?;
    let policy = DnsPolicyResolver::resolve(&defaults, profile_dns, &session.info().dns_servers)?;
    let dns_servers = policy
        .servers
        .iter()
        .copied()
        .map(IpAddr::V4)
        .collect::<Vec<_>>();
    let target = url::Url::parse(&arguments.target)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned));
    let auto_tunnel = target
        .as_deref()
        .filter(|host| host.parse::<IpAddr>().is_err())
        .map(|host| policy.routes_through_tunnel(host));
    let config = build_forward_config_with_route(arguments, &dns_servers, auto_tunnel)?;
    let shutdown = install_shutdown_handler()?;
    let end = forward::run(client, session, config, shutdown)?;
    println!("disconnected: {}", session_end_label(end));
    Ok(())
}

#[cfg(feature = "managed")]
fn valid_filter_cidrs(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| {
            let valid = value
                .split_once('/')
                .and_then(|(address, prefix)| {
                    let address = address.parse::<std::net::IpAddr>().ok()?;
                    let prefix = prefix.parse::<u8>().ok()?;
                    (prefix <= if address.is_ipv4() { 32 } else { 128 }).then_some(())
                })
                .is_some();
            if valid {
                Some(value.clone())
            } else {
                tracing::warn!(rule = %value, "ignoring invalid IP-filter rule");
                None
            }
        })
        .collect()
}

#[cfg(feature = "managed")]
fn managed_server_exclusions(
    configuration: &openiwan::managed::ControllerConfiguration,
) -> Result<Vec<String>> {
    let mut exclusions = base_full_ipv4_exclusions();
    let mut endpoints = configuration
        .iwan_servers()?
        .into_iter()
        .map(|server| server.endpoint())
        .collect::<Vec<_>>();
    for group in configuration.sr_groups()? {
        endpoints.extend(group.entries.into_iter().filter_map(|entry| {
            let port = u16::try_from(entry.ingress.server_port).ok()?;
            (port != 0 && !entry.ingress.server_name.is_empty()).then(|| {
                if entry.ingress.server_name.contains(':')
                    && !entry.ingress.server_name.starts_with('[')
                {
                    format!("[{}]:{port}", entry.ingress.server_name)
                } else {
                    format!("{}:{port}", entry.ingress.server_name)
                }
            })
        }));
    }
    for endpoint in endpoints {
        if let Ok(addresses) = endpoint.to_socket_addrs() {
            exclusions.extend(addresses.map(|address| {
                let address = address.ip();
                format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 })
            }));
        }
    }
    exclusions.sort();
    exclusions.dedup();
    Ok(exclusions)
}

#[cfg(feature = "managed")]
fn prepare_managed(
    client: &DomainClient,
    discovered: &DiscoveredDomain,
    store: &state::StateStore,
    context: &mut ManagedContext,
    arguments: &ManagedAuthArgs,
    line: &LinePreference,
    intent: ManagedAuthenticationIntent,
) -> Result<PreparedConnection> {
    match discovered.auth.method {
        AuthMethod::Credential => {
            if arguments.posture_results.is_some() {
                return Err(Error::InvalidConfig(
                    "--posture-results is only valid for OIDC domains".into(),
                ));
            }
            prepare_managed_password(client, discovered, store, context, arguments, line, intent)
        }
        AuthMethod::Oidc => {
            if arguments.username.is_some() || arguments.password_file.is_some() {
                return Err(Error::InvalidConfig(
                    "--username and --password-file require password authentication".into(),
                ));
            }
            prepare_managed_oidc(client, discovered, store, context, arguments, line, intent)
        }
    }
}

#[cfg(feature = "managed")]
fn prepare_managed_password(
    client: &DomainClient,
    discovered: &DiscoveredDomain,
    store: &state::StateStore,
    context: &mut ManagedContext,
    arguments: &ManagedAuthArgs,
    line: &LinePreference,
    intent: ManagedAuthenticationIntent,
) -> Result<PreparedConnection> {
    let explicit_password = read_explicit_managed_secret(arguments)?;
    let stored =
        if explicit_password.is_none() && intent == ManagedAuthenticationIntent::ReuseOrEphemeral {
            load_stored_credential(context.credential_id.as_deref())?
        } else {
            None
        };
    if matches!(
        stored.as_ref(),
        Some(credentials::StoredCredential::Oidc { .. })
    ) {
        return Err(Error::CredentialStore(
            "saved credentials use a different authentication method; run \
             `openiwan managed login`"
                .into(),
        ));
    }
    let username = arguments
        .username
        .clone()
        .or_else(|| context.username.clone())
        .or_else(|| match stored.as_ref() {
            Some(credentials::StoredCredential::Password { username, .. }) => {
                Some(username.clone())
            }
            _ => None,
        })
        .ok_or_else(|| {
            Error::InvalidConfig("--username is required for password authentication".into())
        })?;
    let password = if let Some(password) = explicit_password {
        zeroize::Zeroizing::new(password)
    } else if let Some(credentials::StoredCredential::Password {
        username: stored_username,
        password,
    }) = stored.as_ref()
        && stored_username == &username
    {
        zeroize::Zeroizing::new(password.clone())
    } else if arguments.non_interactive {
        return Err(Error::CredentialStore(
            "no password available; run \
             `openiwan managed login` or set OPENIWAN_PASSWORD"
                .into(),
        ));
    } else {
        zeroize::Zeroizing::new(prompt_password("iWAN password: ")?)
    };
    let used_saved_password = matches!(
        stored.as_ref(),
        Some(credentials::StoredCredential::Password {
            username: stored_username,
            ..
        }) if stored_username == &username
    );
    let prepared = client.password_login_with_line(
        discovered,
        &context.device_id,
        &username,
        password.as_str(),
        MANAGED_PROBE_TIMEOUT,
        line,
    );
    let prepared = if used_saved_password {
        prepared.map_err(saved_credentials_rejected)?
    } else {
        prepared?
    };
    if intent == ManagedAuthenticationIntent::FreshAndPersist {
        persist_managed_credential(
            store,
            context,
            &username,
            credentials::StoredCredential::Password {
                username: username.clone(),
                password: password.to_string(),
            },
        )?;
    }
    Ok(prepared)
}

#[cfg(feature = "managed")]
fn prepare_managed_oidc(
    client: &DomainClient,
    discovered: &DiscoveredDomain,
    store: &state::StateStore,
    context: &mut ManagedContext,
    arguments: &ManagedAuthArgs,
    line: &LinePreference,
    intent: ManagedAuthenticationIntent,
) -> Result<PreparedConnection> {
    let stored = if intent == ManagedAuthenticationIntent::ReuseOrEphemeral {
        load_stored_credential(context.credential_id.as_deref())?
    } else {
        None
    };
    if matches!(
        stored.as_ref(),
        Some(credentials::StoredCredential::Password { .. })
    ) {
        return Err(Error::CredentialStore(
            "saved credentials use a different authentication method; run \
             `openiwan managed login`"
                .into(),
        ));
    }
    let used_saved_identity = matches!(
        stored.as_ref(),
        Some(credentials::StoredCredential::Oidc { .. })
    );
    let identity = match stored.as_ref() {
        Some(credentials::StoredCredential::Oidc {
            refresh_token,
            user_id,
            username,
        }) => refresh_saved_oidc(
            client,
            discovered,
            context,
            refresh_token,
            user_id,
            username,
        )
        .map_err(saved_credentials_rejected)?,
        _ if arguments.non_interactive => {
            return Err(Error::CredentialStore(
                "no saved OIDC session; run `openiwan managed login`".into(),
            ));
        }
        _ => interactive_oidc(client, discovered, MANAGED_OIDC_REDIRECT_URI)?,
    };
    let posture_results = read_posture_results(arguments.posture_results.as_deref())?;
    let prepared = client.oidc_login_with_options(
        discovered,
        &context.device_id,
        &identity,
        OidcLoginOptions {
            posture_check_results: &posture_results,
            posture_version: None,
            ping_timeout: MANAGED_PROBE_TIMEOUT,
            line,
        },
    );
    let prepared = if used_saved_identity {
        prepared.map_err(saved_credentials_rejected)?
    } else {
        prepared?
    };
    if intent == ManagedAuthenticationIntent::FreshAndPersist {
        persist_oidc_identity(store, context, &identity)?;
    }
    Ok(prepared)
}

#[cfg(feature = "managed")]
fn refresh_saved_oidc(
    client: &DomainClient,
    discovered: &DiscoveredDomain,
    context: &ManagedContext,
    refresh_token: &str,
    user_id: &str,
    username: &str,
) -> Result<openiwan::managed::OidcIdentity> {
    let identity = client.refresh_oidc(
        discovered,
        MANAGED_OIDC_REDIRECT_URI,
        refresh_token,
        user_id,
        username,
    )?;
    save_oidc_identity(
        context.credential_id.as_deref().expect("loaded above"),
        &identity,
    )?;
    Ok(identity)
}

#[cfg(feature = "managed")]
fn interactive_oidc(
    client: &DomainClient,
    discovered: &DiscoveredDomain,
    redirect_uri: &str,
) -> Result<openiwan::managed::OidcIdentity> {
    let pending = client.begin_oidc(discovered, redirect_uri)?;
    println!(
        "Open this URL in a browser:\n\n{}\n",
        pending.authorization_url()
    );
    let redirect = prompt_line("Callback URL: ")?;
    client.complete_oidc(&pending, &redirect)
}

#[cfg(feature = "managed")]
fn save_oidc_identity(
    credential_id: &str,
    identity: &openiwan::managed::OidcIdentity,
) -> Result<()> {
    if identity.refresh_token.is_empty() {
        return Err(Error::CredentialStore(
            "the identity provider did not issue a refresh token; this login cannot be saved"
                .into(),
        ));
    }
    credentials::CredentialStore::save(
        credential_id,
        credentials::StoredCredential::Oidc {
            refresh_token: identity.refresh_token.to_string(),
            user_id: identity.user_id.clone(),
            username: identity.username.clone(),
        },
    )
}

#[cfg(feature = "managed")]
fn persist_oidc_identity(
    store: &state::StateStore,
    context: &mut ManagedContext,
    identity: &openiwan::managed::OidcIdentity,
) -> Result<()> {
    let credential_id = ensure_credential_id(store, context)?;
    save_oidc_identity(&credential_id, identity)?;
    sync_profile_username(store, context, &identity.username)
}

#[cfg(feature = "managed")]
fn persist_managed_credential(
    store: &state::StateStore,
    context: &mut ManagedContext,
    username: &str,
    credential: credentials::StoredCredential,
) -> Result<()> {
    let credential_id = ensure_credential_id(store, context)?;
    credentials::CredentialStore::save(&credential_id, credential)?;
    sync_profile_username(store, context, username)
}

#[cfg(feature = "managed")]
fn ensure_credential_id(store: &state::StateStore, context: &mut ManagedContext) -> Result<String> {
    if let Some(identifier) = &context.credential_id {
        return Ok(identifier.clone());
    }
    let profile_name = context.profile_name.as_deref().ok_or_else(|| {
        Error::InvalidConfig("no profile specified and no default profile is set".into())
    })?;
    let identifier = store.update(|persisted| {
        let profile = persisted
            .profiles
            .get_mut(profile_name)
            .ok_or_else(|| profile_not_found(profile_name))?;
        Ok(profile.ensure_credential_id()?.to_owned())
    })?;
    context.credential_id = Some(identifier.clone());
    Ok(identifier)
}

#[cfg(feature = "managed")]
fn sync_profile_username(
    store: &state::StateStore,
    context: &mut ManagedContext,
    username: &str,
) -> Result<()> {
    let profile_name = context.profile_name.as_deref().ok_or_else(|| {
        Error::InvalidConfig("no profile specified and no default profile is set".into())
    })?;
    store.update(|persisted| {
        let profile = persisted
            .profiles
            .get_mut(profile_name)
            .ok_or_else(|| profile_not_found(profile_name))?;
        profile.username = Some(username.to_owned());
        Ok(())
    })?;
    context.username = Some(username.to_owned());
    Ok(())
}

#[cfg(feature = "managed")]
fn load_stored_credential(
    credential_id: Option<&str>,
) -> Result<Option<credentials::StoredCredential>> {
    credential_id.map_or(Ok(None), credentials::CredentialStore::load)
}

#[cfg(feature = "managed")]
fn saved_credentials_rejected(error: Error) -> Error {
    Error::CredentialStore(format!(
        "saved credentials rejected: {error}; run `openiwan managed login`"
    ))
}

#[cfg(feature = "managed")]
fn print_discovery(discovered: &DiscoveredDomain, device_id: &str) {
    println!("domain: {}", discovered.active_domain());
    println!("device-id: {device_id}");
    println!("service: {}", discovered.lookup.service_type.as_str());
    println!(
        "source: {}",
        match discovered.lookup.source {
            openiwan::managed::LookupSource::Network => "network",
            openiwan::managed::LookupSource::Cache => "cache",
        }
    );
    println!(
        "auth: {}",
        match discovered.auth.method {
            AuthMethod::Credential => "credential",
            AuthMethod::Oidc => "oidc",
        }
    );
}

#[cfg(feature = "managed")]
fn print_prepared(prepared: &PreparedConnection) {
    println!("domain: {}", prepared.domain);
    println!("line: {}", prepared.ingress.line_preference());
    match &prepared.ingress {
        SelectedIngress::Iwan { server, latency } => println!(
            "server: {} endpoint={} latency={:.3} ms",
            server.name,
            server.endpoint(),
            latency.as_secs_f64() * 1_000.0
        ),
        SelectedIngress::SegmentRouting {
            group_id,
            entry,
            latency,
        } => println!(
            "sr-group: {group_id}, ingress={}:{} latency={:.3} ms",
            entry.ingress.server_name,
            entry.ingress.server_port,
            latency.as_secs_f64() * 1_000.0
        ),
    }
}

#[cfg(feature = "managed")]
fn read_explicit_managed_secret(arguments: &ManagedAuthArgs) -> Result<Option<String>> {
    if let Some(path) = &arguments.password_file {
        validate_secret_file(path)?;
        let mut contents = fs::read_to_string(path)?;
        let password = contents
            .lines()
            .next()
            .map(str::to_owned)
            .filter(|password| !password.is_empty())
            .ok_or_else(|| Error::InvalidConfig("password file is empty".into()));
        contents.zeroize();
        return password.map(Some);
    }
    if let Ok(password) = std::env::var(MANAGED_PASSWORD_ENV)
        && !password.is_empty()
    {
        return Ok(Some(password));
    }
    Ok(None)
}

#[cfg(feature = "managed")]
fn read_posture_results(path: Option<&Path>) -> Result<Vec<serde_json::Value>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?)
        .map_err(|error| Error::InvalidConfig(format!("{}: {error}", path.display())))?;
    value
        .as_array()
        .cloned()
        .ok_or_else(|| Error::InvalidConfig(format!("{}: expected a JSON array", path.display())))
}

#[cfg(feature = "managed")]
fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut value = String::new();
    std::io::stdin().read_line(&mut value)?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(Error::InvalidConfig("callback URL is empty".into()));
    }
    Ok(value)
}

fn build_client(arguments: &ConnectionArgs) -> Result<Client> {
    let mut config = if let Some(path) = &arguments.config {
        let contents = fs::read_to_string(path)?;
        toml::from_str::<ClientConfig>(&contents)
            .map_err(|error| Error::InvalidConfig(format!("{}: {error}", path.display())))?
    } else {
        ClientConfig::new(
            arguments
                .server
                .clone()
                .ok_or_else(|| Error::InvalidConfig("specify --server or --config".into()))?,
        )
    };
    if let Some(server) = &arguments.server {
        config.server.clone_from(server);
    }
    if let Some(mtu) = arguments.mtu {
        config.mtu = mtu;
    }
    if let Some(encryption) = arguments.encryption {
        config.encryption = encryption;
    }
    let password = read_secret(arguments)?;
    Client::new(config, arguments.username.clone(), password)
}

fn read_secret(arguments: &ConnectionArgs) -> Result<String> {
    if let Some(path) = &arguments.password_file {
        validate_secret_file(path)?;
        let mut contents = fs::read_to_string(path)?;
        let password = contents
            .lines()
            .next()
            .map(str::to_owned)
            .filter(|password| !password.is_empty())
            .ok_or_else(|| Error::InvalidConfig("password file is empty".into()));
        contents.zeroize();
        return password;
    }
    if let Ok(password) = std::env::var(&arguments.password_env)
        && !password.is_empty()
    {
        return Ok(password);
    }
    prompt_password("iWAN password: ")
}

#[cfg(unix)]
fn validate_secret_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(Error::InvalidConfig(format!(
            "{}: permissions allow access by group or other users",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn validate_secret_file(_path: &Path) -> Result<()> {
    Ok(())
}

fn prompt_password(prompt: &str) -> Result<String> {
    let mut password = rpassword::prompt_password(prompt)?;
    if password.is_empty() {
        password.zeroize();
        return Err(Error::InvalidConfig("password must not be empty".into()));
    }
    Ok(password)
}

fn decode(hex: &str) -> Result<()> {
    let bytes = decode_hex(hex)?;
    if bytes.first().copied() == Some(protocol::PacketType::SegmentRouting as u8) {
        let (header, header_length) = openiwan::sr::SrHeader::parse(&bytes)?;
        let inner = protocol::PacketHeader::decode_inner(
            bytes
                .get(header_length..)
                .ok_or(Error::InvalidSegmentRouting("missing SR inner header"))?,
        )?;
        println!(
            "sr next_id={} links={} algorithm={:?} padding={}",
            header.next_id,
            header
                .links
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
            header.algorithm,
            header.padding_length
        );
        println!(
            "inner type={} encryption={} session_id={} token={:#010x}",
            inner.packet_type, inner.encryption, inner.session_id, inner.token
        );
        println!(
            "body={}",
            encode_hex(
                bytes
                    .get(header_length + protocol::HEADER_LEN..)
                    .ok_or(Error::InvalidSegmentRouting("missing SR inner body"))?
            )
        );
        return Ok(());
    }
    let packet = protocol::decode_packet(&bytes)?;
    println!(
        "type={} encryption={} session_id={} token={:#010x}",
        packet.header.packet_type,
        packet.header.encryption,
        packet.header.session_id,
        packet.header.token
    );
    println!("signature={}", packet.signature.is_some());
    if matches!(
        packet.header.packet_type,
        protocol::PacketType::Open
            | protocol::PacketType::OpenAck
            | protocol::PacketType::OpenReject
    ) {
        for attribute in Tlv::parse_all(&packet.body)? {
            println!(
                "tlv={} length={} value={}",
                attribute.kind.name(),
                attribute.value.len(),
                encode_hex(&attribute.value)
            );
        }
    } else {
        println!("body={}", encode_hex(&packet.body));
    }
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    let compact: String = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && !matches!(character, ':' | '-'))
        .collect();
    if !compact.len().is_multiple_of(2) {
        return Err(Error::InvalidConfig(
            "hexadecimal input has an odd number of digits".into(),
        ));
    }
    (0..compact.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&compact[offset..offset + 2], 16)
                .map_err(|_| Error::InvalidConfig(format!("invalid hex at digit {offset}")))
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn print_session(session: &openiwan::SessionInfo) {
    println!("authenticated: {}", session.peer);
    tracing::debug!(
        peer = %session.peer,
        session_id = session.session_id,
        token = session.token,
        encryption = %session.encryption,
        mtu = session.mtu,
        segment_routing = session.segment_routing,
        "session parameters"
    );
    if let Some(address) = session.address {
        println!("address: {address}");
    }
    if let Some(gateway) = session.gateway {
        println!("gateway: {gateway}");
    }
    if !session.dns_servers.is_empty() {
        println!(
            "dns: {}",
            session
                .dns_servers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

fn init_logging(verbosity: u8) {
    let default = match verbosity {
        0 => "openiwan=info",
        1 => "openiwan=debug",
        _ => "openiwan=trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "managed")]
    fn test_state_store(name: &str) -> state::StateStore {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        state::StateStore::new(Some(std::env::temp_dir().join(format!(
            "openiwan-cli-test-{}-{name}-{counter}",
            std::process::id()
        ))))
        .unwrap()
    }

    #[test]
    fn hex_decoder_accepts_capture_formats() {
        assert_eq!(decode_hex("11:22 aa-bb").unwrap(), [0x11, 0x22, 0xaa, 0xbb]);
        assert!(decode_hex("abc").is_err());
    }

    #[test]
    fn parses_human_readable_timeouts() {
        let parsed =
            Cli::try_parse_from(["openiwan", "ping", "192.0.2.10:6001", "--timeout", "750ms"])
                .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Ping(PingArgs {
                timeout,
                ..
            }) if timeout == Duration::from_millis(750)
        ));
        assert_eq!(parse_duration("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_duration("3m").unwrap(), Duration::from_mins(3));
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("1000").is_err());
    }

    #[test]
    fn tun_name_is_optional_and_can_be_overridden() {
        let base = [
            "openiwan",
            "connect",
            "--server",
            "192.0.2.10:6001",
            "--username",
            "alice",
        ];
        let parsed = Cli::try_parse_from(base).unwrap();
        assert!(matches!(
            parsed.command,
            Command::Connect(ConnectArgs { tun: None, .. })
        ));

        let parsed = Cli::try_parse_from(
            base.into_iter()
                .chain(["--tun", "custom-tun"])
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Connect(ConnectArgs {
                tun: Some(ref name),
                ..
            }) if name == "custom-tun"
        ));
    }

    #[test]
    fn parses_typed_dns_overrides() {
        let parsed = Cli::try_parse_from([
            "openiwan",
            "connect",
            "--server",
            "192.0.2.10:6001",
            "--username",
            "alice",
            "--dns-mode",
            "custom",
            "--dns-server",
            "192.0.2.53",
            "--split-dns-mode",
            "custom",
            "--split-dns-domain",
            "@corp.example",
            "--encrypted-dns",
            "block",
            "--doh-host",
            "dns.example",
        ])
        .unwrap();
        let Command::Connect(arguments) = parsed.command else {
            panic!("expected connect");
        };
        let overrides = arguments.dns.applied_to(&DnsOverrides::default());
        assert_eq!(overrides.server_mode, Some(DnsServerMode::Custom));
        assert_eq!(overrides.servers, Some(vec![Ipv4Addr::new(192, 0, 2, 53)]));
        assert_eq!(overrides.split_mode, Some(SplitDnsMode::Custom));
        assert_eq!(
            overrides.split_domains,
            Some(vec!["@corp.example".parse().unwrap()])
        );
        assert_eq!(overrides.encrypted_dns, Some(EncryptedDnsMode::Block));
    }

    #[test]
    fn explicit_dns_inherit_clears_lower_precedence_profile_values() {
        let lower = DnsOverrides {
            server_mode: Some(DnsServerMode::Custom),
            servers: Some(vec![Ipv4Addr::new(192, 0, 2, 53)]),
            split_mode: Some(SplitDnsMode::Custom),
            split_domains: Some(vec!["@corp.example".parse().unwrap()]),
            encrypted_dns: Some(EncryptedDnsMode::Block),
            doh_hosts: Some(vec!["dns.example".into()]),
        };
        let arguments = DnsOverrideArgs {
            dns_mode: Some(DnsServerModeArg::Inherit),
            split_dns_mode: Some(SplitDnsModeArg::Inherit),
            encrypted_dns: Some(EncryptedDnsModeArg::Inherit),
            ..DnsOverrideArgs::default()
        };

        let overrides = arguments.applied_to(&lower);
        assert_eq!(overrides.server_mode, None);
        assert_eq!(overrides.servers, None);
        assert_eq!(overrides.split_mode, None);
        assert_eq!(overrides.split_domains, None);
        assert_eq!(overrides.encrypted_dns, Some(EncryptedDnsMode::Inherit));
        assert_eq!(overrides.doh_hosts, lower.doh_hosts);
    }

    #[test]
    fn parses_routing_mode_and_ipv6_policy() {
        let parsed = Cli::try_parse_from([
            "openiwan",
            "connect",
            "--server",
            "192.0.2.10:6001",
            "--username",
            "alice",
            "--routing-mode",
            "all",
            "--block-ipv6",
            "--route",
            "10.0.0.0/8",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Connect(ConnectArgs {
                routes: RouteArgs {
                    policy: RoutingOverrideArgs {
                        routing_mode: Some(UserRoutingMode::All),
                        block_ipv6: true,
                        allow_ipv6: false,
                    },
                    routes,
                    ..
                },
                ..
            }) if routes == ["10.0.0.0/8"]
        ));
        assert!(
            Cli::try_parse_from([
                "openiwan",
                "connect",
                "--server",
                "192.0.2.10:6001",
                "--username",
                "alice",
                "--block-ipv6",
                "--allow-ipv6",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "openiwan",
                "profile",
                "set",
                "work",
                "--routing-mode",
                "custom",
                "--unset-routing-mode",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "openiwan",
                "profile",
                "set",
                "work",
                "--route",
                "10.0.0.0/8",
                "--unset-routes",
            ])
            .is_err()
        );

        #[cfg(feature = "managed")]
        {
            let parsed = Cli::try_parse_from([
                "openiwan",
                "managed",
                "connect",
                "--domain",
                "iwan.example",
                "--routing-mode",
                "custom",
                "--allow-ipv6",
                "--route",
                "10.0.0.0/8",
            ])
            .unwrap();
            assert!(matches!(
                parsed.command,
                Command::Managed(ManagedArgs {
                    action: ManagedCommand::Connect(ManagedConnectArgs {
                        routes: RouteArgs {
                            policy: RoutingOverrideArgs {
                                routing_mode: Some(UserRoutingMode::Custom),
                                block_ipv6: false,
                                allow_ipv6: true,
                            },
                            routes,
                            ..
                        },
                        ..
                    }),
                    ..
                }) if routes == ["10.0.0.0/8"]
            ));
        }
    }

    #[derive(Default)]
    struct QueuePacketDevice {
        reads: std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>,
        writes: std::sync::Mutex<Vec<Vec<u8>>>,
        active: AtomicBool,
    }

    impl PacketDevice for QueuePacketDevice {
        fn name(&self) -> &'static str {
            "queue0"
        }

        fn activate_session(&self, _session: &openiwan::SessionInfo) -> Result<()> {
            self.active.store(true, Ordering::Release);
            Ok(())
        }

        fn deactivate_session(&self) -> Result<()> {
            self.active.store(false, Ordering::Release);
            Ok(())
        }

        fn read_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
            let packet = self
                .reads
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "empty"))?;
            buffer[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }

        fn write_packet(&self, packet: &[u8]) -> io::Result<usize> {
            self.writes.lock().unwrap().push(packet.to_vec());
            Ok(packet.len())
        }
    }

    #[test]
    fn ipv6_blocking_device_drops_both_packet_directions() {
        let inner = Arc::new(QueuePacketDevice::default());
        inner
            .reads
            .lock()
            .unwrap()
            .extend([vec![0x60, 0, 0, 0], vec![0x45, 0, 0, 0]]);
        let device = Ipv6BlockingDevice::new(Arc::clone(&inner), true);
        let mut buffer = [0_u8; 64];

        assert_eq!(device.read_packet(&mut buffer).unwrap(), 4);
        assert_eq!(buffer[0] >> 4, 4);
        assert_eq!(device.write_packet(&[0x60, 1, 2, 3]).unwrap(), 4);
        assert!(inner.writes.lock().unwrap().is_empty());
        assert_eq!(device.write_packet(&[0x45, 1, 2, 3]).unwrap(), 4);
        assert_eq!(&*inner.writes.lock().unwrap(), &[vec![0x45, 1, 2, 3]]);

        let session = openiwan::SessionInfo {
            peer: "192.0.2.1:6001".parse().unwrap(),
            session_id: 1,
            token: 2,
            encryption: EncryptionMethod::Xor,
            mtu: 1400,
            address: Some("198.18.0.2".parse().unwrap()),
            gateway: None,
            dns_servers: Vec::new(),
            segment_routing: false,
        };
        device.activate_session(&session).unwrap();
        assert!(inner.active.load(Ordering::Acquire));
        device.deactivate_session().unwrap();
        assert!(!inner.active.load(Ordering::Acquire));
    }

    #[test]
    fn ipv6_capture_routes_exclude_the_active_ipv6_peer() {
        let peer: IpAddr = "2001:db8::1".parse().unwrap();
        let mut cidrs = Vec::new();
        append_ipv6_capture_routes(&mut cidrs, true);
        let routes = resolve_route_policy(&cidrs, &[], &[], &[], peer, false).unwrap();

        assert!(routes.iter().any(|route| route.starts_with("8000::/1")));
        assert!(!routes.iter().any(|route| cidr_contains(route, peer)));
        assert!(
            routes
                .iter()
                .any(|route| cidr_contains(route, "2001:db8::2".parse().unwrap()))
        );
    }

    fn cidr_contains(cidr: &str, candidate: IpAddr) -> bool {
        let (network, prefix) = cidr.split_once('/').unwrap();
        let network = network.parse::<IpAddr>().unwrap();
        let prefix = prefix.parse::<u8>().unwrap();
        match (network, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                u32::from(network) & mask == u32::from(candidate) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                u128::from(network) & mask == u128::from(candidate) & mask
            }
            _ => false,
        }
    }

    #[cfg(feature = "managed")]
    #[test]
    fn parses_managed_login_command() {
        let parsed = Cli::try_parse_from([
            "openiwan",
            "managed",
            "login",
            "--profile",
            "work",
            "--username",
            "alice",
            "--non-interactive",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Managed(ManagedArgs {
                action: ManagedCommand::Login(ManagedLoginArgs {
                    target: ManagedProfileTargetArgs {
                        profile: Some(profile),
                    },
                    auth: ManagedAuthArgs {
                        username: Some(username),
                        non_interactive: true,
                        ..
                    }
                }),
            }) if profile == "work" && username == "alice"
        ));
    }

    #[cfg(feature = "managed")]
    #[test]
    fn managed_cli_rejects_removed_and_misplaced_options() {
        for arguments in [
            vec![
                "openiwan",
                "managed",
                "--domain",
                "iwan.example",
                "discover",
            ],
            vec![
                "openiwan",
                "managed",
                "discover",
                "--state-dir",
                "/tmp/state",
            ],
            vec!["openiwan", "managed", "discover", "--device-id", "device-1"],
            vec![
                "openiwan",
                "managed",
                "discover",
                "--cache-dir",
                "/tmp/cache",
            ],
            vec!["openiwan", "managed", "lines", "--probe-timeout", "3s"],
            vec!["openiwan", "managed", "login", "--password-env", "PASSWORD"],
            vec![
                "openiwan",
                "managed",
                "login",
                "--redirect-uri",
                "app://callback",
            ],
            vec!["openiwan", "managed", "login", "--posture-version", "1"],
            vec!["openiwan", "managed", "login", "--save"],
            vec!["openiwan", "managed", "login", "--reauth"],
            vec!["openiwan", "managed", "login", "--line", "auto"],
            vec!["openiwan", "managed", "login", "--domain", "iwan.example"],
            vec!["openiwan", "profile", "--state-dir", "/tmp/state", "list"],
        ] {
            assert!(
                Cli::try_parse_from(arguments.clone()).is_err(),
                "{arguments:?} should be rejected"
            );
        }

        assert!(
            Cli::try_parse_from([
                "openiwan",
                "managed",
                "connect",
                "--profile",
                "work",
                "--domain",
                "iwan.example",
            ])
            .is_err()
        );
    }

    #[cfg(feature = "managed")]
    #[test]
    fn saved_credential_errors_direct_users_to_managed_login() {
        let error = saved_credentials_rejected(Error::AuthenticationRejected {
            code: 1,
            message: "invalid password".into(),
        });
        let message = error.to_string();
        assert!(message.contains("invalid password"));
        assert!(message.contains("openiwan managed login"));
    }

    #[cfg(all(feature = "managed", feature = "forward"))]
    #[test]
    fn parses_managed_forward_command() {
        let parsed = Cli::try_parse_from([
            "openiwan",
            "managed",
            "forward",
            "--domain",
            "iwan.ustc",
            "--username",
            "alice",
            "--line",
            "iwan:7",
            "--target",
            "tcp://db.internal.example:5432",
            "--listen",
            "127.0.0.1:9543",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Managed(ManagedArgs {
                action: ManagedCommand::Forward(ManagedForwardArgs {
                    target: ManagedTargetArgs {
                        domain: Some(domain),
                        ..
                    },
                    auth: ManagedAuthArgs {
                        username: Some(username),
                        ..
                    },
                    connection: ManagedConnectionOverrideArgs {
                        line: Some(LinePreference::Iwan { server_id }),
                    },
                    forward: ForwardOptions { target, listen, .. },
                }),
            }) if domain == "iwan.ustc"
                && username == "alice"
                && server_id == "7"
                && target == "tcp://db.internal.example:5432"
                && listen == "127.0.0.1:9543".parse().unwrap()
        ));
    }

    #[cfg(feature = "managed")]
    #[test]
    fn managed_context_generates_and_reuses_device_id() {
        let store = test_state_store("context-device-id");
        let target = ManagedTargetArgs {
            profile: None,
            domain: Some("iwan.example".into()),
        };

        let first = resolve_managed_context(&target, &store, false).unwrap();
        let second = resolve_managed_context(&target, &store, false).unwrap();
        assert_eq!(first.device_id, second.device_id);
        assert_eq!(first.device_id, store.load().unwrap().device_id);

        fs::remove_dir_all(store.directory()).unwrap();
    }

    #[cfg(feature = "managed")]
    #[test]
    fn new_profile_uses_generated_device_id() {
        let store = test_state_store("profile-device-id");
        set_profile(
            ProfileSetArgs {
                name: "work".into(),
                domain: Some("iwan.example".into()),
                device_id: None,
                username: Some("alice".into()),
                unset_username: false,
                line: None,
                routing: ProfileRoutingArgs::default(),
                dns: DnsOverrideArgs::default(),
                reset_dns: false,
                unset_dns: Vec::new(),
            },
            &store,
        )
        .unwrap();

        let state = store.load().unwrap();
        assert!(!state.device_id.is_empty());
        assert_eq!(state.profiles["work"].device_id, state.device_id);

        fs::remove_dir_all(store.directory()).unwrap();
    }

    #[cfg(feature = "managed")]
    #[test]
    fn successful_managed_login_can_synchronize_the_profile_username() {
        let store = test_state_store("profile-login-username");
        set_profile(
            ProfileSetArgs {
                name: "work".into(),
                domain: Some("iwan.example".into()),
                device_id: None,
                username: Some("old-user".into()),
                unset_username: false,
                line: None,
                routing: ProfileRoutingArgs::default(),
                dns: DnsOverrideArgs::default(),
                reset_dns: false,
                unset_dns: Vec::new(),
            },
            &store,
        )
        .unwrap();
        let target = ManagedTargetArgs {
            profile: Some("work".into()),
            domain: None,
        };
        let mut context = resolve_managed_context(&target, &store, true).unwrap();

        sync_profile_username(&store, &mut context, "alice").unwrap();

        assert_eq!(context.username.as_deref(), Some("alice"));
        assert_eq!(
            store.load().unwrap().profiles["work"].username.as_deref(),
            Some("alice")
        );
        fs::remove_dir_all(store.directory()).unwrap();
    }

    #[cfg(feature = "managed")]
    #[test]
    fn parses_profile_and_line_commands() {
        let parsed = Cli::try_parse_from([
            "openiwan",
            "profile",
            "set",
            "work",
            "--domain",
            "iwan.example",
            "--device-id",
            "device-1",
            "--line",
            "iwan:7",
            "--unset-username",
            "--reset-dns",
            "--unset-dns",
            "servers",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Profile(ProfileArgs {
                command: ProfileCommand::Set(arguments),
                ..
            }) if arguments.name == "work"
                && arguments.unset_username
                && arguments.reset_dns
                && arguments.unset_dns == [ProfileDnsListArg::Servers]
                && matches!(
                    arguments.line,
                    Some(LinePreference::Iwan { ref server_id }) if server_id == "7"
                )
        ));

        let parsed = Cli::try_parse_from([
            "openiwan",
            "managed",
            "lines",
            "--profile",
            "work",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Managed(ManagedArgs {
                action: ManagedCommand::Lines(ManagedLinesArgs {
                    target: ManagedTargetArgs {
                        profile: Some(name),
                        ..
                    },
                    json: true,
                    ..
                }),
            }) if name == "work"
        ));
        assert!(
            Cli::try_parse_from([
                "openiwan",
                "managed",
                "lines",
                "--profile",
                "work",
                "--set",
                "sr:3",
            ])
            .is_err()
        );

        let parsed = Cli::try_parse_from(["openiwan", "profile", "logout", "work"]).unwrap();
        assert!(matches!(
            parsed.command,
            Command::Profile(ProfileArgs {
                command: ProfileCommand::Logout { name: Some(name) },
                ..
            }) if name == "work"
        ));
    }

    #[cfg(feature = "managed")]
    #[test]
    fn managed_routing_precedence_and_custom_route_sources_are_stable() {
        let controller = openiwan::managed::RoutingConfiguration {
            mode: RoutingMode::Custom,
            custom_routes: vec!["172.16.0.0/12".into()],
            mtu_mode: "server".into(),
            custom_mtu: 0,
        };
        let profile = state::RoutingOverrides {
            mode: Some(UserRoutingMode::Custom),
            routes: vec!["10.0.0.0/8".into()],
            block_ipv6: true,
        };
        let mut command = RouteArgs::default();
        command.routes.push("192.0.2.0/24".into());

        let profile_selection = select_managed_routing(&command, &profile, Some(&controller));
        assert_eq!(
            profile_selection,
            ManagedRoutingSelection {
                mode: RoutingMode::Custom,
                user_overridden: true,
                block_ipv6: true,
            }
        );
        let cidrs = collect_managed_cidrs(
            &command,
            &profile,
            Some(&controller),
            &["100.64.0.0/10".into()],
            profile_selection,
        );
        assert!(cidrs.contains(&"10.0.0.0/8".into()));
        assert!(cidrs.contains(&"192.0.2.0/24".into()));
        assert!(cidrs.contains(&"100.64.0.0/10".into()));
        assert!(!cidrs.contains(&"172.16.0.0/12".into()));
        assert!(cidrs.contains(&"::/1".into()));
        assert!(cidrs.contains(&"8000::/1".into()));

        command.policy.routing_mode = Some(UserRoutingMode::All);
        command.policy.allow_ipv6 = true;
        let cli_selection = select_managed_routing(&command, &profile, Some(&controller));
        assert_eq!(
            cli_selection,
            ManagedRoutingSelection {
                mode: RoutingMode::All,
                user_overridden: true,
                block_ipv6: false,
            }
        );

        let inherited = select_managed_routing(
            &RouteArgs::default(),
            &state::RoutingOverrides::default(),
            Some(&controller),
        );
        let inherited_cidrs = collect_managed_cidrs(
            &RouteArgs::default(),
            &state::RoutingOverrides::default(),
            Some(&controller),
            &[],
            inherited,
        );
        assert_eq!(inherited.mode, RoutingMode::Custom);
        assert!(inherited_cidrs.contains(&"172.16.0.0/12".into()));
    }

    #[cfg(feature = "managed")]
    #[test]
    fn profile_routing_updates_replace_and_clear_saved_routes() {
        let store = test_state_store("profile-routing");
        let parsed = Cli::try_parse_from([
            "openiwan",
            "profile",
            "set",
            "work",
            "--domain",
            "iwan.example",
            "--routing-mode",
            "custom",
            "--route",
            "10.1.2.3/8",
            "--block-ipv6",
        ])
        .unwrap();
        let Command::Profile(ProfileArgs {
            command: ProfileCommand::Set(arguments),
            ..
        }) = parsed.command
        else {
            panic!("expected profile set");
        };
        set_profile(*arguments, &store).unwrap();

        let profile = &store.load().unwrap().profiles["work"];
        assert_eq!(profile.routing.mode, Some(UserRoutingMode::Custom));
        assert_eq!(profile.routing.routes, ["10.0.0.0/8"]);
        assert!(profile.routing.block_ipv6);

        let parsed = Cli::try_parse_from([
            "openiwan",
            "profile",
            "set",
            "work",
            "--unset-routing-mode",
            "--route",
            "192.0.2.0/24",
            "--allow-ipv6",
        ])
        .unwrap();
        let Command::Profile(ProfileArgs {
            command: ProfileCommand::Set(arguments),
            ..
        }) = parsed.command
        else {
            panic!("expected profile set");
        };
        set_profile(*arguments, &store).unwrap();

        let persisted = store.load().unwrap();
        let profile = &persisted.profiles["work"];
        assert_eq!(profile.routing.mode, None);
        assert_eq!(profile.routing.routes, ["192.0.2.0/24"]);
        assert!(!profile.routing.block_ipv6);
        assert_eq!(
            profile_json("work", profile, Some("work"))["routing"]["routes"][0],
            "192.0.2.0/24"
        );
        assert_eq!(
            profile_json("work", profile, Some("work"))["routing"]["mode"],
            "inherit"
        );
        assert_eq!(
            profile_json("work", profile, Some("work"))["routing"]["block_ipv6"],
            false
        );

        let parsed =
            Cli::try_parse_from(["openiwan", "profile", "set", "work", "--unset-routes"]).unwrap();
        let Command::Profile(ProfileArgs {
            command: ProfileCommand::Set(arguments),
            ..
        }) = parsed.command
        else {
            panic!("expected profile set");
        };
        set_profile(*arguments, &store).unwrap();
        assert!(
            store.load().unwrap().profiles["work"]
                .routing
                .routes
                .is_empty()
        );

        fs::remove_dir_all(store.directory()).unwrap();
    }

    #[cfg(feature = "managed")]
    #[test]
    fn formats_managed_lines_with_dynamic_column_widths() {
        let probes = [
            LineProbe {
                preference: LinePreference::Iwan {
                    server_id: "2".into(),
                },
                name: "教育网线路".into(),
                name_en: "Education network".into(),
                endpoint: Some("202.38.64.106:6001".into()),
                latency: Some(Duration::from_micros(35_687)),
                error: None,
            },
            LineProbe {
                preference: LinePreference::Iwan {
                    server_id: "30".into(),
                },
                name: "移动线路".into(),
                name_en: "Mobile network".into(),
                endpoint: None,
                latency: None,
                error: Some("probe timed out".into()),
            },
        ];

        let output = format_line_probes(&probes);
        let lines = output.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 4);
        assert_eq!(
            lines[0].find("LATENCY"),
            lines[1].find("35.687 ms"),
            "latency column should align with its heading"
        );
        assert_eq!(
            lines[0].find("ENDPOINT"),
            lines[1].find("202.38.64.106:6001"),
            "endpoint column should align with its heading"
        );
        assert_eq!(
            lines[0].find("NAME"),
            lines[1].find("教育网线路"),
            "name column should align with its heading"
        );
        assert_eq!(
            lines[0].find("NAME"),
            lines[2].find("移动线路"),
            "short values should be padded to the computed column width"
        );
        assert_eq!(lines[3], "  error: probe timed out");
        assert!(!output.contains('\t'));
    }

    #[cfg(feature = "managed")]
    #[test]
    fn invalid_server_ip_filter_rules_are_ignored() {
        assert_eq!(
            valid_filter_cidrs(&[
                "10.0.0.0/8".into(),
                "10.0.0.0/99".into(),
                "not-a-route".into()
            ]),
            ["10.0.0.0/8"]
        );
    }

    #[cfg(feature = "managed")]
    #[test]
    fn managed_controller_dns_rejects_unspecified_and_uses_official_fallbacks() {
        let servers = DnsPolicyResolver::resolve(
            &DnsDefaults {
                controller_service: true,
                ..DnsDefaults::default()
            },
            &DnsOverrides::default(),
            &["0.0.0.0".parse().unwrap()],
        )
        .unwrap()
        .servers;
        assert_eq!(
            servers,
            [
                "1.1.1.1".parse::<Ipv4Addr>().unwrap(),
                "114.114.114.114".parse().unwrap()
            ]
        );
        assert!(
            DnsPolicyResolver::resolve(
                &DnsDefaults::default(),
                &DnsOverrides::default(),
                &["0.0.0.0".parse().unwrap()],
            )
            .unwrap()
            .servers
            .is_empty()
        );
    }

    #[cfg(feature = "forward")]
    #[test]
    fn parses_manual_forward() {
        let parsed = Cli::try_parse_from([
            "openiwan",
            "forward",
            "--server",
            "192.0.2.10:6001",
            "--username",
            "alice",
            "--target",
            "tcp://db.example.test:5432",
            "--resolve",
            "tunnel",
            "--dns-server",
            "192.0.2.53",
            "--dns-timeout",
            "750ms",
            "--connect-timeout",
            "12s",
            "--listen",
            "127.0.0.1:9080",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Forward(ForwardArgs {
                forward: ForwardOptions {
                    listen,
                    target,
                    resolve: ResolveViaArg::Tunnel,
                    dns_servers,
                    dns_timeout,
                    connect_timeout,
                    ..
                },
                ..
            }) if listen == "127.0.0.1:9080".parse().unwrap()
                && target == "tcp://db.example.test:5432"
                && dns_servers == vec!["192.0.2.53:53".parse::<SocketAddr>().unwrap()]
                && dns_timeout == Duration::from_millis(750)
                && connect_timeout == Duration::from_secs(12)
        ));
        assert!(
            Cli::try_parse_from([
                "openiwan",
                "forward",
                "--server",
                "192.0.2.10:6001",
                "--username",
                "alice",
                "--target",
                "db.example.test:5432",
            ])
            .is_err()
        );
    }
}
