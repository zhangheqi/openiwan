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
use openiwan::tun::{RouteGuard, TunDevice};
use openiwan::{Client, ClientConfig, EncryptionMethod, Error, PacketDevice, Result};
use std::fs;
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
#[command(name = "openiwan", version, about = "Connect to iWAN networks")]
struct Cli {
    /// Increase logging output. Repeat for more detail.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Probe an iWAN server.
    Ping(PingArgs),
    /// Authenticate without opening a tunnel.
    Auth(ConnectionArgs),
    /// Open an iWAN tunnel.
    Connect(ConnectArgs),
    /// Forward TCP or HTTP(S) through iWAN.
    #[cfg(feature = "forward")]
    Forward(ForwardArgs),
    /// Decode an iWAN packet.
    Decode(DecodeArgs),
    /// Use controller-managed iWAN services.
    #[cfg(feature = "managed")]
    Managed(ManagedArgs),
    /// Manage connection profiles.
    #[cfg(feature = "managed")]
    Profile(ProfileArgs),
}

#[derive(Debug, Args)]
struct PingArgs {
    /// iWAN server in HOST:PORT form.
    server: String,
    /// Wait at most DURATION for a reply.
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
    /// Load connection settings from a TOML file.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Connect to the iWAN server at HOST:PORT.
    #[arg(long, value_name = "HOST:PORT")]
    server: Option<String>,
    /// Authenticate as USER.
    #[arg(long, value_name = "USER")]
    username: String,
    /// Read the password from ENV before prompting.
    #[arg(long, value_name = "ENV", default_value = "OPENIWAN_PASSWORD")]
    password_env: String,
    /// Read the password from the first line of FILE.
    #[arg(long, value_name = "FILE")]
    password_file: Option<PathBuf>,
    /// Set the packet MTU.
    #[arg(long, value_name = "BYTES")]
    mtu: Option<u16>,
    /// Set the session cipher.
    #[arg(long, value_name = "CIPHER")]
    encryption: Option<EncryptionMethod>,
}

#[derive(Debug, Args)]
struct ConnectArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Name the TUN interface.
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
    /// Forward to a tcp://, http://, or https:// URI.
    #[arg(long, value_name = "URI", value_parser = forward::parse_target_argument)]
    target: String,
    /// Resolve the target using auto, tunnel, or system DNS.
    #[arg(long, value_name = "MODE", value_enum, default_value = "auto")]
    resolve: ResolveViaArg,
    /// Query a DNS server through iWAN. Repeat to add servers.
    #[arg(
        long = "dns-server",
        value_name = "HOST[:PORT]",
        value_parser = parse_resolver
    )]
    dns_servers: Vec<SocketAddr>,
    /// Wait at most DURATION for each DNS server.
    #[arg(
        long,
        value_name = "DURATION",
        default_value = "3s",
        value_parser = parse_duration
    )]
    dns_timeout: Duration,
    /// Listen on a loopback address.
    #[arg(long, value_name = "HOST:PORT", default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    /// Trust an additional PEM CA certificate. Repeat to add files.
    #[arg(long = "ca-cert", value_name = "FILE")]
    ca_certificates: Vec<PathBuf>,
    /// Complete DNS, TCP, and TLS setup within DURATION.
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
    /// Select the DNS server source.
    #[arg(long, value_name = "MODE", value_enum)]
    dns_mode: Option<DnsServerModeArg>,
    /// Use a custom IPv4 DNS server. Repeat to add a server.
    #[arg(long = "dns-server", value_name = "IP")]
    dns_servers: Vec<Ipv4Addr>,
    /// Set split DNS behavior.
    #[arg(long, value_name = "MODE", value_enum)]
    split_dns_mode: Option<SplitDnsModeArg>,
    /// Add an iWAN domain rule. Repeat to add rules.
    #[arg(long = "split-dns-domain", value_name = "RULE")]
    split_dns_domains: Vec<DomainRule>,
    /// Set encrypted DNS handling.
    #[arg(long, value_name = "MODE", value_enum)]
    encrypted_dns: Option<EncryptedDnsModeArg>,
    /// Block an exact `DoH` hostname. Repeat to add hosts.
    #[arg(long = "doh-host", value_name = "HOST")]
    doh_hosts: Vec<String>,
}

impl DnsOverrideArgs {
    fn as_overrides(&self) -> DnsOverrides {
        DnsOverrides {
            server_mode: self
                .dns_mode
                .and_then(DnsServerModeArg::into_policy)
                .or_else(|| (!self.dns_servers.is_empty()).then_some(DnsServerMode::Custom)),
            servers: (!self.dns_servers.is_empty()).then(|| self.dns_servers.clone()),
            split_mode: self
                .split_dns_mode
                .and_then(SplitDnsModeArg::into_policy)
                .or_else(|| (!self.split_dns_domains.is_empty()).then_some(SplitDnsMode::Custom)),
            split_domains: (!self.split_dns_domains.is_empty())
                .then(|| self.split_dns_domains.clone()),
            encrypted_dns: self.encrypted_dns.map(EncryptedDnsModeArg::into_policy),
            doh_hosts: (!self.doh_hosts.is_empty()).then(|| self.doh_hosts.clone()),
        }
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

#[derive(Debug, Clone, Default, Args)]
struct RouteArgs {
    /// Route a CIDR through iWAN. Repeat to add routes.
    #[arg(long = "route", value_name = "CIDR", value_delimiter = ',')]
    routes: Vec<String>,
    /// Route an IP address through iWAN. Repeat to add addresses.
    #[arg(long = "route-ip", value_name = "IP", value_delimiter = ',')]
    route_ips: Vec<String>,
    /// Resolve a domain and route its addresses through iWAN.
    #[arg(long = "route-domain", value_name = "DOMAIN", value_delimiter = ',')]
    route_domains: Vec<String>,
}

#[derive(Debug, Args)]
struct DecodeArgs {
    /// Packet bytes in hexadecimal. Whitespace, ':' and '-' are ignored.
    hex: String,
}

#[cfg(feature = "managed")]
#[derive(Debug, Args)]
struct ManagedArgs {
    /// Override the state directory (env: `OPENIWAN_STATE_DIR`).
    #[arg(long, global = true, value_name = "DIR")]
    state_dir: Option<PathBuf>,
    /// Use a connection profile.
    #[arg(long, value_name = "NAME")]
    profile: Option<String>,
    /// Use a customer domain without a profile.
    #[arg(long, value_name = "DOMAIN")]
    domain: Option<String>,
    /// Override the installation Device ID.
    #[arg(long, value_name = "ID")]
    device_id: Option<String>,
    /// Store domain lookup data in DIR.
    #[arg(long, value_name = "DIR")]
    cache_dir: Option<PathBuf>,
    /// Wait at most DURATION for each line probe.
    #[arg(
        long,
        value_name = "DURATION",
        default_value = "2s",
        value_parser = parse_duration
    )]
    probe_timeout: Duration,
    #[command(subcommand)]
    action: ManagedCommand,
}

#[cfg(feature = "managed")]
#[derive(Debug, Subcommand)]
enum ManagedCommand {
    /// Show domain and authentication details.
    Discover,
    /// Authenticate and test the selected line.
    Login(ManagedLoginArgs),
    /// Open a managed iWAN tunnel.
    Connect(ManagedConnectArgs),
    /// Forward TCP or HTTP(S) through a managed connection.
    #[cfg(feature = "forward")]
    Forward(ManagedForwardArgs),
    /// List available lines and their latency.
    Lines(ManagedLinesArgs),
}

#[cfg(feature = "managed")]
#[derive(Debug, Clone, Args)]
struct ManagedLoginArgs {
    /// Authenticate as USER. Ignored for OIDC domains.
    #[arg(long, value_name = "USER")]
    username: Option<String>,
    /// Read the password from ENV before prompting.
    #[arg(long, value_name = "ENV", default_value = "OPENIWAN_PASSWORD")]
    password_env: String,
    /// Read the password from the first line of FILE.
    #[arg(long, value_name = "FILE")]
    password_file: Option<PathBuf>,
    /// Use URI for the OIDC callback.
    #[arg(
        long,
        value_name = "URI",
        default_value = "com.panabit.mobile://oauth2redirect"
    )]
    redirect_uri: String,
    /// Read posture check results from a JSON file.
    #[arg(long, value_name = "FILE")]
    posture_results: Option<PathBuf>,
    /// Send a cached posture policy version.
    #[arg(long, value_name = "VERSION")]
    posture_version: Option<i64>,
    /// Save verified authentication. Requires a profile.
    #[arg(long)]
    save: bool,
    /// Ignore saved authentication and log in again.
    #[arg(long)]
    reauth: bool,
    /// Fail instead of prompting or opening an OIDC login.
    #[arg(long)]
    non_interactive: bool,
    /// Use auto, iwan:ID, or sr:ID for this command only.
    #[arg(long, value_name = "LINE")]
    line: Option<LinePreference>,
}

#[cfg(feature = "managed")]
#[derive(Debug, Args)]
struct ManagedConnectArgs {
    #[command(flatten)]
    login: ManagedLoginArgs,
    /// Name the TUN interface.
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
    login: ManagedLoginArgs,
    #[command(flatten)]
    forward: ForwardOptions,
}

#[cfg(feature = "managed")]
#[derive(Debug, Args)]
struct ManagedLinesArgs {
    #[command(flatten)]
    login: ManagedLoginArgs,
    /// Set the selected profile's line preference. Requires a profile.
    #[arg(long, value_name = "LINE")]
    set: Option<LinePreference>,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[cfg(feature = "managed")]
#[derive(Debug, Args)]
struct ProfileArgs {
    /// Override the state directory (env: `OPENIWAN_STATE_DIR`).
    #[arg(long, global = true, value_name = "DIR")]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: ProfileCommand,
}

#[cfg(feature = "managed")]
#[derive(Debug, Subcommand)]
enum ProfileCommand {
    /// List profiles.
    List {
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show a profile.
    Show {
        /// Profile name. Defaults to the default profile.
        name: Option<String>,
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Create or update a profile.
    Set(Box<ProfileSetArgs>),
    /// Select the default profile.
    Use {
        /// Profile name.
        name: String,
    },
    /// Remove a profile.
    Remove {
        /// Profile name.
        name: String,
    },
    /// Delete saved authentication for a profile.
    Logout {
        /// Profile name. Defaults to the default profile.
        name: Option<String>,
    },
}

#[cfg(feature = "managed")]
#[derive(Debug, Args)]
struct ProfileSetArgs {
    /// Profile name.
    name: String,
    /// Set the customer domain.
    #[arg(long, value_name = "DOMAIN")]
    domain: Option<String>,
    /// Override the installation Device ID.
    #[arg(long, value_name = "ID")]
    device_id: Option<String>,
    /// Set the saved username.
    #[arg(long, value_name = "USER", conflicts_with = "unset_username")]
    username: Option<String>,
    /// Remove the saved username.
    #[arg(long)]
    unset_username: bool,
    /// Set the preferred line.
    #[arg(long, value_name = "LINE")]
    line: Option<LinePreference>,
    #[command(flatten)]
    dns: DnsOverrideArgs,
    /// Remove all saved DNS settings.
    #[arg(long)]
    reset_dns: bool,
    /// Remove a saved DNS list. Repeat to remove more lists.
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
        eprintln!("error: {error}");
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
            let store = state::StateStore::new(arguments.state_dir.clone())?;
            managed(arguments, &store)?;
        }
        #[cfg(feature = "managed")]
        Command::Profile(arguments) => {
            let store = state::StateStore::new(arguments.state_dir.clone())?;
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
    let overrides = dns_arguments.as_overrides();
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
    let physical_exclusions = if policy.server_mode == DnsServerMode::Disabled
        || matches!(
            policy.split_mode,
            SplitDnsMode::Managed | SplitDnsMode::Custom
        ) {
        physical
            .iter()
            .map(|resolver| {
                let address = resolver.address.ip();
                format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 })
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let routes = resolve_route_policy(
        &route_arguments.routes,
        &route_ips,
        &route_arguments.route_domains,
        &physical_exclusions,
        session.info().peer.ip(),
        false,
    )?;
    let mut interface_session = session.info().clone();
    interface_session.dns_servers = policy.servers.iter().copied().map(IpAddr::V4).collect();
    let device = Arc::new(TunDevice::open(tun, &interface_session)?);
    let _routes = RouteGuard::configure(&device, &routes)?;
    let runtime = Arc::new(DnsRuntime::new(
        device.dns_platform_target(),
        defaults,
        overrides,
        physical,
        RelayConfig::default(),
    )?);
    let dns_device = Arc::new(DnsPacketDevice::new(Arc::clone(&device), runtime));
    for route in &routes {
        println!("route {route} -> {}", device.name());
    }
    print_dns_policy(&policy);
    println!("TUN {} is active; press Ctrl-C to stop", device.name());

    let shutdown = install_shutdown_handler()?;
    let end = client.run_reconnecting_from(session, dns_device, shutdown)?;
    println!("session ended: {end:?}");
    Ok(())
}

fn install_shutdown_handler() -> Result<Arc<AtomicBool>> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&shutdown);
    ctrlc::set_handler(move || signal.store(true, Ordering::Release)).map_err(|error| {
        Error::InvalidConfig(format!("failed to install signal handler: {error}"))
    })?;
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
    println!("session ended: {end:?}");
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
        "DNS policy: mode={:?}, servers={servers}, split={:?}, encrypted={}",
        policy.server_mode, policy.split_mode, policy.block_encrypted_dns
    );
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
}

#[cfg(feature = "managed")]
fn managed(arguments: ManagedArgs, store: &state::StateStore) -> Result<()> {
    let mut context = resolve_managed_context(&arguments, store)?;
    let cache_directory = arguments
        .cache_dir
        .clone()
        .or_else(|| Some(store.cache_directory()));
    let client = DomainClient::new(cache_directory);
    let discovered = client.discover(&context.domain, &context.device_id)?;
    match arguments.action {
        ManagedCommand::Discover => print_discovery(&discovered, &context.device_id),
        ManagedCommand::Login(login) => {
            let line = context.line.clone();
            let prepared = prepare_managed(
                &client,
                &discovered,
                store,
                &mut context,
                &login,
                &line,
                arguments.probe_timeout,
            )?;
            print_prepared(&prepared);
        }
        ManagedCommand::Connect(connect) => {
            let line = context.line.clone();
            let prepared = prepare_managed(
                &client,
                &discovered,
                store,
                &mut context,
                &connect.login,
                &line,
                arguments.probe_timeout,
            )?;
            print_prepared(&prepared);
            run_managed_client(
                prepared,
                connect.tun.as_deref(),
                &connect.routes,
                &context.dns,
                &connect.dns,
            )?;
        }
        #[cfg(feature = "forward")]
        ManagedCommand::Forward(forward) => {
            let line = context.line.clone();
            let prepared = prepare_managed(
                &client,
                &discovered,
                store,
                &mut context,
                &forward.login,
                &line,
                arguments.probe_timeout,
            )?;
            print_prepared(&prepared);
            run_managed_forward(&prepared, &forward.forward, &context.dns)?;
        }
        ManagedCommand::Lines(lines) => {
            // A stale saved preference must not prevent the recovery command
            // from listing current controller lines.
            let prepared = prepare_managed(
                &client,
                &discovered,
                store,
                &mut context,
                &lines.login,
                &LinePreference::Auto,
                arguments.probe_timeout,
            )?;
            let probes = prepared.probe_lines(arguments.probe_timeout)?;
            print_line_probes(&probes, lines.json)?;
            if let Some(preference) = lines.set {
                let profile_name = context.profile_name.as_deref().ok_or_else(|| {
                    Error::InvalidConfig("--set requires --profile or a default profile".into())
                })?;
                save_profile_line(store, profile_name, &preference, &probes)?;
                println!("profile {profile_name}: line set to {preference}");
            }
        }
    }
    Ok(())
}

#[cfg(feature = "managed")]
fn resolve_managed_context(
    arguments: &ManagedArgs,
    store: &state::StateStore,
) -> Result<ManagedContext> {
    let persisted = store.load()?;
    let explicit_domain = arguments.domain.is_some();
    let profile_name = if let Some(name) = &arguments.profile {
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
                .ok_or_else(|| Error::InvalidConfig(format!("profile {name:?} does not exist")))
        })
        .transpose()?;

    let domain = arguments
        .domain
        .clone()
        .or_else(|| profile.as_ref().map(|profile| profile.domain.clone()))
        .ok_or_else(|| {
            Error::InvalidConfig("--domain is required when no default profile exists".into())
        })?;
    let device_id = arguments
        .device_id
        .clone()
        .or_else(|| profile.as_ref().map(|profile| profile.device_id.clone()))
        .map_or_else(|| store.device_id(), Ok)?;
    openiwan::managed::validate_domain(&domain)?;
    if device_id.trim().is_empty() {
        return Err(Error::InvalidConfig("device ID must not be empty".into()));
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
                    Error::InvalidConfig("profile name is required when no default exists".into())
                })?;
            let profile = persisted
                .profiles
                .get(&name)
                .ok_or_else(|| Error::InvalidConfig(format!("profile {name:?} does not exist")))?;
            print_profile(&name, profile, persisted.default_profile.as_deref(), json)?;
        }
        ProfileCommand::Set(arguments) => set_profile(*arguments, store)?,
        ProfileCommand::Use { name } => {
            state::validate_profile_name(&name)?;
            store.update(|persisted| {
                if !persisted.profiles.contains_key(&name) {
                    return Err(Error::InvalidConfig(format!(
                        "profile {name:?} does not exist"
                    )));
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
                Error::InvalidConfig("--domain is required for a new profile".into())
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
fn remove_profile(store: &state::StateStore, name: &str) -> Result<()> {
    state::validate_profile_name(name)?;
    let persisted = store.load()?;
    let profile = persisted
        .profiles
        .get(name)
        .ok_or_else(|| Error::InvalidConfig(format!("profile {name:?} does not exist")))?;
    if !profile.credential_id.is_empty() {
        credentials::CredentialStore::delete(&profile.credential_id)?;
    }
    store.update(|persisted| {
        if persisted.profiles.remove(name).is_none() {
            return Err(Error::InvalidConfig(format!(
                "profile {name:?} does not exist"
            )));
        }
        if persisted.default_profile.as_deref() == Some(name) {
            persisted.default_profile = None;
        }
        Ok(())
    })?;
    println!("removed profile {name}");
    Ok(())
}

#[cfg(feature = "managed")]
fn logout_profile(store: &state::StateStore, name: Option<String>) -> Result<()> {
    let persisted = store.load()?;
    let name = name
        .or_else(|| persisted.default_profile.clone())
        .ok_or_else(|| {
            Error::InvalidConfig("profile name is required when no default exists".into())
        })?;
    state::validate_profile_name(&name)?;
    let profile = persisted
        .profiles
        .get(&name)
        .ok_or_else(|| Error::InvalidConfig(format!("profile {name:?} does not exist")))?;
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
                .ok_or_else(|| Error::InvalidConfig(format!("profile {name:?} does not exist")))?;
            profile.credential_id.clear();
            Ok(())
        })?;
    }
    if removed {
        println!("removed saved authentication for profile {name}");
    } else {
        println!("profile {name} has no saved authentication");
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
        println!("no profiles configured");
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
            profile.username.as_deref().unwrap_or("<prompt>"),
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
    println!("  default: {}", default_profile == Some(name));
    println!("  domain: {}", profile.domain);
    println!("  device ID: {}", profile.device_id);
    println!(
        "  username: {}",
        profile.username.as_deref().unwrap_or("<prompt>")
    );
    println!("  line: {}", profile.line);
    println!(
        "  DNS overrides: {}",
        if profile.dns == DnsOverrides::default() {
            "inherit".into()
        } else {
            serde_json::to_string(&profile.dns).map_err(|error| {
                Error::InvalidConfig(format!("serialize profile DNS output: {error}"))
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
    serde_json::json!({
        "name": name,
        "default": default_profile == Some(name),
        "domain": profile.domain,
        "device_id": profile.device_id,
        "username": profile.username,
        "line": profile.line.to_string(),
        "dns": profile.dns,
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
fn save_profile_line(
    store: &state::StateStore,
    profile_name: &str,
    preference: &LinePreference,
    probes: &[LineProbe],
) -> Result<()> {
    if !matches!(preference, LinePreference::Auto)
        && !probes.iter().any(|probe| &probe.preference == preference)
    {
        return Err(Error::LineNotFound(preference.to_string()));
    }
    if let Some(probe) = probes.iter().find(|probe| &probe.preference == preference)
        && !probe.reachable()
    {
        tracing::warn!(line = %preference, "saving a currently unreachable managed line");
    }
    store.update(|persisted| {
        let profile = persisted.profiles.get_mut(profile_name).ok_or_else(|| {
            Error::InvalidConfig(format!("profile {profile_name:?} does not exist"))
        })?;
        profile.line = preference.clone();
        Ok(())
    })
}

#[cfg(feature = "managed")]
fn run_managed_client(
    prepared: PreparedConnection,
    tun: Option<&str>,
    route_arguments: &RouteArgs,
    profile_dns: &DnsOverrides,
    dns_arguments: &DnsOverrideArgs,
) -> Result<()> {
    let client = prepared.client()?;
    let session = client.authenticate()?;
    print_session(session.info());
    let defaults = prepared
        .configuration
        .dns_defaults(prepared.service_type() == ServiceType::Controller)?;
    let cli_dns = dns_arguments.as_overrides();
    let overrides = DnsOverrides::layered(profile_dns, &cli_dns);
    let policy = DnsPolicyResolver::resolve(&defaults, &overrides, &session.info().dns_servers)?;
    let physical = discover_physical_resolvers()?;

    let routing = prepared.configuration.routing()?;
    let mode = routing
        .as_ref()
        .map_or(RoutingMode::All, |routing| routing.mode);
    let ip_filter = if mode == RoutingMode::All {
        None
    } else {
        prepared.configuration.ip_filter()?
    };
    let has_ip_filter = ip_filter
        .as_ref()
        .is_some_and(|filter| !filter.inclusive.is_empty() || !filter.exclusive.is_empty());
    let full_ipv4 = mode == RoutingMode::All || (mode == RoutingMode::IpFilter && !has_ip_filter);

    let mut cidrs = route_arguments.routes.clone();
    if let Some(filter) = &ip_filter
        && has_ip_filter
    {
        cidrs.extend(valid_filter_cidrs(&filter.inclusive));
    }
    if mode == RoutingMode::Custom
        && let Some(routing) = &routing
    {
        cidrs.extend(routing.custom_routes.iter().cloned());
    }

    if mode != RoutingMode::All {
        cidrs.extend(policy.servers.iter().map(|server| format!("{server}/32")));
    }
    let mut exclusions = ip_filter
        .as_ref()
        .filter(|_| has_ip_filter)
        .map_or_else(Vec::new, |filter| valid_filter_cidrs(&filter.exclusive));
    exclusions.extend(managed_server_exclusions(&prepared.configuration)?);
    if policy.server_mode == DnsServerMode::Disabled
        || matches!(
            policy.split_mode,
            SplitDnsMode::Managed | SplitDnsMode::Custom
        )
    {
        exclusions.extend(physical.iter().map(|resolver| {
            let address = resolver.address.ip();
            format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 })
        }));
    }
    let routes = resolve_route_policy(
        &cidrs,
        &route_arguments.route_ips,
        &route_arguments.route_domains,
        &exclusions,
        session.info().peer.ip(),
        full_ipv4,
    )?;

    let mut interface_session = session.info().clone();
    if let Some(routing) = &routing
        && routing.mtu_mode == "custom"
        && let Ok(mtu) = u16::try_from(routing.custom_mtu)
        && (576..=9_000).contains(&mtu)
    {
        interface_session.mtu = mtu;
    }
    interface_session.dns_servers = policy.servers.iter().copied().map(IpAddr::V4).collect();
    let device = Arc::new(TunDevice::open(tun, &interface_session)?);
    let _routes = RouteGuard::configure(&device, &routes)?;
    let runtime = Arc::new(DnsRuntime::new(
        device.dns_platform_target(),
        defaults,
        overrides,
        physical,
        RelayConfig::default(),
    )?);
    let dns_device = Arc::new(DnsPacketDevice::new(Arc::clone(&device), runtime));
    for route in &routes {
        println!("route {route} -> {}", device.name());
    }
    print_dns_policy(&policy);
    println!("TUN {} is active; press Ctrl-C to stop", device.name());

    let shutdown = install_shutdown_handler()?;
    let end = client.run_reconnecting_from(session, dns_device, shutdown)?;
    println!("session ended: {end:?}");
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
    println!("session ended: {end:?}");
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
    let mut exclusions = vec![
        "169.254.0.0/16".into(),
        "224.0.0.0/4".into(),
        "127.0.0.0/8".into(),
    ];
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
    arguments: &ManagedLoginArgs,
    profile_line: &LinePreference,
    ping_timeout: Duration,
) -> Result<PreparedConnection> {
    ensure_credential_id(store, context, arguments.save)?;
    let line = arguments.line.as_ref().unwrap_or(profile_line);
    match discovered.auth.method {
        AuthMethod::Credential => {
            prepare_managed_password(client, discovered, context, arguments, line, ping_timeout)
        }
        AuthMethod::Oidc => {
            prepare_managed_oidc(client, discovered, context, arguments, line, ping_timeout)
        }
    }
}

#[cfg(feature = "managed")]
fn prepare_managed_password(
    client: &DomainClient,
    discovered: &DiscoveredDomain,
    context: &ManagedContext,
    arguments: &ManagedLoginArgs,
    line: &LinePreference,
    ping_timeout: Duration,
) -> Result<PreparedConnection> {
    let explicit_password = read_explicit_managed_secret(arguments)?;
    let stored = if explicit_password.is_none() && !arguments.reauth {
        load_stored_credential(context.credential_id.as_deref())?
    } else {
        None
    };
    if matches!(
        stored.as_ref(),
        Some(credentials::StoredCredential::Oidc { .. })
    ) {
        return Err(Error::CredentialStore(
            "saved authentication does not match this credential domain; use \
             --reauth --save"
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
            Error::InvalidConfig("--username is required for this credential domain".into())
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
            "no saved password matches this profile; authenticate once with \
             --reauth --save"
                .into(),
        ));
    } else {
        zeroize::Zeroizing::new(prompt_password("iWAN password: ")?)
    };
    let prepared = client.password_login_with_line(
        discovered,
        &context.device_id,
        &username,
        password.as_str(),
        ping_timeout,
        line,
    )?;
    if arguments.save {
        credentials::CredentialStore::save(
            context.credential_id.as_deref().expect("ensured above"),
            credentials::StoredCredential::Password {
                username,
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
    context: &ManagedContext,
    arguments: &ManagedLoginArgs,
    line: &LinePreference,
    ping_timeout: Duration,
) -> Result<PreparedConnection> {
    let stored = if arguments.reauth {
        None
    } else {
        load_stored_credential(context.credential_id.as_deref())?
    };
    if matches!(
        stored.as_ref(),
        Some(credentials::StoredCredential::Password { .. })
    ) {
        return Err(Error::CredentialStore(
            "saved authentication does not match this OIDC domain; use \
             --reauth --save"
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
            arguments,
            refresh_token,
            user_id,
            username,
        )?,
        _ if arguments.non_interactive => {
            return Err(Error::CredentialStore(
                "no saved OIDC session is available; authenticate once with --save".into(),
            ));
        }
        _ => interactive_oidc(client, discovered, &arguments.redirect_uri)?,
    };
    let posture_results = read_posture_results(arguments.posture_results.as_deref())?;
    let prepared = client.oidc_login_with_options(
        discovered,
        &context.device_id,
        &identity,
        OidcLoginOptions {
            posture_check_results: &posture_results,
            posture_version: arguments.posture_version,
            ping_timeout,
            line,
        },
    )?;
    if arguments.save && !used_saved_identity {
        save_oidc_identity(
            context.credential_id.as_deref().expect("ensured above"),
            &identity,
        )?;
    }
    Ok(prepared)
}

#[cfg(feature = "managed")]
fn refresh_saved_oidc(
    client: &DomainClient,
    discovered: &DiscoveredDomain,
    context: &ManagedContext,
    arguments: &ManagedLoginArgs,
    refresh_token: &str,
    user_id: &str,
    username: &str,
) -> Result<openiwan::managed::OidcIdentity> {
    let identity = client.refresh_oidc(
        discovered,
        &arguments.redirect_uri,
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
        "Open this URL in a browser and complete authentication:\n\n{}\n",
        pending.authorization_url()
    );
    let redirect = prompt_line("Paste the complete callback URL: ")?;
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
fn ensure_credential_id(
    store: &state::StateStore,
    context: &mut ManagedContext,
    required: bool,
) -> Result<()> {
    if !required || context.credential_id.is_some() {
        return Ok(());
    }
    let profile_name = context.profile_name.as_deref().ok_or_else(|| {
        Error::InvalidConfig("--save requires --profile or a default profile".into())
    })?;
    let identifier = store.update(|persisted| {
        let profile = persisted.profiles.get_mut(profile_name).ok_or_else(|| {
            Error::InvalidConfig(format!("profile {profile_name:?} does not exist"))
        })?;
        Ok(profile.ensure_credential_id()?.to_owned())
    })?;
    context.credential_id = Some(identifier);
    Ok(())
}

#[cfg(feature = "managed")]
fn load_stored_credential(
    credential_id: Option<&str>,
) -> Result<Option<credentials::StoredCredential>> {
    credential_id.map_or(Ok(None), credentials::CredentialStore::load)
}

#[cfg(feature = "managed")]
fn print_discovery(discovered: &DiscoveredDomain, device_id: &str) {
    println!("domain: {}", discovered.active_domain());
    println!("device ID: {device_id}");
    println!("lookup type: {}", discovered.lookup.service_type.as_str());
    println!(
        "lookup source: {}",
        match discovered.lookup.source {
            openiwan::managed::LookupSource::Network => "network",
            openiwan::managed::LookupSource::Cache => "cache",
        }
    );
    println!(
        "authentication: {}",
        match discovered.auth.method {
            AuthMethod::Credential => "credential",
            AuthMethod::Oidc => "oidc",
        }
    );
}

#[cfg(feature = "managed")]
fn print_prepared(prepared: &PreparedConnection) {
    println!("login ready for domain {}", prepared.domain);
    println!("selected line: {}", prepared.ingress.line_preference());
    match &prepared.ingress {
        SelectedIngress::Iwan { server, latency } => println!(
            "best server: {} ({}, {:.3} ms)",
            server.name,
            server.endpoint(),
            latency.as_secs_f64() * 1_000.0
        ),
        SelectedIngress::SegmentRouting {
            group_id,
            entry,
            latency,
        } => println!(
            "best SR group: {group_id}, ingress {}:{} ({:.3} ms)",
            entry.ingress.server_name,
            entry.ingress.server_port,
            latency.as_secs_f64() * 1_000.0
        ),
    }
}

#[cfg(feature = "managed")]
fn read_explicit_managed_secret(arguments: &ManagedLoginArgs) -> Result<Option<String>> {
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
    if let Ok(password) = std::env::var(&arguments.password_env)
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
    value.as_array().cloned().ok_or_else(|| {
        Error::InvalidConfig(format!("{} must contain a JSON array", path.display()))
    })
}

#[cfg(feature = "managed")]
fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut value = String::new();
    std::io::stdin().read_line(&mut value)?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(Error::InvalidConfig("input must not be empty".into()));
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
                .ok_or_else(|| Error::InvalidConfig("--server or --config is required".into()))?,
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
            "{} must not be accessible by group or other users",
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
    println!("authenticated");
    println!("  peer: {}", session.peer);
    println!("  session: {:#06x}", session.session_id);
    println!("  token: {:#010x}", session.token);
    println!("  encryption: {}", session.encryption);
    println!("  MTU: {}", session.mtu);
    println!("  segment routing: {}", session.segment_routing);
    println!(
        "  address: {}",
        session
            .address
            .map_or_else(|| "<none>".into(), |value| value.to_string())
    );
    println!(
        "  gateway: {}",
        session
            .gateway
            .map_or_else(|| "<none>".into(), |value| value.to_string())
    );
    if !session.dns_servers.is_empty() {
        println!(
            "  DNS: {}",
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
        assert_eq!(parse_duration("3m").unwrap(), Duration::from_secs(180));
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
        let overrides = arguments.dns.as_overrides();
        assert_eq!(overrides.server_mode, Some(DnsServerMode::Custom));
        assert_eq!(overrides.servers, Some(vec![Ipv4Addr::new(192, 0, 2, 53)]));
        assert_eq!(overrides.split_mode, Some(SplitDnsMode::Custom));
        assert_eq!(
            overrides.split_domains,
            Some(vec!["@corp.example".parse().unwrap()])
        );
        assert_eq!(overrides.encrypted_dns, Some(EncryptedDnsMode::Block));
    }

    #[cfg(feature = "managed")]
    #[test]
    fn parses_managed_login_command() {
        let parsed = Cli::try_parse_from([
            "openiwan",
            "managed",
            "--domain",
            "iwan.ustc",
            "--device-id",
            "device-1",
            "--probe-timeout",
            "750ms",
            "login",
            "--username",
            "alice",
            "--posture-version",
            "2",
            "--save",
            "--reauth",
            "--non-interactive",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Managed(ManagedArgs {
                domain,
                device_id,
                probe_timeout,
                action: ManagedCommand::Login(ManagedLoginArgs {
                    posture_version: Some(version),
                    username: Some(username),
                    save: true,
                    reauth: true,
                    non_interactive: true,
                    ..
                }),
                ..
            }) if domain.as_deref() == Some("iwan.ustc")
                && device_id.as_deref() == Some("device-1")
                && probe_timeout == Duration::from_millis(750)
                && username == "alice"
                && version == 2
        ));
    }

    #[cfg(all(feature = "managed", feature = "forward"))]
    #[test]
    fn parses_managed_forward_command() {
        let parsed = Cli::try_parse_from([
            "openiwan",
            "managed",
            "--domain",
            "iwan.ustc",
            "forward",
            "--username",
            "alice",
            "--target",
            "tcp://db.internal.example:5432",
            "--listen",
            "127.0.0.1:9543",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Managed(ManagedArgs {
                domain,
                device_id: None,
                action: ManagedCommand::Forward(ManagedForwardArgs {
                    login: ManagedLoginArgs {
                        username: Some(username),
                        ..
                    },
                    forward: ForwardOptions { target, listen, .. },
                }),
                ..
            }) if domain.as_deref() == Some("iwan.ustc")
                && username == "alice"
                && target == "tcp://db.internal.example:5432"
                && listen == "127.0.0.1:9543".parse().unwrap()
        ));
    }

    #[cfg(feature = "managed")]
    #[test]
    fn managed_context_generates_and_reuses_device_id() {
        let store = test_state_store("context-device-id");
        let arguments = ManagedArgs {
            state_dir: None,
            profile: None,
            domain: Some("iwan.example".into()),
            device_id: None,
            cache_dir: None,
            probe_timeout: Duration::from_secs(2),
            action: ManagedCommand::Discover,
        };

        let first = resolve_managed_context(&arguments, &store).unwrap();
        let second = resolve_managed_context(&arguments, &store).unwrap();
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
            "--profile",
            "work",
            "lines",
            "--set",
            "sr:3",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Managed(ManagedArgs {
                profile: Some(name),
                action: ManagedCommand::Lines(ManagedLinesArgs {
                    set: Some(LinePreference::SegmentRouting { group_id: 3 }),
                    json: true,
                    ..
                }),
                ..
            }) if name == "work"
        ));

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
