#[cfg(feature = "forward")]
#[path = "openiwan/forward.rs"]
mod forward;

use clap::{Args, Parser, Subcommand};
use openiwan::client;
#[cfg(feature = "managed")]
use openiwan::managed::{
    AuthMethod, DiscoveredDomain, DomainClient, PreparedConnection, RoutingMode, SelectedIngress,
};
use openiwan::protocol::{self, Tlv};
#[cfg(feature = "managed")]
use openiwan::tun::resolve_route_policy;
use openiwan::tun::{DnsGuard, RouteGuard, TunDevice, resolve_route_targets};
use openiwan::{Client, ClientConfig, EncryptionMethod, Error, PacketDevice, Result};
use std::fs;
#[cfg(feature = "managed")]
use std::io::Write;
#[cfg(feature = "managed")]
use std::net::ToSocketAddrs;
#[cfg(feature = "forward")]
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroize;

#[derive(Debug, Parser)]
#[command(name = "openiwan", version, about)]
struct Cli {
    /// Increase logging verbosity (-v, -vv).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Test whether an iWAN UDP endpoint answers the stateless ping packet.
    Ping(PingArgs),
    /// Perform the OPEN/OPENACK authentication handshake without creating TUN.
    Auth(ConnectionArgs),
    /// Authenticate, create a TUN interface, and exchange IP packets.
    Connect(ConnectArgs),
    /// Forward TCP or proxy HTTP(S) to one fixed target without host routes.
    #[cfg(feature = "forward")]
    Forward(ForwardArgs),
    /// Decode one hexadecimal iWAN datagram without network access.
    Decode(DecodeArgs),
    /// Discover a customer domain, authenticate, select an ingress, and connect.
    #[cfg(feature = "managed")]
    Managed(ManagedArgs),
}

#[derive(Debug, Args)]
struct PingArgs {
    /// iWAN UDP endpoint, including port.
    #[arg(long)]
    server: String,
    #[arg(long, default_value_t = 3_000)]
    timeout_ms: u64,
}

#[derive(Debug, Clone, Args)]
struct ConnectionArgs {
    /// Optional TOML file containing a serialized `ClientConfig`.
    #[arg(long)]
    config: Option<PathBuf>,
    /// iWAN UDP endpoint, including port. Overrides the config file.
    #[arg(long)]
    server: Option<String>,
    #[arg(long)]
    username: String,
    /// Read the password from this environment variable before prompting.
    #[arg(long, default_value = "OPENIWAN_PASSWORD")]
    password_env: String,
    /// Read the first line from a password file. The file must not be
    /// group/world accessible on Unix.
    #[arg(long)]
    password_file: Option<PathBuf>,
    #[arg(long)]
    mtu: Option<u16>,
    #[arg(long)]
    encryption: Option<EncryptionMethod>,
}

#[derive(Debug, Args)]
struct ConnectArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// TUN interface name. Defaults to openiwan0 on Linux/Windows and an
    /// automatically allocated utunN on macOS.
    #[arg(long)]
    tun: Option<String>,
    #[command(flatten)]
    routes: RouteArgs,
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
    /// Fixed target URI using tcp://, http://, or https://.
    #[arg(long, value_parser = forward::parse_target_argument)]
    target: String,
    /// DNS policy: auto uses iWAN DNS when available, otherwise host DNS;
    /// iwan requires iWAN DNS; system uses only host DNS.
    #[arg(long, value_enum, default_value = "auto")]
    dns_mode: DnsModeArg,
    /// Recursive DNS server reached through the iWAN userspace stack. An
    /// omitted port defaults to 53. Repeat for multiple servers.
    #[arg(long = "dns-server", value_parser = parse_dns_server)]
    dns_servers: Vec<SocketAddr>,
    /// Timeout for one DNS server query.
    #[arg(long, default_value_t = 3_000)]
    dns_timeout_ms: u64,
    /// Loopback address for the local listener.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    /// Additional HTTPS PEM CA certificate file. Repeat for multiple files.
    #[arg(long = "ca-cert")]
    ca_certificates: Vec<PathBuf>,
    /// Total timeout for target DNS, TCP, and TLS setup.
    #[arg(long, default_value_t = 10_000)]
    connect_timeout_ms: u64,
}

#[cfg(feature = "forward")]
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum DnsModeArg {
    Auto,
    Iwan,
    System,
}

#[cfg(feature = "forward")]
impl From<DnsModeArg> for forward::DnsMode {
    fn from(value: DnsModeArg) -> Self {
        match value {
            DnsModeArg::Auto => Self::Auto,
            DnsModeArg::Iwan => Self::Iwan,
            DnsModeArg::System => Self::System,
        }
    }
}

#[cfg(feature = "forward")]
fn parse_dns_server(value: &str) -> std::result::Result<SocketAddr, String> {
    if let Ok(address) = value.parse::<IpAddr>() {
        return Ok(SocketAddr::new(address, 53));
    }
    value
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid DNS server {value}: {error}"))
}

#[derive(Debug, Clone, Default, Args)]
struct RouteArgs {
    /// CIDR routed through iWAN. Repeat for multiple routes.
    #[arg(long = "route", value_delimiter = ',')]
    routes: Vec<String>,
    /// IP address routed through iWAN as a host route. Repeat as needed.
    #[arg(long = "route-ip", value_delimiter = ',')]
    route_ips: Vec<String>,
    /// Domain resolved once and routed through iWAN. Repeat as needed.
    #[arg(long = "route-domain", value_delimiter = ',')]
    route_domains: Vec<String>,
}

#[derive(Debug, Args)]
struct DecodeArgs {
    /// Datagram bytes as hexadecimal; whitespace, ':' and '-' are ignored.
    hex: String,
}

#[cfg(feature = "managed")]
#[derive(Debug, Args)]
struct ManagedArgs {
    /// Customer domain resolved through the production lookup service.
    #[arg(long)]
    domain: String,
    /// Controller device identifier.
    #[arg(long)]
    device_id: String,
    /// Confirm that the user granted privacy/network access.
    #[arg(long)]
    consent: bool,
    /// Directory for the recovered seven-day lookup cache.
    #[arg(long)]
    cache_dir: Option<PathBuf>,
    /// Timeout for each UDP ingress probe.
    #[arg(long, default_value_t = 2_000)]
    ping_timeout_ms: u64,
    #[command(subcommand)]
    action: ManagedCommand,
}

#[cfg(feature = "managed")]
#[derive(Debug, Subcommand)]
enum ManagedCommand {
    /// Resolve the domain and print the discovered authentication path.
    Discover,
    /// Complete login, posture gates, ingress probing and the temporary OPEN.
    Login(ManagedLoginArgs),
    /// Complete login and establish the persistent VPN tunnel.
    Connect(ManagedConnectArgs),
}

#[cfg(feature = "managed")]
#[derive(Debug, Clone, Args)]
struct ManagedLoginArgs {
    /// Username for credential domains. Ignored for OIDC domains.
    #[arg(long)]
    username: Option<String>,
    /// Read the credential-domain password from this environment variable.
    #[arg(long, default_value = "OPENIWAN_PASSWORD")]
    password_env: String,
    /// Read the first password line from this mode-0600 file.
    #[arg(long)]
    password_file: Option<PathBuf>,
    /// OIDC redirect URI registered by the original Android client.
    #[arg(long, default_value = "com.panabit.mobile://oauth2redirect")]
    redirect_uri: String,
    /// JSON array containing locally evaluated posture check results.
    #[arg(long)]
    posture_results: Option<PathBuf>,
    /// Cached local posture version sent to `/config`.
    #[arg(long)]
    posture_version: Option<i64>,
}

#[cfg(feature = "managed")]
#[derive(Debug, Args)]
struct ManagedConnectArgs {
    #[command(flatten)]
    login: ManagedLoginArgs,
    /// TUN interface name.
    #[arg(long)]
    tun: Option<String>,
    #[command(flatten)]
    routes: RouteArgs,
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
            let elapsed = client::ping(address, Duration::from_millis(arguments.timeout_ms))?;
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
        Command::Managed(arguments) => managed(arguments)?,
    }
    Ok(())
}

fn connect(arguments: ConnectArgs) -> Result<()> {
    let client = build_client(&arguments.connection)?;
    run_client(client, arguments.tun.as_deref(), &arguments.routes)
}

#[cfg(feature = "forward")]
fn forward(arguments: ForwardArgs) -> Result<()> {
    let client = build_client(&arguments.connection)?;
    run_forward(client, &arguments.forward, &[])
}

fn run_client(client: Client, tun: Option<&str>, route_arguments: &RouteArgs) -> Result<()> {
    let session = client.authenticate()?;
    print_session(session.info());

    let mut route_ips = route_arguments.route_ips.clone();
    route_ips.extend(
        session
            .info()
            .dns_servers
            .iter()
            .filter(|server| **server != session.info().peer.ip())
            .map(ToString::to_string),
    );
    let routes = resolve_route_targets(
        &route_arguments.routes,
        &route_ips,
        &route_arguments.route_domains,
        Some(session.info().peer.ip()),
    )?;
    let device = Arc::new(TunDevice::open(tun, session.info())?);
    let _routes = RouteGuard::configure(&device, &routes)?;
    let _dns = DnsGuard::configure(&device, &session.info().dns_servers, &[])?;
    for route in &routes {
        println!("route {route} -> {}", device.name());
    }
    println!("TUN {} is active; press Ctrl-C to stop", device.name());

    let shutdown = install_shutdown_handler()?;
    let end = client.run_reconnecting_from(session, device, shutdown)?;
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
    provider_dns_servers: &[IpAddr],
) -> Result<()> {
    let mut dns_servers = arguments.dns_servers.clone();
    if dns_servers.is_empty() {
        dns_servers.extend(
            provider_dns_servers
                .iter()
                .copied()
                .map(|address| SocketAddr::new(address, 53)),
        );
    }
    let dns = forward::DnsConfig::new(
        arguments.dns_mode.into(),
        dns_servers,
        Duration::from_millis(arguments.dns_timeout_ms),
    )?;
    let config = forward::ForwardConfig::new(
        arguments.listen,
        &arguments.target,
        dns,
        arguments.ca_certificates.clone(),
        Duration::from_millis(arguments.connect_timeout_ms),
    )?;
    let session = client.authenticate()?;
    print_session(session.info());
    let shutdown = install_shutdown_handler()?;
    let end = forward::run(client, session, config, shutdown)?;
    println!("session ended: {end:?}");
    Ok(())
}

#[cfg(feature = "managed")]
fn managed(arguments: ManagedArgs) -> Result<()> {
    let client = DomainClient::new(arguments.cache_dir);
    let discovered = client.discover(&arguments.domain, &arguments.device_id, arguments.consent)?;
    match arguments.action {
        ManagedCommand::Discover => print_discovery(&discovered),
        ManagedCommand::Login(login) => {
            let prepared = prepare_managed(
                &client,
                &discovered,
                &arguments.device_id,
                &login,
                Duration::from_millis(arguments.ping_timeout_ms),
            )?;
            print_prepared(&prepared);
        }
        ManagedCommand::Connect(connect) => {
            let prepared = prepare_managed(
                &client,
                &discovered,
                &arguments.device_id,
                &connect.login,
                Duration::from_millis(arguments.ping_timeout_ms),
            )?;
            print_prepared(&prepared);
            run_managed_client(prepared, connect.tun.as_deref(), &connect.routes)?;
        }
    }
    Ok(())
}

#[cfg(feature = "managed")]
fn run_managed_client(
    prepared: PreparedConnection,
    tun: Option<&str>,
    route_arguments: &RouteArgs,
) -> Result<()> {
    let client = prepared.client()?;
    let session = client.authenticate()?;
    print_session(session.info());

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

    let dns_servers = effective_managed_dns(&prepared, session.info())?;
    if mode != RoutingMode::All {
        cidrs.extend(
            dns_servers
                .iter()
                .map(|server| format!("{server}/{}", if server.is_ipv4() { 32 } else { 128 })),
        );
    }
    let mut exclusions = ip_filter
        .as_ref()
        .filter(|_| has_ip_filter)
        .map_or_else(Vec::new, |filter| valid_filter_cidrs(&filter.exclusive));
    exclusions.extend(managed_server_exclusions(&prepared.configuration)?);
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
    interface_session.dns_servers.clone_from(&dns_servers);
    let device = Arc::new(TunDevice::open(tun, &interface_session)?);
    let _routes = RouteGuard::configure(&device, &routes)?;
    let split_domains = routing
        .as_ref()
        .filter(|routing| routing.split_dns_enabled)
        .map_or(&[][..], |routing| {
            routing.split_dns_custom_domains.as_slice()
        });
    let _dns = DnsGuard::configure(&device, &dns_servers, split_domains)?;
    for route in &routes {
        println!("route {route} -> {}", device.name());
    }
    if !dns_servers.is_empty() {
        println!(
            "DNS policy: {}",
            dns_servers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    println!("TUN {} is active; press Ctrl-C to stop", device.name());

    let shutdown = install_shutdown_handler()?;
    let end = client.run_reconnecting_from(session, device, shutdown)?;
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
                tracing::warn!(rule = %value, "ignoring invalid recovered IP-filter rule");
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
fn effective_managed_dns(
    prepared: &PreparedConnection,
    session: &openiwan::SessionInfo,
) -> Result<Vec<std::net::IpAddr>> {
    let routing = prepared.configuration.routing()?;
    let dns_mode = routing
        .as_ref()
        .map_or("server", |routing| routing.dns_mode.as_str());
    if dns_mode == "disabled" {
        return Ok(Vec::new());
    }
    let mut servers = Vec::new();
    if dns_mode == "custom" {
        if let Some(routing) = routing {
            for value in [&routing.custom_dns1, &routing.custom_dns2] {
                if !value.trim().is_empty() {
                    servers.push(value.trim().parse().map_err(|_| {
                        Error::InvalidConfig(format!("invalid custom DNS server {value:?}"))
                    })?);
                }
            }
        }
    } else {
        if let Some(configuration) = prepared.configuration.dns() {
            for value in configuration.servers {
                if let Ok(address) = value.parse() {
                    servers.push(address);
                }
            }
        }
        servers.extend(session.dns_servers.iter().copied());
    }
    servers.sort_unstable();
    servers.dedup();
    Ok(servers)
}

#[cfg(feature = "managed")]
fn prepare_managed(
    client: &DomainClient,
    discovered: &DiscoveredDomain,
    device_id: &str,
    arguments: &ManagedLoginArgs,
    ping_timeout: Duration,
) -> Result<PreparedConnection> {
    match discovered.auth.method {
        AuthMethod::Credential => {
            let username = arguments.username.as_deref().ok_or_else(|| {
                Error::InvalidConfig("--username is required for this credential domain".into())
            })?;
            let password = read_managed_secret(arguments)?;
            client.password_login(discovered, device_id, username, password, ping_timeout)
        }
        AuthMethod::Oidc => {
            let pending = client.begin_oidc(discovered, &arguments.redirect_uri)?;
            println!(
                "Open this URL in a browser and complete authentication:\n\n{}\n",
                pending.authorization_url()
            );
            let redirect = prompt_line("Paste the complete callback URL: ")?;
            let identity = client.complete_oidc(&pending, &redirect)?;
            let posture_results = read_posture_results(arguments.posture_results.as_deref())?;
            client.oidc_login(
                discovered,
                device_id,
                &identity,
                &posture_results,
                arguments.posture_version,
                ping_timeout,
            )
        }
    }
}

#[cfg(feature = "managed")]
fn print_discovery(discovered: &DiscoveredDomain) {
    println!("domain: {}", discovered.active_domain());
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
fn read_managed_secret(arguments: &ManagedLoginArgs) -> Result<String> {
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

    #[test]
    fn hex_decoder_accepts_capture_formats() {
        assert_eq!(decode_hex("11:22 aa-bb").unwrap(), [0x11, 0x22, 0xaa, 0xbb]);
        assert!(decode_hex("abc").is_err());
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
            "--consent",
            "login",
            "--username",
            "alice",
            "--posture-version",
            "2",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Managed(ManagedArgs {
                domain,
                device_id,
                consent: true,
                action: ManagedCommand::Login(ManagedLoginArgs {
                    posture_version: Some(version),
                    username: Some(username),
                    ..
                }),
                ..
            }) if domain == "iwan.ustc"
                && device_id == "device-1"
                && username == "alice"
                && version == 2
        ));
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
            "--dns-mode",
            "iwan",
            "--dns-server",
            "192.0.2.53",
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
                    dns_mode: DnsModeArg::Iwan,
                    dns_servers,
                    ..
                },
                ..
            }) if listen == "127.0.0.1:9080".parse().unwrap()
                && target == "tcp://db.example.test:5432"
                && dns_servers == vec!["192.0.2.53:53".parse::<SocketAddr>().unwrap()]
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
