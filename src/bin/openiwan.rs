#[cfg(feature = "forward")]
#[path = "openiwan/forward.rs"]
mod forward;

use clap::{Args, Parser, Subcommand};
use openiwan::client;
#[cfg(feature = "managed")]
use openiwan::managed::{
    ManagedClient, ManagedServer, ManagedState, ProviderConfig, default_state_path, load_state,
    new_device_id, save_state, select_server,
};
use openiwan::protocol::{self, Tlv};
use openiwan::tun::{RouteGuard, TunDevice, resolve_route_targets};
use openiwan::{Client, ClientConfig, EncryptionMethod, Error, PacketDevice, Result};
use std::fs;
#[cfg(feature = "managed")]
use std::io::Write;
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
    /// Log in through a configured controller, manage lines, and connect.
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
    /// Protected provider TOML file describing OIDC and controller parameters.
    #[arg(long)]
    provider: PathBuf,
    /// Override the managed state directory.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    action: ManagedCommand,
}

#[cfg(feature = "managed")]
#[derive(Debug, Subcommand)]
enum ManagedCommand {
    /// Log in through OIDC and save the encrypted line configuration.
    Fetch,
    /// List saved lines without network access or password decryption.
    List,
    /// Select a saved line and connect.
    Connect(ManagedConnectArgs),
    /// Fetch, select, and connect, prompting from the line list when needed.
    All(ManagedConnectArgs),
    /// Select a saved line and forward TCP or proxy HTTP(S) without host routes.
    #[cfg(feature = "forward")]
    Forward(ManagedForwardArgs),
}

#[cfg(feature = "managed")]
#[derive(Debug, Args)]
struct ManagedConnectArgs {
    /// Select a line by one-based index instead of prompting.
    #[arg(long, conflicts_with = "line_name")]
    line_index: Option<usize>,
    /// Select a line by its unique exact name instead of prompting.
    #[arg(long, conflicts_with = "line_index")]
    line_name: Option<String>,
    /// TUN interface name. Defaults to openiwan0 on Linux/Windows and an
    /// automatically allocated utunN on macOS.
    #[arg(long)]
    tun: Option<String>,
    #[arg(long)]
    mtu: Option<u16>,
    #[arg(long)]
    encryption: Option<EncryptionMethod>,
    #[command(flatten)]
    routes: RouteArgs,
}

#[cfg(all(feature = "managed", feature = "forward"))]
#[derive(Debug, Args)]
struct ManagedForwardArgs {
    /// Select a line by one-based index instead of prompting.
    #[arg(long, conflicts_with = "line_name")]
    line_index: Option<usize>,
    /// Select a line by its unique exact name instead of prompting.
    #[arg(long, conflicts_with = "line_index")]
    line_name: Option<String>,
    #[arg(long)]
    mtu: Option<u16>,
    #[arg(long)]
    encryption: Option<EncryptionMethod>,
    #[command(flatten)]
    forward: ForwardOptions,
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
            let address = ClientConfig::new(arguments.server, true, 16).resolve_server()?;
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

    let routes = resolve_route_targets(
        &route_arguments.routes,
        &route_arguments.route_ips,
        &route_arguments.route_domains,
        Some(session.info().peer.ip()),
    )?;
    let device = Arc::new(TunDevice::open(tun, session.info())?);
    let _routes = RouteGuard::configure(&device, &routes)?;
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
    let provider = ProviderConfig::load(&arguments.provider)?;
    let state_path = default_state_path(&provider.id, arguments.state_dir.as_deref())?;
    let client = ManagedClient::new(provider);
    match arguments.action {
        ManagedCommand::Fetch => {
            let state = managed_fetch(&client, &state_path)?;
            print_servers(&state);
        }
        ManagedCommand::List => {
            let state = load_managed_state(&client, &state_path)?;
            print_servers(&state);
        }
        ManagedCommand::Connect(connect) => {
            let state = load_managed_state(&client, &state_path)?;
            managed_connect(&client, &state, &connect)?;
        }
        ManagedCommand::All(connect) => {
            let state = managed_fetch(&client, &state_path)?;
            managed_connect(&client, &state, &connect)?;
        }
        #[cfg(feature = "forward")]
        ManagedCommand::Forward(forward) => {
            let state = load_managed_state(&client, &state_path)?;
            managed_forward(&client, &state, &forward)?;
        }
    }
    Ok(())
}

#[cfg(feature = "managed")]
fn managed_fetch(client: &ManagedClient, state_path: &Path) -> Result<ManagedState> {
    let device_id = if state_path.exists() {
        let state = load_managed_state(client, state_path)?;
        state.device_id
    } else {
        new_device_id()
    };
    let pending = client.begin_authorization()?;
    println!(
        "Open this URL in a browser and complete authentication:\n\n{}\n",
        pending.authorization_url()
    );
    let redirect = prompt_line("Paste the complete callback URL: ")?;
    let state = client.fetch(&pending, &redirect, &device_id)?;
    save_state(state_path, &state)?;
    println!(
        "saved {} line(s) to {}",
        state.servers.len(),
        state_path.display()
    );
    Ok(state)
}

#[cfg(feature = "managed")]
fn load_managed_state(client: &ManagedClient, state_path: &Path) -> Result<ManagedState> {
    let state = load_state(state_path)?;
    state.validate_for(&client.provider().id, &client.provider().controller.domain)?;
    Ok(state)
}

#[cfg(feature = "managed")]
fn managed_connect(
    client: &ManagedClient,
    state: &ManagedState,
    arguments: &ManagedConnectArgs,
) -> Result<()> {
    let selected =
        select_or_prompt_server(state, arguments.line_index, arguments.line_name.as_deref())?;
    println!("connecting to {} ({})", selected.name, selected.endpoint());

    let mut config = ClientConfig::new(
        selected.endpoint(),
        client.provider().require_auth_verify_echo,
        client.provider().xor_key_bytes,
    );
    if let Some(mtu) = arguments.mtu {
        config.mtu = mtu;
    }
    if let Some(encryption) = arguments.encryption {
        config.encryption = encryption;
    }
    let iwan_client = client.build_client(state, selected, config)?;
    run_client(iwan_client, arguments.tun.as_deref(), &arguments.routes)
}

#[cfg(all(feature = "managed", feature = "forward"))]
fn managed_forward(
    client: &ManagedClient,
    state: &ManagedState,
    arguments: &ManagedForwardArgs,
) -> Result<()> {
    let selected =
        select_or_prompt_server(state, arguments.line_index, arguments.line_name.as_deref())?;
    println!("connecting to {} ({})", selected.name, selected.endpoint());

    let mut config = ClientConfig::new(
        selected.endpoint(),
        client.provider().require_auth_verify_echo,
        client.provider().xor_key_bytes,
    );
    if let Some(mtu) = arguments.mtu {
        config.mtu = mtu;
    }
    if let Some(encryption) = arguments.encryption {
        config.encryption = encryption;
    }
    let iwan_client = client.build_client(state, selected, config)?;
    run_forward(
        iwan_client,
        &arguments.forward,
        &client.provider().dns_servers,
    )
}

#[cfg(feature = "managed")]
fn select_or_prompt_server<'a>(
    state: &'a ManagedState,
    line_index: Option<usize>,
    line_name: Option<&str>,
) -> Result<&'a ManagedServer> {
    if let Some(server) = select_server(state, line_index, line_name)? {
        return Ok(server);
    }
    print_servers(state);
    prompt_for_server(state)
}

#[cfg(feature = "managed")]
fn print_servers(state: &ManagedState) {
    for (index, server) in state.servers.iter().enumerate() {
        println!("{}. {} ({})", index + 1, server.name, server.endpoint());
    }
}

#[cfg(feature = "managed")]
fn prompt_for_server(state: &ManagedState) -> Result<&ManagedServer> {
    loop {
        let value = prompt_line(&format!("Select line [1-{}]: ", state.servers.len()))?;
        if let Ok(index) = value.parse::<usize>()
            && let Ok(Some(server)) = select_server(state, Some(index), None)
        {
            return Ok(server);
        }
        eprintln!("invalid line selection");
    }
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
            true,
            16,
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
    fn parses_managed_commands_and_rejects_conflicting_selectors() {
        let parsed = Cli::try_parse_from([
            "openiwan",
            "managed",
            "--provider",
            "provider.toml",
            "connect",
            "--line-index",
            "2",
            "--route-ip",
            "192.0.2.10",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Managed(ManagedArgs {
                action: ManagedCommand::Connect(ManagedConnectArgs {
                    line_index: Some(2),
                    ..
                }),
                ..
            })
        ));

        assert!(
            Cli::try_parse_from([
                "openiwan",
                "managed",
                "--provider",
                "provider.toml",
                "connect",
                "--line-index",
                "1",
                "--line-name",
                "Education",
            ])
            .is_err()
        );
    }

    #[cfg(feature = "managed")]
    #[test]
    fn explicit_managed_selector_resolves_without_prompting() {
        let state: ManagedState = serde_json::from_value(serde_json::json!({
            "version": openiwan::managed::STATE_VERSION,
            "provider_id": "test",
            "domain": "test",
            "device_id": "device",
            "fetched_at_unix": 0,
            "servers": [{
                "name": "Education",
                "host": "192.0.2.1",
                "port": 6001,
                "username": "alice",
                "encrypted_password": "encrypted"
            }]
        }))
        .unwrap();

        assert_eq!(
            select_or_prompt_server(&state, Some(1), None).unwrap().name,
            "Education"
        );
        assert_eq!(
            select_or_prompt_server(&state, None, Some("Education"))
                .unwrap()
                .endpoint(),
            "192.0.2.1:6001"
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

    #[cfg(all(feature = "managed", feature = "forward"))]
    #[test]
    fn parses_managed_forward() {
        let parsed = Cli::try_parse_from([
            "openiwan",
            "managed",
            "--provider",
            "provider.toml",
            "forward",
            "--line-name",
            "Education",
            "--target",
            "https://db.example.test",
            "--ca-cert",
            "root-a.pem",
            "--ca-cert",
            "root-b.pem",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Managed(ManagedArgs {
                action: ManagedCommand::Forward(ManagedForwardArgs {
                    line_name: Some(name),
                    forward: ForwardOptions {
                        ca_certificates,
                        ..
                    },
                    ..
                }),
                ..
            }) if name == "Education"
                && ca_certificates
                    == vec![PathBuf::from("root-a.pem"), PathBuf::from("root-b.pem")]
        ));
    }
}
