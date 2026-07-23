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
use std::io::{BufRead, Write};
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
    #[arg(long, default_value = "openiwan0")]
    tun: String,
    #[command(flatten)]
    routes: RouteArgs,
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
    /// Fetch, list, select, and connect.
    All(ManagedConnectArgs),
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
    #[arg(long, default_value = "openiwan0")]
    tun: String,
    #[arg(long)]
    mtu: Option<u16>,
    #[arg(long)]
    encryption: Option<EncryptionMethod>,
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
        Command::Decode(arguments) => decode(&arguments.hex)?,
        #[cfg(feature = "managed")]
        Command::Managed(arguments) => managed(arguments)?,
    }
    Ok(())
}

fn connect(arguments: ConnectArgs) -> Result<()> {
    let client = build_client(&arguments.connection)?;
    run_client(client, &arguments.tun, &arguments.routes)
}

fn run_client(client: Client, tun: &str, route_arguments: &RouteArgs) -> Result<()> {
    let session = client.authenticate()?;
    print_session(session.info());

    let routes = resolve_route_targets(
        &route_arguments.routes,
        &route_arguments.route_ips,
        &route_arguments.route_domains,
        Some(session.info().peer.ip()),
    )?;
    let device = Arc::new(TunDevice::open(tun)?);
    let _routes = RouteGuard::configure(device.name(), session.info(), &routes)?;
    for route in &routes {
        println!("route {route} -> {}", device.name());
    }
    println!("TUN {} is active; press Ctrl-C to stop", device.name());

    let shutdown = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&shutdown);
    ctrlc::set_handler(move || signal.store(true, Ordering::Release)).map_err(|error| {
        Error::InvalidConfig(format!("failed to install signal handler: {error}"))
    })?;
    let end = client.run_reconnecting_from(session, device, shutdown)?;
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
            print_servers(&state);
            managed_connect(&client, &state, &connect)?;
        }
        ManagedCommand::All(connect) => {
            let state = managed_fetch(&client, &state_path)?;
            print_servers(&state);
            managed_connect(&client, &state, &connect)?;
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
    let selected = select_server(state, arguments.line_index, arguments.line_name.as_deref())?
        .map_or_else(|| prompt_for_server(state), Ok)?;
    println!("connecting to {} ({})", selected.name, selected.endpoint());

    let mut config = ClientConfig::new(selected.endpoint());
    if let Some(mtu) = arguments.mtu {
        config.mtu = mtu;
    }
    if let Some(encryption) = arguments.encryption {
        config.encryption = encryption;
    }
    let iwan_client = client.build_client(state, selected, config)?;
    run_client(iwan_client, &arguments.tun, &arguments.routes)
}

#[cfg(feature = "managed")]
fn print_servers(state: &ManagedState) {
    for (index, server) in state.servers.iter().enumerate() {
        println!("{:>2}. {:30} {}", index + 1, server.name, server.endpoint());
    }
}

#[cfg(feature = "managed")]
fn prompt_for_server(state: &ManagedState) -> Result<&ManagedServer> {
    loop {
        let value = prompt_line(&format!("Select line [1-{}]: ", state.servers.len()))?;
        if let Ok(index) = value.parse::<usize>() {
            if let Ok(Some(server)) = select_server(state, Some(index), None) {
                return Ok(server);
            }
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
    if let Ok(password) = std::env::var(&arguments.password_env) {
        if !password.is_empty() {
            return Ok(password);
        }
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
fn validate_secret_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn prompt_password(prompt: &str) -> Result<String> {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;

    let mut tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    tty.write_all(prompt.as_bytes())?;
    tty.flush()?;
    let fd = tty.as_raw_fd();
    let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: `original` points to writable termios storage and fd is a TTY.
    if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: tcgetattr initialized `original` on success.
    let original = unsafe { original.assume_init() };
    let mut hidden = original;
    hidden.c_lflag &= !libc::ECHO;
    // SAFETY: both the descriptor and termios pointer are valid.
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw const hidden) } < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    let mut password = String::new();
    let read_result = {
        let mut reader = std::io::BufReader::new(&tty);
        reader.read_line(&mut password)
    };
    // SAFETY: restore the attributes obtained from tcgetattr.
    let restore_result = unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw const original) };
    tty.write_all(b"\n")?;
    read_result?;
    if restore_result < 0 {
        password.zeroize();
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    while matches!(password.as_bytes().last(), Some(b'\n' | b'\r')) {
        password.pop();
    }
    if password.is_empty() {
        return Err(Error::InvalidConfig("password must not be empty".into()));
    }
    Ok(password)
}

#[cfg(not(unix))]
fn prompt_password(_prompt: &str) -> Result<String> {
    Err(Error::Unsupported(
        "interactive hidden password input is implemented only on Unix",
    ))
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
    if compact.len() % 2 != 0 {
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
}
