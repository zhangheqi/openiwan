mod dns;
mod http_forward;

// URI-driven TCP and HTTP(S) forwarding over one iWAN userspace network stack.

use futures::{Sink, Stream};
use hickory_proto::rr::Name;
use openiwan::{Client, ConnectedSession, Error, PacketDevice, Result, SessionEnd, SessionInfo};
use rustls::pki_types::ServerName;
use std::future::Future;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional};
use tokio::net::{TcpListener, lookup_host};
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::mpsc::{
    Receiver as TokioReceiver, Sender as TokioSender, channel as tokio_channel,
    error::TryRecvError as TokioTryRecvError,
};
use tokio::task::{JoinError, JoinSet};
use tokio::time::{Instant, MissedTickBehavior, interval, timeout};
use tokio_smoltcp::device::{AsyncDevice, DeviceCapabilities};
use tokio_smoltcp::smoltcp::iface;
use tokio_smoltcp::smoltcp::phy::Medium;
use tokio_smoltcp::smoltcp::wire::{HardwareAddress, IpAddress as SmolIpAddress, IpCidr};
use tokio_smoltcp::{BufferSize, Net, NetConfig, TcpStream as UserTcpStream};
use tokio_util::sync::{PollSendError, PollSender};
use tracing::{debug, info, warn};
use url::{Host, Url};

const PACKET_QUEUE_CAPACITY: usize = 1_000;
const TCP_BUFFER_SIZE: usize = 64 * 1_024;
const MAX_CONNECTIONS: usize = 256;
const ERROR_CLOSE_GRACE: Duration = Duration::from_millis(250);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const SHUTDOWN_POLL: Duration = Duration::from_millis(100);
const SYSTEM_DNS_TTL: Duration = Duration::from_secs(60);
const MIN_DNS_TTL: Duration = Duration::from_secs(5);
const MAX_DNS_TTL: Duration = Duration::from_secs(3_600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMode {
    Auto,
    Iwan,
    System,
}

#[derive(Debug, Clone)]
pub struct DnsConfig {
    mode: DnsMode,
    servers: Vec<SocketAddr>,
    timeout: Duration,
}

impl DnsConfig {
    pub fn new(mode: DnsMode, servers: Vec<SocketAddr>, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            return Err(Error::InvalidConfig(
                "DNS timeout must be greater than zero".into(),
            ));
        }
        if servers.iter().any(|server| {
            server.port() == 0 || server.ip().is_unspecified() || server.ip().is_multicast()
        }) {
            return Err(Error::InvalidConfig(
                "DNS servers must be unicast addresses with a nonzero port".into(),
            ));
        }
        Ok(Self {
            mode,
            servers,
            timeout,
        })
    }
}

#[derive(Clone)]
pub struct ForwardConfig {
    listen: SocketAddr,
    target: Target,
    dns: DnsConfig,
    tls: Option<tokio_rustls::TlsConnector>,
    connect_timeout: Duration,
}

impl ForwardConfig {
    pub fn new(
        listen: SocketAddr,
        target: &str,
        dns: DnsConfig,
        ca_certificates: Vec<PathBuf>,
        connect_timeout: Duration,
    ) -> Result<Self> {
        if !listen.ip().is_loopback() {
            return Err(Error::InvalidConfig(format!(
                "forward listen address {listen} is not a loopback address"
            )));
        }
        if connect_timeout.is_zero() {
            return Err(Error::InvalidConfig(
                "connect timeout must be greater than zero".into(),
            ));
        }
        let target = Target::parse(target)?;
        if !ca_certificates.is_empty() && !target.uses_tls() {
            return Err(Error::InvalidConfig(
                "--ca-cert is only valid for an https:// target".into(),
            ));
        }
        let tls = target
            .uses_tls()
            .then(|| http_forward::build_tls_connector(&ca_certificates))
            .transpose()?;
        Ok(Self {
            listen,
            target,
            dns,
            tls,
            connect_timeout,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetScheme {
    Tcp,
    Http,
    Https,
}

impl TargetScheme {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    scheme: TargetScheme,
    host: String,
    authority: String,
    port: u16,
}

impl Target {
    fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.is_empty() {
            return Err(Error::InvalidConfig(
                "forward target must not be empty".into(),
            ));
        }
        let (_, remainder) = value.split_once("://").ok_or_else(|| {
            Error::InvalidConfig(
                "forward target must be an absolute URI using tcp://, http://, or https://".into(),
            )
        })?;
        let raw_authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
        let url = Url::parse(value).map_err(|error| {
            Error::InvalidConfig(format!(
                "invalid forward target URI; use tcp://, http://, or https://: {error}"
            ))
        })?;
        let scheme = match url.scheme() {
            "tcp" => TargetScheme::Tcp,
            "http" => TargetScheme::Http,
            "https" => TargetScheme::Https,
            scheme => {
                return Err(Error::InvalidConfig(format!(
                    "unsupported forward target scheme {scheme:?}; use tcp, http, or https"
                )));
            }
        };
        if raw_authority.contains('@') || !url.username().is_empty() || url.password().is_some() {
            return Err(Error::InvalidConfig(
                "forward target URI must not contain user information".into(),
            ));
        }
        let has_valid_path = match scheme {
            TargetScheme::Tcp => url.path().is_empty(),
            TargetScheme::Http | TargetScheme::Https => url.path() == "/",
        };
        if !has_valid_path || url.query().is_some() || url.fragment().is_some() {
            return Err(Error::InvalidConfig(
                "forward target must be an origin without a path, query, or fragment".into(),
            ));
        }
        let host = parse_target_host(&url)?;
        let port = match scheme {
            TargetScheme::Tcp => url.port().ok_or_else(|| {
                Error::InvalidConfig("tcp:// forward targets must include an explicit port".into())
            })?,
            TargetScheme::Http | TargetScheme::Https => url
                .port_or_known_default()
                .expect("HTTP schemes have known default ports"),
        };
        if port == 0 {
            return Err(Error::InvalidConfig(
                "forward target port must be nonzero".into(),
            ));
        }
        if scheme == TargetScheme::Https {
            ServerName::try_from(host.clone()).map_err(|error| {
                Error::InvalidConfig(format!(
                    "HTTPS target host is not a valid TLS server identity: {error}"
                ))
            })?;
        }
        let authority = target_authority(scheme, &host, port, url.port())?;
        Ok(Self {
            scheme,
            host,
            authority,
            port,
        })
    }

    fn display(&self) -> String {
        format!("{}://{}", self.scheme.as_str(), self.authority)
    }

    const fn is_http(&self) -> bool {
        matches!(self.scheme, TargetScheme::Http | TargetScheme::Https)
    }

    const fn uses_tls(&self) -> bool {
        matches!(self.scheme, TargetScheme::Https)
    }
}

fn parse_target_host(url: &Url) -> Result<String> {
    let host = match url
        .host()
        .ok_or_else(|| Error::InvalidConfig("forward target URI has no host".into()))?
    {
        Host::Domain(domain) => {
            let name = Name::from_ascii(domain).map_err(|error| {
                Error::InvalidConfig(format!("invalid forward target host {domain:?}: {error}"))
            })?;
            if name.is_root() {
                return Err(Error::InvalidConfig(
                    "forward target URI must contain a non-root host".into(),
                ));
            }
            domain.to_owned()
        }
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    };
    if let Ok(address) = host.parse::<IpAddr>()
        && (address.is_unspecified() || address.is_multicast())
    {
        return Err(Error::InvalidConfig(
            "forward target must be a unicast, non-unspecified address".into(),
        ));
    }
    Ok(host)
}

fn target_authority(
    scheme: TargetScheme,
    host: &str,
    port: u16,
    explicit_port: Option<u16>,
) -> Result<String> {
    let display_host = if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let authority = match (scheme, explicit_port) {
        (TargetScheme::Tcp, _) => format!("{display_host}:{port}"),
        (TargetScheme::Http | TargetScheme::Https, Some(port)) => {
            format!("{display_host}:{port}")
        }
        (TargetScheme::Http | TargetScheme::Https, None) => display_host,
    };
    authority
        .parse::<hyper::http::uri::Authority>()
        .map_err(|error| {
            Error::InvalidConfig(format!("invalid forward target authority: {error}"))
        })?;
    Ok(authority)
}

pub fn parse_target_argument(value: &str) -> std::result::Result<String, String> {
    Target::parse(value)
        .map(|_| value.trim().to_owned())
        .map_err(|error| error.to_string())
}

pub fn run(
    client: Client,
    session: ConnectedSession,
    config: ForwardConfig,
    shutdown: Arc<AtomicBool>,
) -> Result<SessionEnd> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("openiwan-forward")
        .build()
        .map_err(Error::Io)?;
    runtime.block_on(run_async(client, session, config, shutdown))
}

async fn run_async(
    client: Client,
    session: ConnectedSession,
    config: ForwardConfig,
    shutdown: Arc<AtomicBool>,
) -> Result<SessionEnd> {
    let ForwardConfig {
        listen,
        target,
        dns,
        tls,
        connect_timeout,
    } = config;
    let session_info = session.info().clone();
    let (packet_device, capture) = channel_packet_device(session_info.mtu);
    let net = build_userspace_net(capture, &session_info)?;
    let connector = build_tcp_connector(
        Arc::clone(&net),
        &session_info,
        target.clone(),
        dns,
        connect_timeout,
    );
    let listener = TcpListener::bind(listen).await.map_err(Error::Io)?;
    let listen_address = listener.local_addr().map_err(Error::Io)?;

    let mut tunnel = spawn_tunnel(client, session, packet_device, Arc::clone(&shutdown));

    if let Some(end) = preflight_connector(&connector, &mut tunnel, &shutdown).await? {
        return Ok(end);
    }

    let handler = ConnectionHandler::new(connector, &target, tls);
    announce_forward(listen_address, &target);

    let mut connections = JoinSet::new();
    let mut shutdown_check = interval(SHUTDOWN_POLL);
    shutdown_check.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut tunnel_result = None;
    let mut accept_error = None;
    let mut capacity_warning_active = false;

    loop {
        tokio::select! {
            result = &mut tunnel => {
                tunnel_result = Some(result);
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((local, peer)) => {
                        match capacity_decision(
                            connections.len(),
                            &mut capacity_warning_active,
                        ) {
                            CapacityDecision::Accept => {
                                spawn_connection(
                                    &mut connections,
                                    local,
                                    peer,
                                    handler.clone(),
                                );
                            }
                            CapacityDecision::RejectAndWarn => {
                                warn!(
                                    %peer,
                                    limit = MAX_CONNECTIONS,
                                    "rejecting forward connections at capacity"
                                );
                                drop(local);
                            }
                            CapacityDecision::Reject => drop(local),
                        }
                    }
                    Err(error) => {
                        accept_error = Some(error);
                        break;
                    }
                }
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = joined {
                    warn!(%error, "forward connection task failed");
                }
                reset_capacity_warning(connections.len(), &mut capacity_warning_active);
            }
            _ = shutdown_check.tick() => {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
            }
        }
    }

    shutdown.store(true, Ordering::Release);
    drop(listener);
    finish_connections(&mut connections).await;
    drop(net);

    let end = match tunnel_result {
        Some(result) => flatten_tunnel_result(result)?,
        None => flatten_tunnel_result(tunnel.await)?,
    };
    if let Some(error) = accept_error {
        return Err(Error::Io(error));
    }
    info!(?end, "route-free forward stopped");
    Ok(end)
}

fn spawn_tunnel(
    client: Client,
    session: ConnectedSession,
    device: Arc<ChannelPacketDevice>,
    shutdown: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<Result<SessionEnd>> {
    let device: Arc<dyn PacketDevice> = device;
    tokio::task::spawn_blocking(move || client.run_reconnecting_from(session, device, shutdown))
}

fn build_tcp_connector(
    net: Arc<Net>,
    session: &SessionInfo,
    target: Target,
    dns: DnsConfig,
    connect_timeout: Duration,
) -> TcpConnector {
    let dns_servers = effective_dns_servers(&dns.servers, session);
    TcpConnector::new(
        net,
        session,
        ConnectorSettings {
            target,
            dns_mode: dns.mode,
            dns_servers,
            dns_timeout: dns.timeout,
            timeout: connect_timeout,
        },
    )
}

#[derive(Clone)]
enum ConnectionHandler {
    Tcp(TcpConnector),
    Http(http_forward::HttpForwarder),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapacityDecision {
    Accept,
    RejectAndWarn,
    Reject,
}

fn capacity_decision(active: usize, warning_active: &mut bool) -> CapacityDecision {
    if active < MAX_CONNECTIONS {
        CapacityDecision::Accept
    } else if *warning_active {
        CapacityDecision::Reject
    } else {
        *warning_active = true;
        CapacityDecision::RejectAndWarn
    }
}

fn reset_capacity_warning(active: usize, warning_active: &mut bool) {
    if active < MAX_CONNECTIONS {
        *warning_active = false;
    }
}

impl ConnectionHandler {
    fn new(
        connector: TcpConnector,
        target: &Target,
        tls: Option<tokio_rustls::TlsConnector>,
    ) -> Self {
        if target.is_http() {
            Self::Http(http_forward::HttpForwarder::new(
                connector,
                target.clone(),
                tls,
            ))
        } else {
            debug_assert!(tls.is_none());
            Self::Tcp(connector)
        }
    }
}

fn spawn_connection(
    connections: &mut JoinSet<()>,
    local: tokio::net::TcpStream,
    peer: SocketAddr,
    handler: ConnectionHandler,
) {
    connections.spawn(async move {
        match handler {
            ConnectionHandler::Tcp(connector) => {
                let mut local = local;
                match connector.connect().await {
                    Ok(remote) => match relay_connection(&mut local, remote).await {
                        Ok((sent, received)) => {
                            debug!(
                                %peer,
                                local_to_target = sent,
                                target_to_local = received,
                                "TCP forward connection closed"
                            );
                        }
                        Err(error) => {
                            debug!(%peer, %error, "TCP forward connection ended with an error");
                        }
                    },
                    Err(error) => {
                        warn!(%peer, %error, "cannot connect to TCP forward target");
                    }
                }
            }
            ConnectionHandler::Http(proxy) => proxy.serve(local, peer).await,
        }
    });
}

async fn relay_connection(
    local: &mut tokio::net::TcpStream,
    remote: UserTcpStream,
) -> io::Result<(u64, u64)> {
    // tokio-smoltcp waits through TCP TIME-WAIT in poll_shutdown. The adapter
    // first drains acknowledged data, then initiates FIN while allowing
    // copy_bidirectional to finish without retaining completed forwards through
    // TIME-WAIT.
    let mut remote = RelayTcpStream::new(remote);
    let result = copy_bidirectional(local, &mut remote).await;
    if result.is_err() {
        remote.close_after_error().await;
    }
    tokio::task::yield_now().await;
    result
}

struct RelayTcpStream {
    inner: UserTcpStream,
    write_flushed: bool,
}

impl RelayTcpStream {
    const fn new(inner: UserTcpStream) -> Self {
        Self {
            inner,
            write_flushed: false,
        }
    }

    async fn close_after_error(&mut self) {
        let close = tokio::io::AsyncWriteExt::shutdown(&mut self.inner);
        let _ = timeout(ERROR_CLOSE_GRACE, close).await;
    }
}

impl AsyncRead for RelayTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for RelayTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(context, buffer);
        if matches!(&result, Poll::Ready(Ok(written)) if *written > 0) {
            self.write_flushed = false;
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(context);
        if matches!(&result, Poll::Ready(Ok(()))) {
            self.write_flushed = true;
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.write_flushed {
            match Pin::new(&mut self.inner).poll_flush(context) {
                Poll::Ready(Ok(())) => self.write_flushed = true,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        match Pin::new(&mut self.inner).poll_shutdown(context) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => Poll::Ready(Ok(())),
        }
    }
}

fn announce_forward(listen_address: SocketAddr, target: &Target) {
    if target.is_http() {
        println!(
            "HTTP forward listening on http://{listen_address} -> {}",
            target.display()
        );
        if !target.uses_tls() {
            println!("warning: upstream HTTP traffic is not protected by TLS");
        }
    } else {
        println!(
            "TCP forward listening on tcp://{listen_address} -> {}",
            target.display()
        );
        println!("TCP bytes, including TLS, are relayed unchanged");
    }
    println!("no TUN interface or host route was created; press Ctrl-C to stop");
}

fn effective_dns_servers(configured: &[SocketAddr], session: &SessionInfo) -> Vec<SocketAddr> {
    let mut servers = configured.to_vec();
    for address in session
        .dns_servers
        .iter()
        .copied()
        .filter(|address| !address.is_unspecified() && !address.is_multicast())
    {
        let server = SocketAddr::new(address, dns::default_port());
        if !servers.contains(&server) {
            servers.push(server);
        }
    }
    servers
}

async fn preflight_connector(
    connector: &TcpConnector,
    tunnel: &mut tokio::task::JoinHandle<Result<SessionEnd>>,
    shutdown: &Arc<AtomicBool>,
) -> Result<Option<SessionEnd>> {
    tokio::select! {
        result = &mut *tunnel => flatten_tunnel_result(result).map(Some),
        result = connector.preflight() => {
            if let Err(error) = result {
                shutdown.store(true, Ordering::Release);
                let _ = tunnel.await;
                Err(error)
            } else {
                Ok(None)
            }
        }
    }
}

async fn finish_connections(connections: &mut JoinSet<()>) {
    if timeout(SHUTDOWN_GRACE, async {
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                warn!(%error, "forward connection task failed during shutdown");
            }
        }
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}

fn flatten_tunnel_result(
    result: std::result::Result<Result<SessionEnd>, JoinError>,
) -> Result<SessionEnd> {
    result.map_err(|error| {
        Error::Io(io::Error::other(format!(
            "iWAN session task failed: {error}"
        )))
    })?
}

struct ChannelPacketDevice {
    incoming: TokioSender<io::Result<Vec<u8>>>,
    outgoing: Mutex<TokioReceiver<Vec<u8>>>,
}

impl PacketDevice for ChannelPacketDevice {
    fn name(&self) -> &'static str {
        "userspace-forward"
    }

    fn read_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let packet = self
            .outgoing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .try_recv()
            .map_err(|error| match error {
                TokioTryRecvError::Empty => ErrorKind::WouldBlock.into(),
                TokioTryRecvError::Disconnected => {
                    io::Error::new(ErrorKind::BrokenPipe, "userspace network stack stopped")
                }
            })?;
        if packet.len() > buffer.len() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "userspace packet of {} bytes exceeds device buffer of {} bytes",
                    packet.len(),
                    buffer.len()
                ),
            ));
        }
        buffer[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }

    fn write_packet(&self, packet: &[u8]) -> io::Result<usize> {
        self.incoming
            .blocking_send(Ok(packet.to_vec()))
            .map_err(|_| {
                io::Error::new(ErrorKind::BrokenPipe, "userspace network stack stopped")
            })?;
        Ok(packet.len())
    }
}

struct IwanAsyncDevice {
    incoming: TokioReceiver<io::Result<Vec<u8>>>,
    outgoing: PollSender<Vec<u8>>,
    capabilities: DeviceCapabilities,
}

impl Stream for IwanAsyncDevice {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.incoming.poll_recv(context)
    }
}

fn map_poll_send_error(error: PollSendError<Vec<u8>>) -> io::Error {
    io::Error::new(ErrorKind::BrokenPipe, error)
}

impl Sink<Vec<u8>> for IwanAsyncDevice {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.outgoing
            .poll_reserve(context)
            .map_err(map_poll_send_error)
    }

    fn start_send(mut self: Pin<&mut Self>, packet: Vec<u8>) -> io::Result<()> {
        self.outgoing.send_item(packet).map_err(map_poll_send_error)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.outgoing
            .poll_reserve(context)
            .map_err(map_poll_send_error)
    }

    fn poll_close(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncDevice for IwanAsyncDevice {
    fn capabilities(&self) -> &DeviceCapabilities {
        &self.capabilities
    }
}

fn channel_packet_device(mtu: u16) -> (Arc<ChannelPacketDevice>, IwanAsyncDevice) {
    let (incoming_tx, incoming_rx) = tokio_channel(PACKET_QUEUE_CAPACITY);
    let (outgoing_tx, outgoing_rx) = tokio_channel(PACKET_QUEUE_CAPACITY);
    let device = Arc::new(ChannelPacketDevice {
        incoming: incoming_tx,
        outgoing: Mutex::new(outgoing_rx),
    });

    let mut capabilities = DeviceCapabilities::default();
    capabilities.medium = Medium::Ip;
    capabilities.max_transmission_unit = usize::from(mtu);
    capabilities.max_burst_size = Some(100);
    let capture = IwanAsyncDevice {
        incoming: incoming_rx,
        outgoing: PollSender::new(outgoing_tx),
        capabilities,
    };
    (device, capture)
}

fn build_userspace_net(capture: IwanAsyncDevice, session: &SessionInfo) -> Result<Arc<Net>> {
    let address = session.address.ok_or(Error::MissingTlv("IP/IP6"))?;
    let prefix = match address {
        IpAddr::V4(_) => session
            .netmask
            .map(ipv4_mask_prefix)
            .transpose()?
            .unwrap_or(32),
        IpAddr::V6(_) => 128,
    };
    let ip_cidr = format!("{address}/{prefix}")
        .parse::<IpCidr>()
        .map_err(|()| Error::InvalidConfig("invalid userspace IP assignment".into()))?;
    let gateways = session
        .gateway
        .filter(|gateway| gateway.is_ipv4() == address.is_ipv4())
        .map(SmolIpAddress::from)
        .into_iter()
        .collect();

    let mut interface_config = iface::Config::new(HardwareAddress::Ip);
    interface_config.random_seed = session_random_seed(session);
    let mut net_config = NetConfig::new(interface_config, ip_cidr, gateways);
    net_config.buffer_size = BufferSize {
        tcp_rx_size: TCP_BUFFER_SIZE,
        tcp_tx_size: TCP_BUFFER_SIZE,
        ..BufferSize::default()
    };
    Ok(Arc::new(Net::new(capture, net_config)))
}

fn session_random_seed(session: &SessionInfo) -> u64 {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    time ^ (u64::from(session.token) << 16) ^ u64::from(session.session_id)
}

fn ipv4_mask_prefix(mask: Ipv4Addr) -> Result<u8> {
    let bits = u32::from(mask);
    let prefix = bits.leading_ones() as u8;
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if bits != expected {
        return Err(Error::InvalidConfig(format!(
            "non-contiguous IPv4 netmask {mask}"
        )));
    }
    Ok(prefix)
}

#[derive(Clone)]
struct TcpConnector {
    net: Arc<Net>,
    target: Target,
    dns_mode: DnsMode,
    dns_servers: Arc<[SocketAddr]>,
    dns_timeout: Duration,
    dns_cache: Arc<TokioMutex<Option<CachedResolution>>>,
    next_dns_id: Arc<AtomicU16>,
    timeout: Duration,
    ipv4: bool,
    synthetic_route: Arc<AtomicBool>,
}

struct ConnectorSettings {
    target: Target,
    dns_mode: DnsMode,
    dns_servers: Vec<SocketAddr>,
    dns_timeout: Duration,
    timeout: Duration,
}

#[derive(Clone)]
struct CachedResolution {
    addresses: Vec<SocketAddr>,
    source: ResolutionSource,
    expires_at: Instant,
}

#[derive(Clone)]
enum ResolutionSource {
    Fixed,
    IwanDns(SocketAddr),
    SystemDns,
}

impl TcpConnector {
    fn new(net: Arc<Net>, session: &SessionInfo, settings: ConnectorSettings) -> Self {
        let address = session
            .address
            .expect("authenticated session has an address");
        let seed = session_random_seed(session);
        Self {
            net,
            target: settings.target,
            dns_mode: settings.dns_mode,
            dns_servers: settings.dns_servers.into(),
            dns_timeout: settings.dns_timeout,
            dns_cache: Arc::new(TokioMutex::new(None)),
            next_dns_id: Arc::new(AtomicU16::new(seed as u16)),
            timeout: settings.timeout,
            ipv4: address.is_ipv4(),
            synthetic_route: Arc::new(AtomicBool::new(
                session
                    .gateway
                    .is_some_and(|gateway| gateway.is_ipv4() == address.is_ipv4()),
            )),
        }
    }

    async fn preflight(&self) -> Result<()> {
        let resolution = timeout(self.timeout, self.resolve())
            .await
            .map_err(|_| {
                Error::InvalidConfig(format!(
                    "DNS resolution for target {} timed out",
                    self.target.host
                ))
            })?
            .map_err(|error| {
                Error::InvalidConfig(format!(
                    "cannot resolve target {}: {error}",
                    self.target.host
                ))
            })?;
        if resolution.addresses.is_empty() {
            let family = if self.ipv4 { "IPv4" } else { "IPv6" };
            return Err(Error::InvalidConfig(format!(
                "target {} has no {family} address matching the iWAN session",
                self.target.host
            )));
        }
        match resolution.source {
            ResolutionSource::Fixed => {
                info!(
                    target = %self.target.host,
                    addresses = ?resolution.addresses,
                    "using fixed target address; DNS was bypassed"
                );
            }
            ResolutionSource::IwanDns(server) => {
                info!(
                    target = %self.target.host,
                    addresses = ?resolution.addresses,
                    %server,
                    "resolved target through iWAN DNS"
                );
            }
            ResolutionSource::SystemDns => {
                info!(
                    target = %self.target.host,
                    addresses = ?resolution.addresses,
                    "resolved target with the host DNS resolver"
                );
            }
        }
        if matches!(resolution.source, ResolutionSource::SystemDns)
            && resolution
                .addresses
                .iter()
                .any(|address| is_ipv4_benchmark_address(address.ip()))
        {
            warn!(
                target = %self.target.host,
                addresses = ?resolution.addresses,
                "host DNS returned 198.18.0.0/15; this may be a VPN Fake-IP \
                 rather than the real target address"
            );
        }
        self.ensure_userspace_route(resolution.addresses[0].ip())
            .map_err(Error::Io)?;
        Ok(())
    }

    async fn resolve(&self) -> io::Result<CachedResolution> {
        if let Ok(address) = self.target.host.parse::<IpAddr>() {
            let mut addresses = vec![SocketAddr::new(address, self.target.port)];
            self.normalize_addresses(&mut addresses);
            return Ok(CachedResolution {
                addresses,
                source: ResolutionSource::Fixed,
                expires_at: Instant::now() + MAX_DNS_TTL,
            });
        }

        let mut cache = self.dns_cache.lock().await;
        if let Some(resolution) = cache.as_ref()
            && resolution.expires_at > Instant::now()
        {
            return Ok(resolution.clone());
        }
        let resolution = self.resolve_uncached().await?;
        *cache = Some(resolution.clone());
        Ok(resolution)
    }

    async fn resolve_uncached(&self) -> io::Result<CachedResolution> {
        match self.dns_mode {
            DnsMode::Iwan => self.resolve_iwan_dns().await,
            DnsMode::System => self.resolve_system_dns(false).await,
            DnsMode::Auto => {
                if self.dns_servers.is_empty() {
                    self.resolve_system_dns(true).await
                } else {
                    self.resolve_iwan_dns().await
                }
            }
        }
    }

    async fn resolve_iwan_dns(&self) -> io::Result<CachedResolution> {
        if self.dns_servers.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "no usable iWAN DNS server was advertised or configured; \
                 add dns_servers to the managed provider or pass --dns-server",
            ));
        }

        let mut last_error = None;
        for server in self
            .dns_servers
            .iter()
            .copied()
            .filter(|server| server.is_ipv4() == self.ipv4)
        {
            self.ensure_userspace_route(server.ip())?;
            match dns::lookup(
                &self.net,
                server,
                &self.target.host,
                self.ipv4,
                self.dns_timeout,
                &self.next_dns_id,
            )
            .await
            {
                Ok(lookup) => {
                    let mut addresses: Vec<_> = lookup
                        .addresses
                        .into_iter()
                        .map(|address| SocketAddr::new(address, self.target.port))
                        .collect();
                    self.normalize_addresses(&mut addresses);
                    if addresses.is_empty() {
                        last_error = Some(io::Error::new(
                            ErrorKind::AddrNotAvailable,
                            "iWAN DNS result does not match the session address family",
                        ));
                        continue;
                    }
                    return Ok(CachedResolution {
                        addresses,
                        source: ResolutionSource::IwanDns(server),
                        expires_at: Instant::now() + clamp_dns_ttl(lookup.ttl),
                    });
                }
                Err(error) => {
                    debug!(%server, %error, "iWAN DNS server query failed");
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                ErrorKind::AddrNotAvailable,
                "no iWAN DNS server matches the session address family",
            )
        }))
    }

    async fn resolve_system_dns(&self, reject_fake_ip: bool) -> io::Result<CachedResolution> {
        let mut addresses: Vec<_> = lookup_host((self.target.host.as_str(), self.target.port))
            .await?
            .collect();
        self.normalize_addresses(&mut addresses);
        if addresses.is_empty() {
            return Err(io::Error::new(
                ErrorKind::AddrNotAvailable,
                "host DNS result does not match the iWAN session address family",
            ));
        }
        if reject_fake_ip
            && addresses
                .iter()
                .any(|address| is_ipv4_benchmark_address(address.ip()))
        {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "host DNS returned an address in 198.18.0.0/15, likely a VPN Fake-IP; \
                 configure an organization DNS server with --dns-server or provider dns_servers",
            ));
        }
        Ok(CachedResolution {
            addresses,
            source: ResolutionSource::SystemDns,
            expires_at: Instant::now() + SYSTEM_DNS_TTL,
        })
    }

    fn normalize_addresses(&self, addresses: &mut Vec<SocketAddr>) {
        addresses.retain(|address| address.is_ipv4() == self.ipv4);
        let mut unique = Vec::with_capacity(addresses.len());
        for address in addresses.drain(..) {
            if !unique.contains(&address) {
                unique.push(address);
            }
        }
        *addresses = unique;
    }

    fn ensure_userspace_route(&self, address: IpAddr) -> io::Result<()> {
        if self.synthetic_route.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let mut result = Ok(());
        self.net.routes_mut(|routes| {
            result = match address {
                IpAddr::V4(address) => routes
                    .add_default_ipv4_route(address)
                    .map(|_| ())
                    .map_err(|error| io::Error::other(error.to_string())),
                IpAddr::V6(address) => routes
                    .add_default_ipv6_route(address)
                    .map(|_| ())
                    .map_err(|error| io::Error::other(error.to_string())),
            };
        });
        if result.is_err() {
            self.synthetic_route.store(false, Ordering::Release);
        }
        result
    }

    async fn connect(&self) -> io::Result<UserTcpStream> {
        self.connect_with(|stream| std::future::ready(Ok(stream)))
            .await
    }

    async fn connect_with<T, F, Fut>(&self, mut finish: F) -> io::Result<T>
    where
        F: FnMut(UserTcpStream) -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        let started = Instant::now();
        let addresses = timeout(self.timeout, self.resolve())
            .await
            .map_err(|_| io::Error::new(ErrorKind::TimedOut, "target resolution timed out"))??
            .addresses;
        if addresses.is_empty() {
            return Err(io::Error::new(
                ErrorKind::AddrNotAvailable,
                "target DNS result does not match the iWAN address family",
            ));
        }

        let address_count = addresses.len();
        let mut last_error = None;
        for (index, address) in addresses.into_iter().enumerate() {
            self.ensure_userspace_route(address.ip())?;
            let remaining = self.timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                break;
            }
            let attempts_left = u32::try_from(address_count - index).unwrap_or(u32::MAX);
            let attempt_timeout = (remaining / attempts_left)
                .max(Duration::from_millis(1))
                .min(remaining);
            let attempt = async {
                let stream = self.net.tcp_connect(address).await?;
                finish(stream).await
            };
            match timeout(attempt_timeout, attempt).await {
                Ok(Ok(value)) => return Ok(value),
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => {
                    last_error = Some(io::Error::new(
                        ErrorKind::TimedOut,
                        format!("connection setup for target address {address} timed out"),
                    ));
                }
            }
        }
        Err(last_error
            .unwrap_or_else(|| io::Error::new(ErrorKind::TimedOut, "target connection timed out")))
    }
}

fn clamp_dns_ttl(ttl: Duration) -> Duration {
    ttl.clamp(MIN_DNS_TTL, MAX_DNS_TTL)
}

fn is_ipv4_benchmark_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            octets[0] == 198 && matches!(octets[1], 18 | 19)
        }
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openiwan::EncryptionMethod;

    pub(super) fn test_session(address: Ipv4Addr) -> SessionInfo {
        SessionInfo {
            peer: "127.0.0.1:6001".parse().unwrap(),
            session_id: 1,
            token: 2,
            encryption: EncryptionMethod::None,
            mtu: 1_400,
            address: Some(address.into()),
            gateway: None,
            netmask: Some(Ipv4Addr::BROADCAST),
            dns_servers: Vec::new(),
            duplicate_packets: false,
            server_config: None,
        }
    }

    pub(super) fn linked_userspace_nets(
        client_ip: Ipv4Addr,
        server_ip: Ipv4Addr,
    ) -> (
        Arc<Net>,
        Arc<Net>,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
        let (client_device, client_capture) = channel_packet_device(1_400);
        let (server_device, server_capture) = channel_packet_device(1_400);
        let client_net = build_userspace_net(client_capture, &test_session(client_ip)).unwrap();
        let server_net = build_userspace_net(server_capture, &test_session(server_ip)).unwrap();
        client_net.routes_mut(|routes| {
            routes.add_default_ipv4_route(server_ip).unwrap();
        });
        server_net.routes_mut(|routes| {
            routes.add_default_ipv4_route(client_ip).unwrap();
        });

        let pumping = Arc::new(AtomicBool::new(true));
        let pump_running = Arc::clone(&pumping);
        let pump = std::thread::spawn(move || {
            let mut client_buffer = [0_u8; 4_096];
            let mut server_buffer = [0_u8; 4_096];
            while pump_running.load(Ordering::Acquire) {
                let mut moved = false;
                if let Ok(length) = client_device.read_packet(&mut client_buffer) {
                    server_device
                        .write_packet(&client_buffer[..length])
                        .unwrap();
                    moved = true;
                }
                if let Ok(length) = server_device.read_packet(&mut server_buffer) {
                    client_device
                        .write_packet(&server_buffer[..length])
                        .unwrap();
                    moved = true;
                }
                if !moved {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        });
        (client_net, server_net, pumping, pump)
    }

    #[test]
    fn validates_target_and_loopback_listener() {
        let config = ForwardConfig::new(
            "127.0.0.1:8080".parse().unwrap(),
            "tcp://db.example.test:5432",
            DnsConfig::new(DnsMode::Auto, Vec::new(), Duration::from_secs(3)).unwrap(),
            Vec::new(),
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(config.target.host, "db.example.test");
        assert_eq!(config.target.port, 5432);

        assert!(
            ForwardConfig::new(
                "0.0.0.0:8080".parse().unwrap(),
                "tcp://db.example.test:5432",
                DnsConfig::new(DnsMode::Auto, Vec::new(), Duration::from_secs(3)).unwrap(),
                Vec::new(),
                Duration::from_secs(10),
            )
            .is_err()
        );
        assert!(
            ForwardConfig::new(
                "127.0.0.1:8080".parse().unwrap(),
                "tcp://db.example.test:5432",
                DnsConfig::new(DnsMode::Auto, Vec::new(), Duration::from_secs(3)).unwrap(),
                Vec::new(),
                Duration::ZERO,
            )
            .is_err()
        );
        assert!(
            DnsConfig::new(
                DnsMode::Iwan,
                vec!["0.0.0.0:53".parse().unwrap()],
                Duration::from_secs(3),
            )
            .is_err()
        );
    }

    #[test]
    fn parses_domain_ipv4_and_bracketed_ipv6_targets() {
        let tcp = Target::parse("tcp://db.example.test:5432").unwrap();
        assert_eq!(tcp.scheme, TargetScheme::Tcp);
        assert_eq!(tcp.host, "db.example.test");
        assert_eq!(tcp.authority, "db.example.test:5432");
        assert_eq!(tcp.port, 5432);

        let ipv4 = Target::parse("tcp://192.0.2.25:22").unwrap();
        assert_eq!(ipv4.host, "192.0.2.25");
        assert_eq!(ipv4.port, 22);

        let ipv6 = Target::parse("tcp://[2001:db8::25]:443").unwrap();
        assert_eq!(ipv6.host, "2001:db8::25");
        assert_eq!(ipv6.port, 443);
        assert_eq!(ipv6.display(), "tcp://[2001:db8::25]:443");

        let http = Target::parse("http://example.test").unwrap();
        assert_eq!(http.scheme, TargetScheme::Http);
        assert_eq!(http.port, 80);
        assert_eq!(http.authority, "example.test");

        let https = Target::parse("https://example.test:8443").unwrap();
        assert_eq!(https.scheme, TargetScheme::Https);
        assert_eq!(https.port, 8443);
        assert_eq!(https.authority, "example.test:8443");

        for invalid in [
            "",
            "db.example.test",
            "db.example.test:5432",
            "http:example.test",
            "tcp://db.example.test",
            "tcp://db.example.test:5432/",
            "tcp://db.example.test:0",
            "udp://db.example.test:53",
            "http://user@example.test",
            "http://@example.test",
            "http://./",
            "http://example.test/path",
            "https://example.test?query=yes",
            "2001:db8::25:443",
            "tcp://0.0.0.0:80",
            "tcp://[ff02::1]:80",
        ] {
            assert!(Target::parse(invalid).is_err(), "{invalid:?} was accepted");
        }
    }

    #[test]
    fn identifies_common_vpn_fake_ip_range() {
        assert!(is_ipv4_benchmark_address("198.18.0.23".parse().unwrap()));
        assert!(is_ipv4_benchmark_address("198.19.255.254".parse().unwrap()));
        assert!(!is_ipv4_benchmark_address("198.20.0.1".parse().unwrap()));
        assert!(!is_ipv4_benchmark_address("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn enforces_connection_capacity_and_throttles_warnings() {
        let mut warning_active = false;
        assert_eq!(
            capacity_decision(MAX_CONNECTIONS - 1, &mut warning_active),
            CapacityDecision::Accept
        );
        assert_eq!(
            capacity_decision(MAX_CONNECTIONS, &mut warning_active),
            CapacityDecision::RejectAndWarn
        );
        assert!(warning_active);
        assert_eq!(
            capacity_decision(MAX_CONNECTIONS + 1, &mut warning_active),
            CapacityDecision::Reject
        );

        reset_capacity_warning(MAX_CONNECTIONS - 1, &mut warning_active);
        assert!(!warning_active);
        assert_eq!(
            capacity_decision(MAX_CONNECTIONS, &mut warning_active),
            CapacityDecision::RejectAndWarn
        );
    }

    #[test]
    fn channel_packet_device_preserves_packet_directions() {
        let (device, mut capture) = channel_packet_device(1_400);
        device.write_packet(&[0x45, 1, 2, 3]).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            use futures::{SinkExt, StreamExt};
            assert_eq!(capture.next().await.unwrap().unwrap(), vec![0x45, 1, 2, 3]);
            capture.send(vec![0x45, 4, 5, 6]).await.unwrap();
        });
        let mut buffer = [0_u8; 16];
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let length = loop {
            match device.read_packet(&mut buffer) {
                Ok(length) => break length,
                Err(error)
                    if error.kind() == ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("packet bridge failed: {error}"),
            }
        };
        assert_eq!(length, 4);
        assert_eq!(&buffer[..4], &[0x45, 4, 5, 6]);
    }

    #[test]
    fn validates_contiguous_ipv4_masks() {
        assert_eq!(
            ipv4_mask_prefix(Ipv4Addr::new(255, 255, 255, 0)).unwrap(),
            24
        );
        assert!(ipv4_mask_prefix(Ipv4Addr::new(255, 0, 255, 0)).is_err());
    }

    #[test]
    fn userspace_tcp_crosses_only_the_in_memory_packet_link() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let client_ip = Ipv4Addr::new(198, 18, 0, 1);
            let server_ip = Ipv4Addr::new(198, 18, 0, 2);
            let (client_net, server_net, pumping, pump) =
                linked_userspace_nets(client_ip, server_ip);

            let server_address = SocketAddr::new(server_ip.into(), 8_443);
            let mut listener = server_net.tcp_bind(server_address).await.unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 4];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"ping");
                stream.write_all(b"pong").await.unwrap();
                stream.flush().await.unwrap();
            });
            let mut stream = timeout(
                Duration::from_secs(2),
                client_net.tcp_connect(server_address),
            )
            .await
            .unwrap()
            .unwrap();
            stream.write_all(b"ping").await.unwrap();
            stream.flush().await.unwrap();
            let mut response = [0_u8; 4];
            timeout(Duration::from_secs(2), stream.read_exact(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&response, b"pong");
            server.await.unwrap();

            pumping.store(false, Ordering::Release);
            pump.join().unwrap();
        });
    }

    #[test]
    fn resolved_target_timeout_falls_back_to_the_next_address() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let client_ip = Ipv4Addr::new(198, 18, 0, 1);
            let blackhole_ip = Ipv4Addr::new(198, 18, 0, 250);
            let server_ip = Ipv4Addr::new(198, 18, 0, 200);
            let (client_net, server_net, pumping, pump) =
                linked_userspace_nets(client_ip, server_ip);
            let server_address = SocketAddr::new(server_ip.into(), 9_000);
            let mut listener = server_net.tcp_bind(server_address).await.unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 4];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"ping");
                stream.write_all(b"pong").await.unwrap();
                stream.flush().await.unwrap();
            });

            let connector = TcpConnector::new(
                client_net,
                &test_session(client_ip),
                ConnectorSettings {
                    target: Target::parse("tcp://service.example.test:9000").unwrap(),
                    dns_mode: DnsMode::Auto,
                    dns_servers: Vec::new(),
                    dns_timeout: Duration::from_secs(1),
                    timeout: Duration::from_secs(1),
                },
            );
            *connector.dns_cache.lock().await = Some(CachedResolution {
                addresses: vec![
                    SocketAddr::new(blackhole_ip.into(), 9_000),
                    SocketAddr::new(server_ip.into(), 9_000),
                ],
                source: ResolutionSource::SystemDns,
                expires_at: Instant::now() + Duration::from_secs(60),
            });
            assert_eq!(
                connector.resolve().await.unwrap().addresses,
                vec![
                    SocketAddr::new(blackhole_ip.into(), 9_000),
                    SocketAddr::new(server_ip.into(), 9_000),
                ]
            );
            let mut stream = timeout(Duration::from_secs(2), connector.connect())
                .await
                .unwrap()
                .unwrap();
            stream.write_all(b"ping").await.unwrap();
            stream.flush().await.unwrap();
            let mut response = [0_u8; 4];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"pong");
            server.await.unwrap();

            pumping.store(false, Ordering::Release);
            pump.join().unwrap();
        });
    }

    #[test]
    fn forwards_arbitrary_tcp_bytes_and_preserves_half_close() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let client_ip = Ipv4Addr::new(198, 18, 0, 1);
            let server_ip = Ipv4Addr::new(198, 18, 0, 2);
            let (client_net, server_net, pumping, pump) =
                linked_userspace_nets(client_ip, server_ip);
            let server_address = SocketAddr::new(server_ip.into(), 8_080);
            let mut listener = server_net.tcp_bind(server_address).await.unwrap();
            let request = (0_u32..70_000)
                .map(|value| (value.wrapping_mul(31) & 0xff) as u8)
                .collect::<Vec<_>>();
            let expected_request = request.clone();
            let response = vec![0, 0xff, 0x16, 0x03, 0x01, 0, 4, 1, 2, 3, 4];
            let expected_response = response.clone();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, expected_request);
                stream.write_all(&response).await.unwrap();
                stream.shutdown().await.unwrap();
            });

            let connector = TcpConnector::new(
                client_net,
                &test_session(client_ip),
                ConnectorSettings {
                    target: Target::parse(&format!("tcp://{server_ip}:8080")).unwrap(),
                    dns_mode: DnsMode::Auto,
                    dns_servers: Vec::new(),
                    dns_timeout: Duration::from_secs(1),
                    timeout: Duration::from_secs(2),
                },
            );

            let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let local_address = local_listener.local_addr().unwrap();
            let local_client = tokio::spawn(async move {
                let mut stream = tokio::net::TcpStream::connect(local_address).await.unwrap();
                stream.write_all(&request).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await.unwrap();
                received
            });
            let (mut local, _) = local_listener.accept().await.unwrap();
            let remote = connector.connect().await.unwrap();
            let relay =
                tokio::spawn(async move { relay_connection(&mut local, remote).await.unwrap() });

            let received = timeout(Duration::from_secs(5), local_client)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received, expected_response);
            timeout(Duration::from_secs(5), relay)
                .await
                .unwrap()
                .unwrap();
            timeout(Duration::from_secs(5), server)
                .await
                .unwrap()
                .unwrap();

            pumping.store(false, Ordering::Release);
            pump.join().unwrap();
        });
    }

    #[test]
    fn preserves_late_upload_when_target_half_closes_first() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let client_ip = Ipv4Addr::new(198, 18, 0, 1);
            let server_ip = Ipv4Addr::new(198, 18, 0, 2);
            let (client_net, server_net, pumping, pump) =
                linked_userspace_nets(client_ip, server_ip);
            let server_address = SocketAddr::new(server_ip.into(), 8_081);
            let mut listener = server_net.tcp_bind(server_address).await.unwrap();
            let request = (0_u32..200_000)
                .map(|value| (value.wrapping_mul(17) & 0xff) as u8)
                .collect::<Vec<_>>();
            let expected_request = request.clone();
            let response = [0xde, 0xad, 0xbe, 0xef];
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = RelayTcpStream::new(stream);
                stream.write_all(&response).await.unwrap();
                stream.shutdown().await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await.unwrap();
                received
            });

            let connector = TcpConnector::new(
                client_net,
                &test_session(client_ip),
                ConnectorSettings {
                    target: Target::parse(&format!("tcp://{server_ip}:8081")).unwrap(),
                    dns_mode: DnsMode::Auto,
                    dns_servers: Vec::new(),
                    dns_timeout: Duration::from_secs(1),
                    timeout: Duration::from_secs(2),
                },
            );
            let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let local_address = local_listener.local_addr().unwrap();
            let local_client = tokio::spawn(async move {
                let mut stream = tokio::net::TcpStream::connect(local_address).await.unwrap();
                let mut received = [0_u8; 4];
                stream.read_exact(&mut received).await.unwrap();
                assert_eq!(received, response);
                assert_eq!(stream.read(&mut [0_u8; 1]).await.unwrap(), 0);
                stream.write_all(&request).await.unwrap();
                stream.shutdown().await.unwrap();
            });
            let (mut local, _) = local_listener.accept().await.unwrap();
            let remote = connector.connect().await.unwrap();
            let relay =
                tokio::spawn(async move { relay_connection(&mut local, remote).await.unwrap() });

            timeout(Duration::from_secs(10), local_client)
                .await
                .unwrap()
                .unwrap();
            let received = timeout(Duration::from_secs(10), server)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received, expected_request);
            timeout(Duration::from_secs(10), relay)
                .await
                .unwrap()
                .unwrap();

            pumping.store(false, Ordering::Release);
            pump.join().unwrap();
        });
    }

    #[test]
    fn userspace_dns_uses_iwan_udp_and_tcp_fallback() {
        use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{RData, Record};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let client_ip = Ipv4Addr::new(198, 51, 100, 1);
            let server_ip = Ipv4Addr::new(198, 51, 100, 2);
            let answer_ip = Ipv4Addr::new(203, 0, 113, 25);
            let (client_net, server_net, pumping, pump) =
                linked_userspace_nets(client_ip, server_ip);

            let dns_address = SocketAddr::new(server_ip.into(), 53);
            let udp = server_net.udp_bind(dns_address).await.unwrap();
            let mut tcp = server_net.tcp_bind(dns_address).await.unwrap();
            let server = tokio::spawn(async move {
                let mut request_buffer = [0_u8; 1_024];
                let (request_length, peer) = udp.recv_from(&mut request_buffer).await.unwrap();
                let request = Message::from_vec(&request_buffer[..request_length]).unwrap();
                let query = request.queries()[0].clone();

                let mut truncated = Message::new();
                truncated
                    .set_id(request.id())
                    .set_message_type(MessageType::Response)
                    .set_op_code(OpCode::Query)
                    .set_response_code(ResponseCode::NoError)
                    .set_truncated(true)
                    .add_query(query);
                udp.send_to(&truncated.to_vec().unwrap(), peer)
                    .await
                    .unwrap();

                let (mut stream, _) = tcp.accept().await.unwrap();
                let tcp_length = usize::from(stream.read_u16().await.unwrap());
                let mut tcp_request = vec![0_u8; tcp_length];
                stream.read_exact(&mut tcp_request).await.unwrap();
                let tcp_request = Message::from_vec(&tcp_request).unwrap();
                let query = tcp_request.queries()[0].clone();
                let name = query.name().clone();
                let mut response = Message::new();
                response
                    .set_id(tcp_request.id())
                    .set_message_type(MessageType::Response)
                    .set_op_code(OpCode::Query)
                    .set_response_code(ResponseCode::NoError)
                    .add_query(query)
                    .add_answer(Record::from_rdata(name, 90, RData::A(A(answer_ip))));
                let response = response.to_vec().unwrap();
                stream
                    .write_all(&u16::try_from(response.len()).unwrap().to_be_bytes())
                    .await
                    .unwrap();
                stream.write_all(&response).await.unwrap();
                let _ = timeout(Duration::from_secs(1), stream.flush()).await;
            });

            let lookup = timeout(
                Duration::from_secs(5),
                dns::lookup(
                    &client_net,
                    dns_address,
                    "api.example.test",
                    true,
                    Duration::from_secs(2),
                    &AtomicU16::new(100),
                ),
            )
            .await;
            let server_result = timeout(Duration::from_secs(5), server).await;
            pumping.store(false, Ordering::Release);
            pump.join().unwrap();

            let lookup = lookup.unwrap().unwrap();
            server_result.unwrap().unwrap();
            assert_eq!(lookup.addresses, vec![IpAddr::V4(answer_ip)]);
            assert_eq!(lookup.ttl, Duration::from_secs(90));
        });
    }
}
