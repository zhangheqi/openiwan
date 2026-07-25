mod dns;

use bytes::Bytes;
use futures::{Future, Sink, Stream};
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::body::Incoming;
use hyper::header::{CONNECTION, HOST, HeaderName, HeaderValue, LOCATION};
use hyper::rt::{Read as HyperRead, ReadBufCursor, Write as HyperWrite};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response, StatusCode, Uri, Version};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::{Client as HttpClient, Error as HttpClientError};
use hyper_util::rt::{TokioExecutor, TokioIo};
use openiwan::{Client, ConnectedSession, Error, PacketDevice, Result, SessionEnd, SessionInfo};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::convert::Infallible;
use std::error::Error as StdError;
use std::fs::File;
use std::io::{self, BufReader, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, lookup_host};
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::mpsc::{
    Receiver as TokioReceiver, Sender as TokioSender, channel as tokio_channel,
    error::TryRecvError as TokioTryRecvError,
};
use tokio::task::{JoinError, JoinSet};
use tokio::time::{Instant, MissedTickBehavior, interval, timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_smoltcp::device::{AsyncDevice, DeviceCapabilities};
use tokio_smoltcp::smoltcp::iface;
use tokio_smoltcp::smoltcp::phy::Medium;
use tokio_smoltcp::smoltcp::wire::{HardwareAddress, IpAddress as SmolIpAddress, IpCidr};
use tokio_smoltcp::{BufferSize, Net, NetConfig, TcpStream as UserTcpStream};
use tokio_util::sync::{PollSendError, PollSender};
use tower_service::Service;
use tracing::{debug, info, warn};
use url::Url;

type BoxError = Box<dyn StdError + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;
type ProxyClient = HttpClient<IwanConnector, Incoming>;

const PACKET_QUEUE_CAPACITY: usize = 1_000;
const TCP_BUFFER_SIZE: usize = 64 * 1_024;
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

#[derive(Debug, Clone)]
pub struct HttpProxyConfig {
    listen: SocketAddr,
    upstream: Upstream,
    upstream_ips: Vec<IpAddr>,
    dns: DnsConfig,
    ca_certificates: Vec<PathBuf>,
    upstream_timeout: Duration,
}

impl HttpProxyConfig {
    pub fn new(
        listen: SocketAddr,
        upstream: &str,
        upstream_ips: Vec<IpAddr>,
        dns: DnsConfig,
        ca_certificates: Vec<PathBuf>,
        upstream_timeout: Duration,
    ) -> Result<Self> {
        if !listen.ip().is_loopback() {
            return Err(Error::InvalidConfig(format!(
                "HTTP proxy listen address {listen} is not a loopback address"
            )));
        }
        if upstream_timeout.is_zero() {
            return Err(Error::InvalidConfig(
                "upstream timeout must be greater than zero".into(),
            ));
        }
        if upstream_ips
            .iter()
            .any(|address| address.is_unspecified() || address.is_multicast())
        {
            return Err(Error::InvalidConfig(
                "fixed upstream IPs must be unicast, non-unspecified addresses".into(),
            ));
        }
        Ok(Self {
            listen,
            upstream: Upstream::parse(upstream)?,
            upstream_ips,
            dns,
            ca_certificates,
            upstream_timeout,
        })
    }
}

#[derive(Debug, Clone)]
struct Upstream {
    url: Url,
    host: String,
    authority: String,
    port: u16,
}

impl Upstream {
    fn parse(value: &str) -> Result<Self> {
        let url = Url::parse(value)
            .map_err(|error| Error::InvalidConfig(format!("invalid upstream URL: {error}")))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(Error::InvalidConfig(
                "upstream URL must use http or https".into(),
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Error::InvalidConfig(
                "upstream URL must not contain user information".into(),
            ));
        }
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(Error::InvalidConfig(
                "upstream URL must be an origin without a path, query, or fragment".into(),
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| Error::InvalidConfig("upstream URL has no host".into()))?
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| Error::InvalidConfig("upstream URL has no port".into()))?;
        let display_host = if host.parse::<Ipv6Addr>().is_ok() {
            format!("[{host}]")
        } else {
            host.clone()
        };
        let authority = url.port().map_or_else(
            || display_host.clone(),
            |port| format!("{display_host}:{port}"),
        );
        authority
            .parse::<hyper::http::uri::Authority>()
            .map_err(|error| {
                Error::InvalidConfig(format!("invalid upstream authority: {error}"))
            })?;
        Ok(Self {
            url,
            host,
            authority,
            port,
        })
    }

    fn request_uri(&self, incoming: &Uri) -> Result<Uri> {
        let path_and_query = incoming
            .path_and_query()
            .map_or("/", hyper::http::uri::PathAndQuery::as_str);
        Uri::builder()
            .scheme(self.url.scheme())
            .authority(self.authority.as_str())
            .path_and_query(path_and_query)
            .build()
            .map_err(|error| Error::Http(format!("build upstream request URI: {error}")))
    }

    fn uses_tls(&self) -> bool {
        self.url.scheme() == "https"
    }
}

pub fn run(
    client: Client,
    session: ConnectedSession,
    config: HttpProxyConfig,
    shutdown: Arc<AtomicBool>,
) -> Result<SessionEnd> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("openiwan-http")
        .build()
        .map_err(Error::Io)?;
    runtime.block_on(run_async(client, session, config, shutdown))
}

async fn run_async(
    client: Client,
    session: ConnectedSession,
    config: HttpProxyConfig,
    shutdown: Arc<AtomicBool>,
) -> Result<SessionEnd> {
    let session_info = session.info().clone();
    let (packet_device, capture) = channel_packet_device(session_info.mtu);
    let net = build_userspace_net(capture, &session_info)?;
    let tls = build_optional_tls(&config.upstream, &config.ca_certificates)?;
    let dns_servers = effective_dns_servers(&config.dns.servers, &session_info);
    let connector = IwanConnector::new(
        Arc::clone(&net),
        &session_info,
        ConnectorSettings {
            upstream: config.upstream.clone(),
            upstream_ips: config.upstream_ips,
            dns_mode: config.dns.mode,
            dns_servers,
            dns_timeout: config.dns.timeout,
            tls,
            timeout: config.upstream_timeout,
        },
    );
    let listener = TcpListener::bind(config.listen).await.map_err(Error::Io)?;
    let listen_address = listener.local_addr().map_err(Error::Io)?;

    let tunnel_shutdown = Arc::clone(&shutdown);
    let tunnel_device: Arc<dyn PacketDevice> = packet_device;
    let mut tunnel = tokio::task::spawn_blocking(move || {
        client.run_reconnecting_from(session, tunnel_device, tunnel_shutdown)
    });

    if let Some(end) = preflight_connector(&connector, &mut tunnel, &shutdown).await? {
        return Ok(end);
    }

    let http_client = HttpClient::builder(TokioExecutor::new()).build(connector);
    let proxy_state = Arc::new(ProxyState {
        client: http_client,
        upstream: config.upstream,
    });

    announce_proxy(listen_address, &proxy_state.upstream);

    let mut connections = JoinSet::new();
    let mut shutdown_check = interval(SHUTDOWN_POLL);
    shutdown_check.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut tunnel_result = None;
    let mut accept_error = None;

    loop {
        tokio::select! {
            result = &mut tunnel => {
                tunnel_result = Some(result);
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let state = Arc::clone(&proxy_state);
                        connections.spawn(async move {
                            let service = service_fn(move |request| {
                                proxy_request(request, Arc::clone(&state))
                            });
                            if let Err(error) = http1::Builder::new()
                                .keep_alive(true)
                                .serve_connection(TokioIo::new(stream), service)
                                .await
                            {
                                debug!(%peer, %error, "local HTTP connection ended with an error");
                            }
                        });
                    }
                    Err(error) => {
                        accept_error = Some(error);
                        break;
                    }
                }
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = joined {
                    warn!(%error, "local HTTP connection task failed");
                }
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
    info!(?end, "route-free HTTP proxy stopped");
    Ok(end)
}

fn build_optional_tls(
    upstream: &Upstream,
    ca_certificates: &[PathBuf],
) -> Result<Option<TlsConnector>> {
    upstream
        .uses_tls()
        .then(|| build_tls_connector(ca_certificates))
        .transpose()
}

fn announce_proxy(listen_address: SocketAddr, upstream: &Upstream) {
    println!(
        "HTTP proxy listening on http://{listen_address} -> {}",
        upstream.url
    );
    if !upstream.uses_tls() {
        println!("warning: HTTP upstream traffic is not protected by TLS");
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
    connector: &IwanConnector,
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
                warn!(%error, "local HTTP connection task failed during shutdown");
            }
        }
    })
    .await
    .is_err()
    {
        connections.abort_all();
    }
}

fn flatten_tunnel_result(
    result: std::result::Result<Result<SessionEnd>, JoinError>,
) -> Result<SessionEnd> {
    result.map_err(|error| Error::Http(format!("iWAN session task failed: {error}")))?
}

struct ChannelPacketDevice {
    incoming: TokioSender<io::Result<Vec<u8>>>,
    outgoing: Mutex<TokioReceiver<Vec<u8>>>,
}

impl PacketDevice for ChannelPacketDevice {
    fn name(&self) -> &'static str {
        "userspace-http"
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

fn build_tls_connector(ca_certificates: &[PathBuf]) -> Result<TlsConnector> {
    let native = rustls_native_certs::load_native_certs();
    for error in &native.errors {
        warn!(%error, "failed to load one native root certificate");
    }
    let mut roots = RootCertStore::empty();
    let (native_added, native_ignored) = roots.add_parsable_certificates(native.certs);
    if native_ignored > 0 {
        warn!(
            native_ignored,
            "ignored invalid certificates from native root store"
        );
    }

    let mut custom_added = 0_usize;
    for path in ca_certificates {
        let file = File::open(path).map_err(|error| {
            Error::InvalidConfig(format!("cannot open CA file {}: {error}", path.display()))
        })?;
        let mut reader = BufReader::new(file);
        let certificates = rustls_pemfile::certs(&mut reader)
            .collect::<io::Result<Vec<_>>>()
            .map_err(|error| {
                Error::InvalidConfig(format!("cannot parse CA file {}: {error}", path.display()))
            })?;
        if certificates.is_empty() {
            return Err(Error::InvalidConfig(format!(
                "CA file {} contains no certificates",
                path.display()
            )));
        }
        for certificate in certificates {
            roots.add(certificate).map_err(|error| {
                Error::InvalidConfig(format!(
                    "invalid certificate in CA file {}: {error}",
                    path.display()
                ))
            })?;
            custom_added += 1;
        }
    }
    if native_added + custom_added == 0 {
        return Err(Error::InvalidConfig(
            "no usable TLS root certificates were loaded".into(),
        ));
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| Error::Http(format!("select TLS protocol versions: {error}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(client_config)))
}

#[derive(Clone)]
struct IwanConnector {
    net: Arc<Net>,
    upstream: Upstream,
    upstream_ips: Arc<[IpAddr]>,
    dns_mode: DnsMode,
    dns_servers: Arc<[SocketAddr]>,
    dns_timeout: Duration,
    dns_cache: Arc<TokioMutex<Option<CachedResolution>>>,
    next_dns_id: Arc<AtomicU16>,
    tls: Option<TlsConnector>,
    timeout: Duration,
    ipv4: bool,
    synthetic_route: Arc<AtomicBool>,
}

struct ConnectorSettings {
    upstream: Upstream,
    upstream_ips: Vec<IpAddr>,
    dns_mode: DnsMode,
    dns_servers: Vec<SocketAddr>,
    dns_timeout: Duration,
    tls: Option<TlsConnector>,
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

impl IwanConnector {
    fn new(net: Arc<Net>, session: &SessionInfo, settings: ConnectorSettings) -> Self {
        let address = session
            .address
            .expect("authenticated session has an address");
        let seed = session_random_seed(session);
        Self {
            net,
            upstream: settings.upstream,
            upstream_ips: settings.upstream_ips.into(),
            dns_mode: settings.dns_mode,
            dns_servers: settings.dns_servers.into(),
            dns_timeout: settings.dns_timeout,
            dns_cache: Arc::new(TokioMutex::new(None)),
            next_dns_id: Arc::new(AtomicU16::new(seed as u16)),
            tls: settings.tls,
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
                    "DNS resolution for upstream {} timed out",
                    self.upstream.host
                ))
            })?
            .map_err(|error| {
                Error::InvalidConfig(format!(
                    "cannot resolve upstream {}: {error}",
                    self.upstream.host
                ))
            })?;
        if resolution.addresses.is_empty() {
            let family = if self.ipv4 { "IPv4" } else { "IPv6" };
            return Err(Error::InvalidConfig(format!(
                "upstream {} has no {family} address matching the iWAN session",
                self.upstream.host
            )));
        }
        match resolution.source {
            ResolutionSource::Fixed => {
                info!(
                    upstream = %self.upstream.host,
                    addresses = ?resolution.addresses,
                    "using fixed upstream address; DNS was bypassed"
                );
            }
            ResolutionSource::IwanDns(server) => {
                info!(
                    upstream = %self.upstream.host,
                    addresses = ?resolution.addresses,
                    %server,
                    "resolved upstream through iWAN DNS"
                );
            }
            ResolutionSource::SystemDns => {
                info!(
                    upstream = %self.upstream.host,
                    addresses = ?resolution.addresses,
                    "resolved upstream with the host DNS resolver"
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
                upstream = %self.upstream.host,
                addresses = ?resolution.addresses,
                "host DNS returned 198.18.0.0/15; this may be a VPN Fake-IP \
                 rather than the real upstream address"
            );
        }
        self.ensure_userspace_route(resolution.addresses[0].ip())
            .map_err(|error| Error::Http(format!("configure userspace route: {error}")))?;
        Ok(())
    }

    async fn resolve(&self) -> io::Result<CachedResolution> {
        if !self.upstream_ips.is_empty() {
            let mut addresses: Vec<_> = self
                .upstream_ips
                .iter()
                .copied()
                .map(|address| SocketAddr::new(address, self.upstream.port))
                .collect();
            self.normalize_addresses(&mut addresses);
            return Ok(CachedResolution {
                addresses,
                source: ResolutionSource::Fixed,
                expires_at: Instant::now() + MAX_DNS_TTL,
            });
        }
        if let Ok(address) = self.upstream.host.parse::<IpAddr>() {
            let mut addresses = vec![SocketAddr::new(address, self.upstream.port)];
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
                &self.upstream.host,
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
                        .map(|address| SocketAddr::new(address, self.upstream.port))
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
        let mut addresses: Vec<_> = lookup_host((self.upstream.host.as_str(), self.upstream.port))
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
        addresses.sort_unstable();
        addresses.dedup();
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

    async fn connect(&self, uri: &Uri) -> std::result::Result<IwanConnection, BoxError> {
        if uri.scheme_str() != Some(self.upstream.url.scheme())
            || uri.host() != Some(self.upstream.host.as_str())
            || uri.port_u16().unwrap_or(self.upstream.port) != self.upstream.port
        {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "proxy connector rejected a non-configured destination",
            )
            .into());
        }

        let server_name = self
            .upstream
            .uses_tls()
            .then(|| {
                ServerName::try_from(self.upstream.host.clone())
                    .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error.to_string()))
            })
            .transpose()?;
        let operation = async {
            let addresses = self.resolve().await?.addresses;
            if addresses.is_empty() {
                return Err(io::Error::new(
                    ErrorKind::AddrNotAvailable,
                    "upstream DNS result does not match the iWAN address family",
                ));
            }
            let mut last_error = None;
            for address in addresses {
                self.ensure_userspace_route(address.ip())?;
                match self.net.tcp_connect(address).await {
                    Ok(stream) => {
                        let Some(server_name) = server_name.clone() else {
                            return Ok(IwanConnection::Plain(TokioIo::new(stream)));
                        };
                        let tls = self
                            .tls
                            .as_ref()
                            .expect("HTTPS upstream has a TLS connector");
                        match tls.connect(server_name, stream).await {
                            Ok(stream) => {
                                return Ok(IwanConnection::Tls(Box::new(TokioIo::new(stream))));
                            }
                            Err(error) => last_error = Some(error),
                        }
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| {
                io::Error::new(
                    ErrorKind::AddrNotAvailable,
                    "upstream has no usable address",
                )
            }))
        };
        timeout(self.timeout, operation)
            .await
            .map_err(|_| io::Error::new(ErrorKind::TimedOut, "upstream connection timed out"))?
            .map_err(Into::into)
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

impl Service<Uri> for IwanConnector {
    type Response = IwanConnection;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        _context: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connector = self.clone();
        Box::pin(async move { connector.connect(&uri).await })
    }
}

enum IwanConnection {
    Plain(TokioIo<UserTcpStream>),
    Tls(Box<TokioIo<TlsStream<UserTcpStream>>>),
}

impl Connection for IwanConnection {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl HyperRead for IwanConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => HyperRead::poll_read(Pin::new(stream), context, buffer),
            Self::Tls(stream) => HyperRead::poll_read(Pin::new(stream.as_mut()), context, buffer),
        }
    }
}

impl HyperWrite for IwanConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => HyperWrite::poll_write(Pin::new(stream), context, buffer),
            Self::Tls(stream) => HyperWrite::poll_write(Pin::new(stream.as_mut()), context, buffer),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => HyperWrite::poll_flush(Pin::new(stream), context),
            Self::Tls(stream) => HyperWrite::poll_flush(Pin::new(stream.as_mut()), context),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => HyperWrite::poll_shutdown(Pin::new(stream), context),
            Self::Tls(stream) => HyperWrite::poll_shutdown(Pin::new(stream.as_mut()), context),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(stream) => HyperWrite::is_write_vectored(stream),
            Self::Tls(stream) => HyperWrite::is_write_vectored(stream.as_ref()),
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => {
                HyperWrite::poll_write_vectored(Pin::new(stream), context, buffers)
            }
            Self::Tls(stream) => {
                HyperWrite::poll_write_vectored(Pin::new(stream.as_mut()), context, buffers)
            }
        }
    }
}

struct ProxyState {
    client: ProxyClient,
    upstream: Upstream,
}

async fn proxy_request(
    mut request: Request<Incoming>,
    state: Arc<ProxyState>,
) -> std::result::Result<Response<ProxyBody>, Infallible> {
    let uri = match state.upstream.request_uri(request.uri()) {
        Ok(uri) => uri,
        Err(error) => {
            warn!(%error, "rejected malformed local HTTP request");
            return Ok(error_response(StatusCode::BAD_REQUEST));
        }
    };
    strip_hop_by_hop(request.headers_mut());
    let host = match HeaderValue::from_str(&state.upstream.authority) {
        Ok(host) => host,
        Err(error) => {
            warn!(%error, "configured upstream authority is not a valid Host header");
            return Ok(error_response(StatusCode::BAD_GATEWAY));
        }
    };
    request.headers_mut().insert(HOST, host);
    *request.uri_mut() = uri;
    *request.version_mut() = Version::HTTP_11;

    match state.client.request(request).await {
        Ok(mut response) => {
            strip_hop_by_hop(response.headers_mut());
            rewrite_location(response.headers_mut(), &state.upstream);
            Ok(response.map(|body| {
                body.map_err(|error| -> BoxError { Box::new(error) })
                    .boxed_unsync()
            }))
        }
        Err(error) => {
            let status = if is_timeout_error(&error) {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            };
            warn!(%error, "upstream request failed");
            Ok(error_response(status))
        }
    }
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let connection_headers = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect::<Vec<_>>();
    for name in connection_headers {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

fn rewrite_location(headers: &mut HeaderMap, upstream: &Upstream) {
    let Some(value) = headers.get(LOCATION) else {
        return;
    };
    let Ok(value) = value.to_str() else {
        return;
    };
    let Ok(location) = Url::parse(value) else {
        return;
    };
    if location.origin() != upstream.url.origin() {
        return;
    }
    let mut relative = location.path().to_owned();
    if let Some(query) = location.query() {
        relative.push('?');
        relative.push_str(query);
    }
    if let Some(fragment) = location.fragment() {
        relative.push('#');
        relative.push_str(fragment);
    }
    if let Ok(value) = HeaderValue::from_str(&relative) {
        headers.insert(LOCATION, value);
    }
}

fn is_timeout_error(error: &HttpClientError) -> bool {
    let mut current: Option<&(dyn StdError + 'static)> = Some(error);
    while let Some(error) = current {
        if error
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == ErrorKind::TimedOut)
        {
            return true;
        }
        current = error.source();
    }
    false
}

fn error_response(status: StatusCode) -> Response<ProxyBody> {
    let message = match status {
        StatusCode::BAD_REQUEST => "bad request\n",
        StatusCode::GATEWAY_TIMEOUT => "upstream connection timed out\n",
        _ => "upstream unavailable\n",
    };
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(
            Full::new(Bytes::from_static(message.as_bytes()))
                .map_err(|never| -> BoxError { match never {} })
                .boxed_unsync(),
        )
        .expect("static HTTP error response is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use openiwan::EncryptionMethod;

    fn test_session(address: Ipv4Addr) -> SessionInfo {
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

    fn linked_userspace_nets(
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
    fn validates_http_or_https_origin_and_loopback_listener() {
        let secure_config = HttpProxyConfig::new(
            "127.0.0.1:8080".parse().unwrap(),
            "https://api.example.test",
            Vec::new(),
            DnsConfig::new(DnsMode::Auto, Vec::new(), Duration::from_secs(3)).unwrap(),
            Vec::new(),
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(secure_config.upstream.authority, "api.example.test");
        assert!(secure_config.upstream.uses_tls());

        let plain_config = HttpProxyConfig::new(
            "127.0.0.1:8080".parse().unwrap(),
            "http://api.example.test",
            Vec::new(),
            DnsConfig::new(DnsMode::Auto, Vec::new(), Duration::from_secs(3)).unwrap(),
            Vec::new(),
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(plain_config.upstream.port, 80);
        assert!(!plain_config.upstream.uses_tls());

        assert!(
            HttpProxyConfig::new(
                "0.0.0.0:8080".parse().unwrap(),
                "https://api.example.test",
                Vec::new(),
                DnsConfig::new(DnsMode::Auto, Vec::new(), Duration::from_secs(3)).unwrap(),
                Vec::new(),
                Duration::from_secs(10),
            )
            .is_err()
        );
        assert!(
            HttpProxyConfig::new(
                "127.0.0.1:8080".parse().unwrap(),
                "ftp://api.example.test",
                Vec::new(),
                DnsConfig::new(DnsMode::Auto, Vec::new(), Duration::from_secs(3)).unwrap(),
                Vec::new(),
                Duration::from_secs(10),
            )
            .is_err()
        );
        assert!(
            HttpProxyConfig::new(
                "127.0.0.1:8080".parse().unwrap(),
                "https://api.example.test/base",
                Vec::new(),
                DnsConfig::new(DnsMode::Auto, Vec::new(), Duration::from_secs(3)).unwrap(),
                Vec::new(),
                Duration::from_secs(10),
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
    fn identifies_common_vpn_fake_ip_range() {
        assert!(is_ipv4_benchmark_address("198.18.0.23".parse().unwrap()));
        assert!(is_ipv4_benchmark_address("198.19.255.254".parse().unwrap()));
        assert!(!is_ipv4_benchmark_address("198.20.0.1".parse().unwrap()));
        assert!(!is_ipv4_benchmark_address("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn preserves_path_and_query_for_fixed_upstream() {
        let secure_origin = Upstream::parse("https://api.example.test:8443").unwrap();
        let uri = secure_origin
            .request_uri(&"/v1/items?limit=5".parse().unwrap())
            .unwrap();
        assert_eq!(
            uri,
            "https://api.example.test:8443/v1/items?limit=5"
                .parse::<Uri>()
                .unwrap()
        );

        let plain_origin = Upstream::parse("http://api.example.test:8080").unwrap();
        let uri = plain_origin
            .request_uri(&"/v1/items?limit=5".parse().unwrap())
            .unwrap();
        assert_eq!(
            uri,
            "http://api.example.test:8080/v1/items?limit=5"
                .parse::<Uri>()
                .unwrap()
        );
    }

    #[test]
    fn strips_hop_headers_and_connection_nominations() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, x-remove"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("x-remove", HeaderValue::from_static("yes"));
        headers.insert("authorization", HeaderValue::from_static("Bearer secret"));
        strip_hop_by_hop(&mut headers);
        assert!(!headers.contains_key(CONNECTION));
        assert!(!headers.contains_key("keep-alive"));
        assert!(!headers.contains_key("x-remove"));
        assert_eq!(headers["authorization"], "Bearer secret");
    }

    #[test]
    fn rewrites_only_same_origin_absolute_locations() {
        let upstream = Upstream::parse("https://api.example.test").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            LOCATION,
            HeaderValue::from_static("https://api.example.test/v2/items?next=1"),
        );
        rewrite_location(&mut headers, &upstream);
        assert_eq!(headers[LOCATION], "/v2/items?next=1");

        headers.insert(
            LOCATION,
            HeaderValue::from_static("https://login.example.test/authorize"),
        );
        rewrite_location(&mut headers, &upstream);
        assert_eq!(headers[LOCATION], "https://login.example.test/authorize");
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
    fn http_connector_sends_plain_http_over_userspace_tcp() {
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
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let service = service_fn(|request: Request<Incoming>| async move {
                    assert_eq!(request.uri().path(), "/health");
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ready"))))
                });
                let _ = http1::Builder::new()
                    .keep_alive(false)
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });

            let connector = IwanConnector::new(
                client_net,
                &test_session(client_ip),
                ConnectorSettings {
                    upstream: Upstream::parse("http://api.example.test:8080").unwrap(),
                    upstream_ips: vec![server_ip.into()],
                    dns_mode: DnsMode::Auto,
                    dns_servers: Vec::new(),
                    dns_timeout: Duration::from_secs(1),
                    tls: None,
                    timeout: Duration::from_secs(2),
                },
            );
            let http_client: HttpClient<IwanConnector, Full<Bytes>> =
                HttpClient::builder(TokioExecutor::new()).build(connector);
            let request = Request::builder()
                .uri("http://api.example.test:8080/health")
                .body(Full::new(Bytes::new()))
                .unwrap();
            let response = http_client.request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "ready"
            );
            server.await.unwrap();

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
