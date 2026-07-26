use crate::config::ClientConfig;
use crate::crypto::{self, DataCipher};
use crate::fragment::{Fragment, FragmentReassembler, trim_ip_packet};
use crate::protocol::{
    self, DecodedPacket, EncryptionMethod, PacketHeader, PacketType, Tlv, TlvType,
};
use crate::{Error, Result};
use std::collections::HashSet;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, trace, warn};
use zeroize::Zeroize;

/// A TUN-like source and sink of complete IPv4 or IPv6 packets.
///
/// Implementations should use nonblocking reads so a running session can shut
/// down promptly.
pub trait PacketDevice: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn read_packet(&self, buffer: &mut [u8]) -> std::io::Result<usize>;
    fn write_packet(&self, packet: &[u8]) -> std::io::Result<usize>;
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub peer: SocketAddr,
    pub session_id: u16,
    pub token: u32,
    pub encryption: EncryptionMethod,
    pub mtu: u16,
    pub address: Option<IpAddr>,
    pub gateway: Option<IpAddr>,
    pub netmask: Option<Ipv4Addr>,
    pub dns_servers: Vec<IpAddr>,
    pub duplicate_packets: bool,
    pub server_config: Option<Vec<u8>>,
}

impl SessionInfo {
    pub const fn header(&self, packet_type: PacketType) -> PacketHeader {
        PacketHeader::new(packet_type, self.encryption, self.session_id, self.token)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    LocalShutdown,
    ServerClose,
    HeartbeatTimeout,
    TransportFailure,
}

struct Credentials {
    username: String,
    password: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

#[derive(Debug)]
pub struct Client {
    config: ClientConfig,
    credentials: Credentials,
    first_hop_link: Option<u32>,
}

impl Client {
    pub fn new(
        config: ClientConfig,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self> {
        let credentials = Credentials {
            username: username.into(),
            password: password.into(),
        };
        if credentials.username.is_empty() {
            return Err(Error::InvalidConfig("username must not be empty".into()));
        }
        if credentials.password.is_empty() {
            return Err(Error::InvalidConfig("password must not be empty".into()));
        }
        config.validate()?;
        Ok(Self {
            config,
            credentials,
            first_hop_link: None,
        })
    }

    pub const fn with_first_hop_link(mut self, link: u32) -> Self {
        self.first_hop_link = Some(link);
        self
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub fn authenticate(&self) -> Result<ConnectedSession> {
        let peer = self.config.resolve_server()?;
        let bind_address = match peer {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind_address)?;
        socket.connect(peer)?;
        socket.set_read_timeout(Some(self.config.auth_timeout()))?;
        socket.set_write_timeout(Some(self.config.auth_timeout()))?;

        let nonce = random_u32()?;
        let open = protocol::build_open(
            &self.credentials.username,
            &self.credentials.password,
            self.config.mtu,
            self.config.encryption,
            self.first_hop_link,
            Some(nonce),
        )?;

        let mut receive_buffer = vec![0_u8; 65_535];
        for attempt in 1..=self.config.auth_attempts {
            debug!(attempt, peer = %peer, "sending OPEN");
            socket.send(&open)?;
            match socket.recv(&mut receive_buffer) {
                Ok(length) => {
                    let decoded = protocol::decode_packet(&receive_buffer[..length])?;
                    match decoded.header.packet_type {
                        PacketType::OpenReject => {
                            return Err(parse_rejection(&decoded.body));
                        }
                        PacketType::OpenAck => {
                            let info = parse_open_ack(
                                &decoded,
                                peer,
                                nonce,
                                self.config.mtu,
                                self.config.require_auth_verify_echo,
                            )?;
                            if info.encryption != self.config.encryption {
                                return Err(Error::InvalidConfig(format!(
                                    "server selected {} but client requested {}",
                                    info.encryption, self.config.encryption
                                )));
                            }
                            socket.set_read_timeout(Some(self.config.receive_poll()))?;
                            socket.set_write_timeout(Some(self.config.auth_timeout()))?;
                            let cipher = crypto::create_cipher(
                                info.encryption,
                                &self.credentials.username,
                                &self.credentials.password,
                                self.config.xor_key_bytes,
                            )?;
                            info!(
                                peer = %peer,
                                session_id = info.session_id,
                                encryption = %info.encryption,
                                "authentication succeeded"
                            );
                            return Ok(ConnectedSession {
                                socket: Arc::new(socket),
                                info,
                                cipher: Arc::from(cipher),
                                heartbeat_interval: self.config.heartbeat_interval(),
                                heartbeat_timeout: self.config.heartbeat_timeout(),
                                running: Arc::new(AtomicBool::new(true)),
                                close_sent: AtomicBool::new(false),
                            });
                        }
                        other => {
                            debug!(packet_type = %other, "ignoring packet during authentication");
                        }
                    }
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                {
                    debug!(attempt, "OPEN response timed out");
                }
                Err(error) => return Err(Error::Io(error)),
            }
        }
        Err(Error::Timeout("authentication"))
    }

    /// Authenticate and run sessions until a clean local/server shutdown or
    /// the configured reconnection budget is exhausted.
    pub fn run_reconnecting(
        &self,
        device: Arc<dyn PacketDevice>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<SessionEnd> {
        self.run_reconnecting_inner(None, device, shutdown)
    }

    /// Run an already-authenticated session, then reconnect on transient
    /// failures.
    ///
    /// This variant is intended for native TUN users that need the first
    /// [`SessionInfo`] to configure the interface. Reconnected sessions must
    /// retain the original address, gateway, netmask, and MTU; otherwise the
    /// method stops instead of continuing with stale interface state.
    pub fn run_reconnecting_from(
        &self,
        initial_session: ConnectedSession,
        device: Arc<dyn PacketDevice>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<SessionEnd> {
        self.run_reconnecting_inner(Some(initial_session), device, shutdown)
    }

    fn run_reconnecting_inner(
        &self,
        initial_session: Option<ConnectedSession>,
        device: Arc<dyn PacketDevice>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<SessionEnd> {
        let mut retry = 0_u32;
        let mut delay = Duration::from_millis(self.config.reconnect.initial_delay_ms);
        let expected_assignment = initial_session.as_ref().map(|session| session.info.clone());
        let mut pending_session = initial_session;
        loop {
            if shutdown.load(Ordering::Acquire) {
                return Ok(SessionEnd::LocalShutdown);
            }
            let authentication = pending_session
                .take()
                .map_or_else(|| self.authenticate(), Result::<ConnectedSession>::Ok);
            match authentication {
                Ok(session) => {
                    if let Some(expected) = &expected_assignment {
                        ensure_same_tun_assignment(expected, session.info())?;
                    }
                    let started = Instant::now();
                    let outcome = session.run(Arc::clone(&device), Arc::clone(&shutdown));
                    match outcome {
                        Ok(SessionEnd::LocalShutdown | SessionEnd::ServerClose) => return outcome,
                        Ok(SessionEnd::HeartbeatTimeout | SessionEnd::TransportFailure)
                        | Err(_) => {
                            if let Err(error) = &outcome {
                                warn!(%error, "session failed");
                            }
                        }
                    }
                    if started.elapsed() >= self.config.heartbeat_timeout() {
                        retry = 0;
                        delay = Duration::from_millis(self.config.reconnect.initial_delay_ms);
                    }
                }
                Err(
                    error @ (Error::AuthenticationRejected { .. }
                    | Error::AuthenticationVerifyMismatch),
                ) => return Err(error),
                Err(error) => warn!(%error, "connection attempt failed"),
            }

            retry += 1;
            if retry > self.config.reconnect.attempts {
                return Err(Error::Timeout("reconnection budget exhausted"));
            }
            wait_interruptibly(delay, &shutdown);
            delay = delay
                .saturating_mul(2)
                .min(Duration::from_millis(self.config.reconnect.max_delay_ms));
        }
    }
}

fn ensure_same_tun_assignment(expected: &SessionInfo, actual: &SessionInfo) -> Result<()> {
    if expected.address != actual.address
        || expected.gateway != actual.gateway
        || expected.netmask != actual.netmask
        || expected.mtu != actual.mtu
    {
        return Err(Error::InvalidConfig(format!(
            "server changed the tunnel assignment during reconnection: \
             expected address={:?}, gateway={:?}, netmask={:?}, mtu={}; \
             received address={:?}, gateway={:?}, netmask={:?}, mtu={}",
            expected.address,
            expected.gateway,
            expected.netmask,
            expected.mtu,
            actual.address,
            actual.gateway,
            actual.netmask,
            actual.mtu
        )));
    }
    Ok(())
}

pub struct ConnectedSession {
    socket: Arc<UdpSocket>,
    info: SessionInfo,
    cipher: Arc<dyn DataCipher>,
    heartbeat_interval: Duration,
    heartbeat_timeout: Duration,
    running: Arc<AtomicBool>,
    close_sent: AtomicBool,
}

impl fmt::Debug for ConnectedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectedSession")
            .field("info", &self.info)
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("heartbeat_timeout", &self.heartbeat_timeout)
            .finish_non_exhaustive()
    }
}

use std::fmt;

impl ConnectedSession {
    pub const fn info(&self) -> &SessionInfo {
        &self.info
    }

    pub fn shutdown(&self) {
        self.running.store(false, Ordering::Release);
    }

    /// Send CLOSE once and consume the authenticated session.
    pub fn close(self) -> Result<()> {
        self.running.store(false, Ordering::Release);
        self.send_close_once()
    }

    pub fn run(
        self,
        device: Arc<dyn PacketDevice>,
        external_shutdown: Arc<AtomicBool>,
    ) -> Result<SessionEnd> {
        let running = Arc::clone(&self.running);
        let (failure_tx, failure_rx) = mpsc::channel::<WorkerFailure>();
        let last_echo = Arc::new(Mutex::new(Instant::now()));

        let sender = spawn_packet_sender(
            Arc::clone(&self.socket),
            Arc::clone(&device),
            Arc::clone(&self.cipher),
            self.info.clone(),
            Arc::clone(&running),
            failure_tx.clone(),
        )?;
        let heartbeat = match spawn_heartbeat(
            Arc::clone(&self.socket),
            self.info.clone(),
            Arc::clone(&running),
            Arc::clone(&last_echo),
            self.heartbeat_interval,
            self.heartbeat_timeout,
            failure_tx,
        ) {
            Ok(handle) => handle,
            Err(error) => {
                running.store(false, Ordering::Release);
                let _ = sender.join();
                return Err(error);
            }
        };

        let mut reassemblers = [
            FragmentReassembler::default(),
            FragmentReassembler::default(),
        ];
        let mut buffer = vec![0_u8; 65_535];
        let outcome = 'receive: loop {
            if external_shutdown.load(Ordering::Acquire) || !running.load(Ordering::Acquire) {
                break 'receive SessionEnd::LocalShutdown;
            }
            if let Ok(failure) = failure_rx.try_recv() {
                break 'receive match failure {
                    WorkerFailure::HeartbeatTimeout => SessionEnd::HeartbeatTimeout,
                    WorkerFailure::Transport(error) => {
                        warn!(%error, "worker transport failure");
                        SessionEnd::TransportFailure
                    }
                };
            }

            match self.socket.recv(&mut buffer) {
                Ok(length) => {
                    trace!(length, "received UDP datagram");
                    let decoded = match protocol::decode_packet(&buffer[..length]) {
                        Ok(packet) => packet,
                        Err(error) => {
                            warn!(%error, "dropping malformed datagram");
                            continue;
                        }
                    };
                    if decoded.header.session_id != self.info.session_id
                        || decoded.header.token != self.info.token
                    {
                        warn!(
                            session_id = decoded.header.session_id,
                            token = decoded.header.token,
                            "dropping packet from a different session"
                        );
                        continue;
                    }
                    trace_session_packet(&decoded);
                    match self.process_packet(
                        &decoded,
                        device.as_ref(),
                        &last_echo,
                        &mut reassemblers,
                    ) {
                        Ok(PacketAction::Continue) => {}
                        Ok(PacketAction::ServerClose) => {
                            break 'receive SessionEnd::ServerClose;
                        }
                        Err(Error::Io(error)) => {
                            warn!(%error, "packet delivery failed");
                            break 'receive SessionEnd::TransportFailure;
                        }
                        Err(error) => {
                            warn_invalid_session_datagram(&decoded, &error);
                        }
                    }
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(error) => {
                    warn!(%error, "UDP receive failed");
                    break 'receive SessionEnd::TransportFailure;
                }
            }
        };

        running.store(false, Ordering::Release);
        let _ = self.send_close_once();
        let _ = sender.join();
        let _ = heartbeat.join();
        Ok(outcome)
    }

    fn process_packet(
        &self,
        packet: &DecodedPacket,
        device: &dyn PacketDevice,
        last_echo: &Mutex<Instant>,
        reassemblers: &mut [FragmentReassembler; 2],
    ) -> Result<PacketAction> {
        match packet.header.packet_type {
            PacketType::Data | PacketType::DataDup => {
                write_inner_packet(device, validate_inner_packet(&packet.body, Some(4))?)?;
            }
            PacketType::Data6 => {
                write_inner_packet(device, validate_inner_packet(&packet.body, Some(6))?)?;
            }
            PacketType::DataEncrypt | PacketType::DataEncDup => {
                if packet.header.encryption != self.cipher.method() {
                    return Err(Error::InvalidConfig(format!(
                        "packet encryption {} does not match session {}",
                        packet.header.encryption,
                        self.cipher.method()
                    )));
                }
                let plaintext = self.cipher.decrypt(&packet.body)?;
                let inner = validate_inner_packet(&plaintext, None)?;
                write_inner_packet(device, inner)?;
            }
            packet_type @ (PacketType::IpFrag | PacketType::IpFrag6) => {
                let fragment = Fragment::parse(&packet.body)?;
                let (reassembler, expected_version) = if packet_type == PacketType::IpFrag {
                    (&mut reassemblers[0], 4)
                } else {
                    (&mut reassemblers[1], 6)
                };
                if let Some(inner) = reassembler.insert(fragment, Instant::now())? {
                    let inner = validate_inner_packet(&inner, Some(expected_version))?;
                    write_inner_packet(device, inner)?;
                }
            }
            PacketType::EchoResponse => {
                let response = protocol::parse_echo_response(&packet.body)?;
                *last_echo
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
                if let Some(stats) = response.delay_stats {
                    debug!(
                        sent_at = response.timestamp_micros,
                        current_delay_micros = stats.current_micros,
                        min_delay_micros = stats.minimum_micros,
                        max_delay_micros = stats.maximum_micros,
                        "heartbeat response"
                    );
                } else {
                    debug!(
                        sent_at = response.timestamp_micros,
                        "compact heartbeat response"
                    );
                }
            }
            PacketType::EchoRequest => {
                if packet.body.len() < 8 {
                    return Err(Error::PacketTooShort {
                        minimum: 8,
                        actual: packet.body.len(),
                    });
                }
                let timestamp =
                    u64::from_be_bytes(packet.body[..8].try_into().expect("length checked"));
                let response = protocol::build_echo_response(packet.header, timestamp, 0, 0, 0);
                self.socket.send(&response)?;
            }
            PacketType::Close => return Ok(PacketAction::ServerClose),
            PacketType::PingRequest => {
                let response = protocol::encode_control(
                    PacketHeader::new(
                        PacketType::PingResponse,
                        packet.header.encryption,
                        packet.header.session_id,
                        packet.header.token,
                    ),
                    &[],
                );
                self.socket.send(&response)?;
            }
            PacketType::PingResponse => {}
            PacketType::Open | PacketType::OpenAck | PacketType::OpenReject | PacketType::SegRt => {
                debug!(packet_type = %packet.header.packet_type, "ignoring unexpected packet");
            }
        }
        Ok(PacketAction::Continue)
    }

    fn send_close_once(&self) -> Result<()> {
        if !self.close_sent.swap(true, Ordering::AcqRel) {
            self.socket
                .send(&protocol::build_close(self.info.header(PacketType::Close)))?;
        }
        Ok(())
    }
}

impl Drop for ConnectedSession {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        let _ = self.send_close_once();
    }
}

#[derive(Debug, Clone, Copy)]
enum PacketAction {
    Continue,
    ServerClose,
}

#[derive(Debug)]
enum WorkerFailure {
    HeartbeatTimeout,
    Transport(std::io::Error),
}

fn warn_invalid_session_datagram(packet: &DecodedPacket, error: &Error) {
    warn!(
        packet_type = %packet.header.packet_type,
        body_length = packet.body.len(),
        %error,
        "dropping invalid session datagram"
    );
}

fn trace_session_packet(packet: &DecodedPacket) {
    trace!(
        packet_type = %packet.header.packet_type,
        body_length = packet.body.len(),
        "received session packet"
    );
}

fn spawn_packet_sender(
    socket: Arc<UdpSocket>,
    device: Arc<dyn PacketDevice>,
    cipher: Arc<dyn DataCipher>,
    info: SessionInfo,
    running: Arc<AtomicBool>,
    failures: mpsc::Sender<WorkerFailure>,
) -> Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("openiwan-packet-sender".into())
        .spawn(move || {
            let mut buffer = vec![0_u8; usize::from(info.mtu).max(2_048) + 64];
            while running.load(Ordering::Acquire) {
                let length = match device.read_packet(&mut buffer) {
                    Ok(0) => continue,
                    Ok(length) => length,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    Err(error) => {
                        let _ = failures.send(WorkerFailure::Transport(error));
                        break;
                    }
                };
                let inner = match validate_inner_packet(&buffer[..length], None) {
                    Ok(packet) if packet.len() <= usize::from(info.mtu) => packet,
                    Ok(packet) => {
                        warn!(
                            length = packet.len(),
                            mtu = info.mtu,
                            "dropping oversized TUN packet"
                        );
                        continue;
                    }
                    Err(error) => {
                        warn!(%error, "dropping malformed TUN packet");
                        continue;
                    }
                };
                let (packet_type, payload) = match info.encryption {
                    EncryptionMethod::None => {
                        let packet_type = if inner.first().is_some_and(|byte| byte >> 4 == 6) {
                            PacketType::Data6
                        } else {
                            PacketType::Data
                        };
                        (packet_type, inner.to_vec())
                    }
                    EncryptionMethod::Xor | EncryptionMethod::Aes => match cipher.encrypt(inner) {
                        Ok(payload) => (PacketType::DataEncrypt, payload),
                        Err(error) => {
                            warn!(%error, "data encryption failed");
                            continue;
                        }
                    },
                };
                let datagram = protocol::encode_data(info.header(packet_type), &payload);
                match socket.send(&datagram) {
                    Ok(length) => trace!(
                        packet_type = %packet_type,
                        inner_length = inner.len(),
                        datagram_length = length,
                        "sent TUN packet"
                    ),
                    Err(error) => {
                        let _ = failures.send(WorkerFailure::Transport(error));
                        break;
                    }
                }
            }
        })
        .map_err(Error::Io)
}

fn spawn_heartbeat(
    socket: Arc<UdpSocket>,
    info: SessionInfo,
    running: Arc<AtomicBool>,
    last_echo: Arc<Mutex<Instant>>,
    interval: Duration,
    timeout: Duration,
    failures: mpsc::Sender<WorkerFailure>,
) -> Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("openiwan-heartbeat".into())
        .spawn(move || {
            while running.load(Ordering::Acquire) {
                wait_interruptibly(interval, &running);
                if !running.load(Ordering::Acquire) {
                    break;
                }
                let elapsed = last_echo
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .elapsed();
                if elapsed > timeout {
                    let _ = failures.send(WorkerFailure::HeartbeatTimeout);
                    running.store(false, Ordering::Release);
                    break;
                }
                let packet = protocol::build_echo_request(
                    info.header(PacketType::EchoRequest),
                    unix_time_micros(),
                );
                if let Err(error) = socket.send(&packet) {
                    let _ = failures.send(WorkerFailure::Transport(error));
                    running.store(false, Ordering::Release);
                    break;
                }
            }
        })
        .map_err(Error::Io)
}

fn write_inner_packet(device: &dyn PacketDevice, packet: &[u8]) -> Result<()> {
    let written = device.write_packet(packet)?;
    if written != packet.len() {
        return Err(Error::Io(std::io::Error::new(
            ErrorKind::WriteZero,
            format!("short TUN write: {written}/{}", packet.len()),
        )));
    }
    Ok(())
}

fn validate_inner_packet(packet: &[u8], expected_version: Option<u8>) -> Result<&[u8]> {
    let packet = trim_ip_packet(packet)?;
    if let Some(expected) = expected_version
        && packet[0] >> 4 != expected
    {
        return Err(Error::InvalidFragment(
            "inner IP version does not match packet type",
        ));
    }
    Ok(packet)
}

fn parse_open_ack(
    packet: &DecodedPacket,
    peer: SocketAddr,
    expected_nonce: u32,
    requested_mtu: u16,
    require_auth_verify_echo: bool,
) -> Result<SessionInfo> {
    if packet.header.session_id == 0 {
        return Err(Error::InvalidConfig(
            "OPENACK returned a zero session ID".into(),
        ));
    }
    let attributes = Tlv::parse_all(&packet.body)?;
    if let Some(attribute) = protocol::find_tlv(&attributes, TlvType::AuthVerify) {
        if attribute.as_u32()? != expected_nonce {
            return Err(Error::AuthenticationVerifyMismatch);
        }
    } else if require_auth_verify_echo {
        return Err(Error::MissingTlv("AUTH_VERIFY"));
    } else {
        debug!("OPENACK omitted optional AUTH_VERIFY echo");
    }
    if let Some(attribute) = protocol::find_tlv(&attributes, TlvType::Encrypt) {
        let advertised = EncryptionMethod::try_from(attribute.as_u8()?)?;
        if advertised != packet.header.encryption {
            return Err(Error::InvalidConfig(format!(
                "OPENACK encryption TLV {advertised} does not match header {}",
                packet.header.encryption
            )));
        }
    }

    let mtu = protocol::find_tlv(&attributes, TlvType::Mtu)
        .map(Tlv::as_u16)
        .transpose()?
        .filter(|mtu| (576..=9_000).contains(mtu))
        .unwrap_or(requested_mtu);
    let address = parse_address(
        protocol::find_tlv(&attributes, TlvType::Ip),
        protocol::find_tlv(&attributes, TlvType::Ip6),
    )?;
    let gateway = parse_address(
        protocol::find_tlv(&attributes, TlvType::Gateway),
        protocol::find_tlv(&attributes, TlvType::Gateway6),
    )?;
    let netmask = protocol::find_tlv(&attributes, TlvType::Netmask)
        .map(Tlv::as_ipv4)
        .transpose()?;

    let mut dns_servers = Vec::new();
    if let Some(dns) = protocol::find_tlv(&attributes, TlvType::Dns) {
        if dns.value.len() % 4 != 0 {
            return Err(Error::InvalidTlvValue(TlvType::Dns.name()));
        }
        dns_servers.extend(
            dns.value
                .chunks_exact(4)
                .map(|bytes| IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))),
        );
    }
    if let Some(dns6) = protocol::find_tlv(&attributes, TlvType::Dns6) {
        if dns6.value.len() % 16 != 0 {
            return Err(Error::InvalidTlvValue(TlvType::Dns6.name()));
        }
        for bytes in dns6.value.chunks_exact(16) {
            let octets: [u8; 16] = bytes.try_into().expect("chunk length is 16");
            dns_servers.push(IpAddr::V6(Ipv6Addr::from(octets)));
        }
    }
    dns_servers.retain(|address| !address.is_unspecified() && !address.is_multicast());
    let mut seen_dns_servers = HashSet::new();
    dns_servers.retain(|address| seen_dns_servers.insert(*address));

    Ok(SessionInfo {
        peer,
        session_id: packet.header.session_id,
        token: packet.header.token,
        encryption: packet.header.encryption,
        mtu,
        address,
        gateway,
        netmask,
        dns_servers,
        duplicate_packets: protocol::find_tlv(&attributes, TlvType::DupPacket)
            .map(Tlv::as_u8)
            .transpose()?
            .is_some_and(|value| value != 0),
        server_config: protocol::find_tlv(&attributes, TlvType::ServerConfig)
            .map(|attribute| attribute.value.clone()),
    })
}

fn parse_address(v4: Option<&Tlv>, v6: Option<&Tlv>) -> Result<Option<IpAddr>> {
    if let Some(attribute) = v4 {
        return attribute.as_ipv4().map(IpAddr::V4).map(Some);
    }
    if let Some(attribute) = v6 {
        return attribute.as_ipv6().map(IpAddr::V6).map(Some);
    }
    Ok(None)
}

fn parse_rejection(body: &[u8]) -> Error {
    if let Ok(attributes) = Tlv::parse_all(body) {
        let code = protocol::find_tlv(&attributes, TlvType::RejectReason)
            .and_then(|attribute| attribute.value.first())
            .copied()
            .unwrap_or(0);
        let message = attributes
            .iter()
            .find(|attribute| attribute.kind == TlvType::ServerConfig)
            .and_then(|attribute| String::from_utf8(attribute.value.clone()).ok())
            .unwrap_or_else(|| "server rejected OPEN".into());
        return Error::AuthenticationRejected { code, message };
    }
    let (code, message) = body
        .split_first()
        .map_or((0, "server rejected OPEN".into()), |(code, message)| {
            (*code, String::from_utf8_lossy(message).into_owned())
        });
    Error::AuthenticationRejected { code, message }
}

pub fn ping(server: SocketAddr, timeout: Duration) -> Result<Duration> {
    let bind_address = match server {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_address)?;
    socket.connect(server)?;
    socket.set_read_timeout(Some(timeout))?;
    let packet = protocol::build_ping_request();
    let started = Instant::now();
    socket.send(&packet)?;
    let mut buffer = [0_u8; 2_048];
    let length = socket.recv(&mut buffer).map_err(|error| {
        if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) {
            Error::Timeout("ping")
        } else {
            Error::Io(error)
        }
    })?;
    let response = protocol::decode_packet(&buffer[..length])?;
    if response.header.packet_type != PacketType::PingResponse
        || response.header.encryption != EncryptionMethod::None
        || response.header.session_id != 0
        || response.header.token != 0
        || !response.body.is_empty()
    {
        return Err(Error::InvalidPingResponse);
    }
    Ok(started.elapsed())
}

fn random_u32() -> Result<u32> {
    loop {
        let value =
            getrandom::u32().map_err(|_| Error::Crypto("system randomness is unavailable"))?;
        if value != 0 {
            return Ok(value);
        }
    }
}

fn unix_time_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn wait_interruptibly(duration: Duration, running: &AtomicBool) {
    let started = Instant::now();
    while running.load(Ordering::Acquire) && started.elapsed() < duration {
        let remaining = duration.saturating_sub(started.elapsed());
        thread::sleep(remaining.min(Duration::from_millis(100)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Tlv, encode_control};
    use std::thread;

    #[test]
    fn rejection_fallback_is_safe_for_non_tlv_body() {
        let error = parse_rejection(b"\x07bad password");
        assert!(matches!(
            error,
            Error::AuthenticationRejected { code: 7, .. }
        ));
    }

    #[test]
    fn debug_output_redacts_password() {
        let client = Client::new(
            ClientConfig::new("127.0.0.1:6001", true, 16),
            "alice",
            "very-secret",
        )
        .unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("very-secret"));
    }

    #[test]
    fn auth_verify_echo_can_be_optional_but_never_mismatched() {
        let header = PacketHeader::new(
            PacketType::OpenAck,
            EncryptionMethod::Xor,
            0x1234,
            0x5060_7080,
        );
        let without_echo = protocol::decode_packet(&encode_control(header, &[])).unwrap();
        let peer = "127.0.0.1:6001".parse().unwrap();
        assert!(matches!(
            parse_open_ack(&without_echo, peer, 0x0102_0304, 1400, true),
            Err(Error::MissingTlv("AUTH_VERIFY"))
        ));
        assert!(parse_open_ack(&without_echo, peer, 0x0102_0304, 1400, false).is_ok());

        let mut body = Vec::new();
        Tlv::auth_verify(0xaabb_ccdd).encode(&mut body).unwrap();
        let mismatched = protocol::decode_packet(&encode_control(header, &body)).unwrap();
        assert!(matches!(
            parse_open_ack(&mismatched, peer, 0x0102_0304, 1400, false),
            Err(Error::AuthenticationVerifyMismatch)
        ));
    }

    #[test]
    fn authenticates_against_local_compatible_endpoint() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let server_address = server.local_addr().unwrap();
        let endpoint = thread::spawn(move || {
            let mut buffer = [0_u8; 2_048];
            let (length, peer) = server.recv_from(&mut buffer).unwrap();
            let open = protocol::decode_packet(&buffer[..length]).unwrap();
            assert_eq!(open.header.packet_type, PacketType::Open);
            let attributes = Tlv::parse_all(&open.body).unwrap();
            let nonce = protocol::find_tlv(&attributes, TlvType::AuthVerify)
                .unwrap()
                .as_u32()
                .unwrap();

            let response_attributes = [
                Tlv::mtu(1400),
                Tlv::new(TlvType::Ip, [10, 64, 0, 2]).unwrap(),
                Tlv::new(TlvType::Gateway, [10, 64, 0, 1]).unwrap(),
                Tlv::new(TlvType::Dns, [0, 0, 0, 0, 1, 1, 1, 1]).unwrap(),
                Tlv::auth_verify(nonce),
            ];
            let mut body = Vec::new();
            for attribute in response_attributes {
                attribute.encode(&mut body).unwrap();
            }
            let response = encode_control(
                PacketHeader::new(
                    PacketType::OpenAck,
                    open.header.encryption,
                    0x1234,
                    0x5060_7080,
                ),
                &body,
            );
            server.send_to(&response, peer).unwrap();

            let (length, close_peer) = server.recv_from(&mut buffer).unwrap();
            assert_eq!(close_peer, peer);
            let close = protocol::decode_packet(&buffer[..length]).unwrap();
            assert_eq!(close.header.packet_type, PacketType::Close);
            assert_eq!(close.header.session_id, 0x1234);
            assert_eq!(close.header.token, 0x5060_7080);
        });

        let mut config = ClientConfig::new(server_address.to_string(), true, 16);
        config.auth_timeout_ms = 1_000;
        config.auth_attempts = 1;
        let session = Client::new(config, "alice", "secret")
            .unwrap()
            .authenticate()
            .unwrap();
        assert_eq!(session.info().session_id, 0x1234);
        assert_eq!(
            session.info().address,
            Some(IpAddr::V4(Ipv4Addr::new(10, 64, 0, 2)))
        );
        assert_eq!(
            session.info().dns_servers,
            [IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]
        );
        session.close().unwrap();
        endpoint.join().unwrap();
    }
}
