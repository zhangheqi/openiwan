use crate::config::{ClientConfig, SegmentRoutingConfig};
use crate::crypto::{self, DataCipher};
use crate::fragment::{Fragment, LegacyFragmentReassembler, SrFragmentReassembler, trim_ip_packet};
use crate::protocol::{
    self, DecodedPacket, EchoBody, EchoDelayStats, EncryptionMethod, PacketHeader, PacketType, Tlv,
    TlvType,
};
use crate::sr::{
    self, SrDecoded, SrMonitor, SrMonitorResponder, SrMonitorState, SrOuterCipher, SrSessionTuple,
};
use crate::{Error, Result};
use std::fmt;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};
use zeroize::Zeroize;

const AUTH_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);
const AUTH_OVERALL_TIMEOUT: Duration = Duration::from_secs(13);
const AUTH_RETRY_DELAY: Duration = Duration::from_secs(1);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(20);
const HEARTBEAT_MAX_MISSES: u32 = 10;

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
    pub dns_servers: Vec<IpAddr>,
    pub segment_routing: bool,
}

impl SessionInfo {
    pub const fn header(&self, packet_type: PacketType) -> PacketHeader {
        PacketHeader::new(packet_type, self.encryption, self.session_id, self.token)
    }

    const fn sr_tuple(&self) -> SrSessionTuple {
        SrSessionTuple {
            session_id: self.session_id,
            token: self.token,
            encryption: self.encryption,
        }
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
        config.validate()?;
        Ok(Self {
            config,
            credentials,
        })
    }

    pub const fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub fn authenticate(&self) -> Result<ConnectedSession> {
        self.authenticate_with_budget(AUTH_OVERALL_TIMEOUT)
    }

    /// One-shot authentication probe retained by the APK.
    pub fn authenticate_once(&self) -> Result<ConnectedSession> {
        self.authenticate_with_budget(AUTH_ATTEMPT_TIMEOUT)
    }

    fn authenticate_with_budget(&self, overall_timeout: Duration) -> Result<ConnectedSession> {
        let peer = self.config.resolve_server()?;
        let bind_address = match peer {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind_address)?;
        socket.connect(peer)?;
        socket.set_read_timeout(Some(AUTH_ATTEMPT_TIMEOUT))?;
        socket.set_write_timeout(Some(AUTH_ATTEMPT_TIMEOUT))?;

        let nonce = random_nonzero_u32()?;
        let first_hop = self
            .config
            .segment_routing
            .as_ref()
            .and_then(|sr| sr.links.first().copied());
        let open = protocol::build_open(
            &self.credentials.username,
            &self.credentials.password,
            self.config.mtu,
            self.config.encryption,
            first_hop,
            Some(nonce),
        )?;

        let started = Instant::now();
        let mut attempt = 0_u32;
        let mut receive_buffer = vec![0_u8; 65_535];
        loop {
            attempt = attempt.saturating_add(1);
            debug!(attempt, peer = %peer, "sending OPEN");
            socket.send(&open)?;
            match socket.recv(&mut receive_buffer) {
                Ok(length) => {
                    let decoded = protocol::decode_packet(&receive_buffer[..length])?;
                    match decoded.header.packet_type {
                        PacketType::OpenReject => {
                            return Err(parse_rejection(&decoded.body, nonce)?);
                        }
                        PacketType::OpenAck => {
                            let mut info = parse_open_ack(&decoded, peer, nonce, self.config.mtu)?;
                            info.segment_routing = self.config.segment_routing.is_some();
                            socket.set_read_timeout(Some(self.config.receive_poll()))?;
                            socket.set_write_timeout(Some(AUTH_ATTEMPT_TIMEOUT))?;
                            let cipher = crypto::create_cipher(
                                info.encryption,
                                &self.credentials.username,
                                &self.credentials.password,
                            )?;
                            let sr_runtime = self
                                .config
                                .segment_routing
                                .as_ref()
                                .map(SrRuntime::new)
                                .transpose()?;
                            info!(
                                peer = %peer,
                                session_id = info.session_id,
                                encryption = %info.encryption,
                                segment_routing = info.segment_routing,
                                "authentication succeeded"
                            );
                            return Ok(ConnectedSession {
                                socket: Arc::new(socket),
                                info,
                                cipher: Arc::from(cipher),
                                sr: sr_runtime.map(Arc::new),
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

            if overall_timeout <= AUTH_ATTEMPT_TIMEOUT
                || started.elapsed().saturating_add(AUTH_RETRY_DELAY) >= overall_timeout
            {
                return Err(Error::Timeout("authentication"));
            }
            thread::sleep(AUTH_RETRY_DELAY);
        }
    }

    pub fn run_reconnecting(
        &self,
        device: Arc<dyn PacketDevice>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<SessionEnd> {
        self.run_reconnecting_inner(None, device, shutdown)
    }

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
                    match session.run(Arc::clone(&device), Arc::clone(&shutdown)) {
                        Ok(SessionEnd::LocalShutdown) => return Ok(SessionEnd::LocalShutdown),
                        Ok(SessionEnd::ServerClose) => return Ok(SessionEnd::ServerClose),
                        Ok(end) => {
                            if started.elapsed() >= HEARTBEAT_TIMEOUT {
                                retry = 0;
                                delay =
                                    Duration::from_millis(self.config.reconnect.initial_delay_ms);
                            }
                            debug!(?end, "session ended; reconnecting");
                        }
                        Err(error) => warn!(%error, "session failed"),
                    }
                }
                Err(error) => warn!(%error, "connection attempt failed"),
            }
            if retry >= self.config.reconnect.attempts {
                return Err(Error::Timeout("reconnection budget exhausted"));
            }
            retry += 1;
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
        || expected.mtu != actual.mtu
        || expected.segment_routing != actual.segment_routing
    {
        return Err(Error::InvalidConfig(format!(
            "server changed the tunnel assignment during reconnection: \
             expected address={:?}, gateway={:?}, mtu={}, sr={}; \
             received address={:?}, gateway={:?}, mtu={}, sr={}",
            expected.address,
            expected.gateway,
            expected.mtu,
            expected.segment_routing,
            actual.address,
            actual.gateway,
            actual.mtu,
            actual.segment_routing,
        )));
    }
    Ok(())
}

struct SrRuntime {
    config: SegmentRoutingConfig,
    outer_cipher: SrOuterCipher,
    fragment_id: AtomicU32,
}

impl std::fmt::Debug for SrRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SrRuntime")
            .field("config", &self.config)
            .field("outer_cipher", &self.outer_cipher)
            .finish_non_exhaustive()
    }
}

impl SrRuntime {
    fn new(config: &SegmentRoutingConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            outer_cipher: SrOuterCipher::new(config.encrypt_algo, &config.encrypt_key)?,
            fragment_id: AtomicU32::new(random_nonzero_u32()?),
        })
    }

    fn next_fragment_id(&self) -> u32 {
        self.fragment_id.fetch_add(1, Ordering::Relaxed)
    }
}

pub struct ConnectedSession {
    socket: Arc<UdpSocket>,
    info: SessionInfo,
    cipher: Arc<dyn DataCipher>,
    sr: Option<Arc<SrRuntime>>,
    running: Arc<AtomicBool>,
    close_sent: AtomicBool,
}

impl fmt::Debug for ConnectedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectedSession")
            .field("info", &self.info)
            .field("segment_routing", &self.sr.is_some())
            .finish_non_exhaustive()
    }
}

impl ConnectedSession {
    pub const fn info(&self) -> &SessionInfo {
        &self.info
    }

    pub fn shutdown(&self) {
        self.running.store(false, Ordering::Release);
    }

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
        let monotonic_origin = Instant::now();
        let heartbeat = Arc::new(Mutex::new(HeartbeatTracker::new()));
        let sr_monitor = self
            .sr
            .as_ref()
            .map(|runtime| Arc::new(Mutex::new(SrMonitor::new(runtime.config.monitor_sr_id()))));

        let sender = spawn_packet_sender(
            Arc::clone(&self.socket),
            Arc::clone(&device),
            Arc::clone(&self.cipher),
            self.info.clone(),
            self.sr.clone(),
            Arc::clone(&running),
            failure_tx.clone(),
        )?;
        let heartbeat_worker =
            if let (Some(runtime), Some(monitor)) = (self.sr.as_ref(), sr_monitor.as_ref()) {
                if runtime.config.keepalive {
                    Some(spawn_sr_monitor(
                        Arc::clone(&self.socket),
                        self.info.clone(),
                        Arc::clone(runtime),
                        Arc::clone(monitor),
                        Arc::clone(&running),
                        monotonic_origin,
                        failure_tx.clone(),
                    )?)
                } else {
                    None
                }
            } else {
                Some(spawn_traditional_heartbeat(
                    Arc::clone(&self.socket),
                    self.info.clone(),
                    Arc::clone(&heartbeat),
                    Arc::clone(&running),
                    monotonic_origin,
                    failure_tx,
                )?)
            };

        let outcome = self.receive_loop(
            device.as_ref(),
            external_shutdown.as_ref(),
            &failure_rx,
            &heartbeat,
            sr_monitor.as_deref(),
            monotonic_origin,
        );

        running.store(false, Ordering::Release);
        let _ = self.send_close_once();
        let _ = sender.join();
        if let Some(worker) = heartbeat_worker {
            let _ = worker.join();
        }
        Ok(outcome)
    }

    fn receive_loop(
        &self,
        device: &dyn PacketDevice,
        external_shutdown: &AtomicBool,
        failure_rx: &mpsc::Receiver<WorkerFailure>,
        heartbeat: &Mutex<HeartbeatTracker>,
        sr_monitor: Option<&Mutex<SrMonitor>>,
        monotonic_origin: Instant,
    ) -> SessionEnd {
        let mut legacy_reassemblers = [
            LegacyFragmentReassembler::default(),
            LegacyFragmentReassembler::default(),
        ];
        let mut sr_reassembler = SrFragmentReassembler::default();
        let mut sr_responder = SrMonitorResponder::default();
        let mut buffer = vec![0_u8; 65_535];
        loop {
            if external_shutdown.load(Ordering::Acquire) || !self.running.load(Ordering::Acquire) {
                return SessionEnd::LocalShutdown;
            }
            if let Ok(failure) = failure_rx.try_recv() {
                return match failure {
                    WorkerFailure::HeartbeatTimeout => SessionEnd::HeartbeatTimeout,
                    WorkerFailure::Transport(error) => {
                        warn!(%error, "worker transport failure");
                        SessionEnd::TransportFailure
                    }
                };
            }

            let length = match self.socket.recv(&mut buffer) {
                Ok(length) => length,
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    continue;
                }
                Err(error) => {
                    warn!(%error, "UDP receive failed");
                    return SessionEnd::TransportFailure;
                }
            };
            let datagram = &buffer[..length];
            let action = if datagram.first().copied() == Some(PacketType::SegmentRouting as u8) {
                self.process_sr_packet(
                    datagram,
                    device,
                    &mut sr_reassembler,
                    &mut sr_responder,
                    sr_monitor,
                    monotonic_origin,
                )
            } else {
                let decoded = match protocol::decode_packet(datagram) {
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
                self.process_standard_packet(
                    &decoded,
                    device,
                    heartbeat,
                    &mut legacy_reassemblers,
                    monotonic_origin,
                )
            };
            match action {
                Ok(PacketAction::Continue) => {}
                Ok(PacketAction::ServerClose) => return SessionEnd::ServerClose,
                Err(Error::Io(error)) => {
                    warn!(%error, "packet delivery failed");
                    return SessionEnd::TransportFailure;
                }
                Err(error) => warn!(%error, "dropping invalid session datagram"),
            }
        }
    }

    fn process_standard_packet(
        &self,
        packet: &DecodedPacket,
        device: &dyn PacketDevice,
        heartbeat: &Mutex<HeartbeatTracker>,
        reassemblers: &mut [LegacyFragmentReassembler; 2],
        monotonic_origin: Instant,
    ) -> Result<PacketAction> {
        match packet.header.packet_type {
            PacketType::Data | PacketType::DataDup => {
                require_encryption(packet.header, EncryptionMethod::None)?;
                write_inner_packet(device, validate_inner_packet(&packet.body, None)?)?;
            }
            PacketType::DataIpv6 => {
                require_encryption(packet.header, EncryptionMethod::None)?;
                write_inner_packet(device, validate_inner_packet(&packet.body, Some(6))?)?;
            }
            PacketType::DataEncrypted | PacketType::DataEncryptedDup => {
                require_encryption(packet.header, self.cipher.method())?;
                let plaintext = self.cipher.decrypt(&packet.body)?;
                write_inner_packet(device, validate_inner_packet(&plaintext, None)?)?;
            }
            packet_type @ (PacketType::IpFragment | PacketType::IpFragmentIpv6) => {
                require_encryption(packet.header, EncryptionMethod::None)?;
                let fragment = Fragment::parse_traditional(&packet.body)?;
                let (reassembler, expected_version) = if packet_type == PacketType::IpFragment {
                    (&mut reassemblers[0], 4)
                } else {
                    (&mut reassemblers[1], 6)
                };
                if let Some(inner) = reassembler.insert(fragment, Instant::now())? {
                    write_inner_packet(
                        device,
                        validate_inner_packet(&inner, Some(expected_version))?,
                    )?;
                }
            }
            PacketType::EchoResponse => {
                let response = EchoBody::decode(&packet.body)?;
                let now_micros = monotonic_micros(monotonic_origin);
                if response.tick_micros > now_micros {
                    return Err(Error::InvalidConfig(
                        "heartbeat echoed a future monotonic tick".into(),
                    ));
                }
                let rtt = u32::try_from(now_micros - response.tick_micros).unwrap_or(u32::MAX);
                heartbeat
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .observe(rtt);
            }
            PacketType::EchoRequest => {
                let response = protocol::build_echo_response(packet.header, &packet.body)?;
                self.socket.send(&response)?;
            }
            PacketType::Close => return Ok(PacketAction::ServerClose),
            PacketType::PingRequest
            | PacketType::PingResponse
            | PacketType::Open
            | PacketType::OpenAck
            | PacketType::OpenReject
            | PacketType::SegmentRouting => {
                debug!(packet_type = %packet.header.packet_type, "ignoring unexpected packet");
            }
        }
        Ok(PacketAction::Continue)
    }

    fn process_sr_packet(
        &self,
        datagram: &[u8],
        device: &dyn PacketDevice,
        reassembler: &mut SrFragmentReassembler,
        responder: &mut SrMonitorResponder,
        monitor: Option<&Mutex<SrMonitor>>,
        monotonic_origin: Instant,
    ) -> Result<PacketAction> {
        let runtime = self.sr.as_ref().ok_or(Error::InvalidSegmentRouting(
            "received SR packet in traditional mode",
        ))?;
        match sr::decode_datagram(
            datagram,
            &runtime.config.links,
            self.info.sr_tuple(),
            self.cipher.as_ref(),
            &runtime.outer_cipher,
        )? {
            SrDecoded::Data(packet) => write_inner_packet(device, &packet)?,
            SrDecoded::Fragment {
                packet_type,
                fragment,
            } => {
                if let Some(packet) =
                    sr::insert_fragment(reassembler, packet_type, fragment, Instant::now())?
                {
                    write_inner_packet(device, &packet)?;
                }
            }
            SrDecoded::EchoRequest(request) => {
                if request.sr_id != runtime.config.monitor_sr_id() {
                    return Err(Error::InvalidSegmentRouting(
                        "SR monitor request has the wrong SR ID",
                    ));
                }
                if let Some(response) = responder.respond(request) {
                    self.socket.send(&sr::encode_monitor_datagram(
                        PacketType::EchoResponse,
                        response,
                        &runtime.config.links,
                        self.info.sr_tuple(),
                    )?)?;
                }
            }
            SrDecoded::EchoResponse(response) => {
                let monitor = monitor.ok_or(Error::InvalidSegmentRouting(
                    "received SR monitor response while monitoring is disabled",
                ))?;
                let now_micros = monotonic_micros(monotonic_origin);
                if response.tick_micros > now_micros {
                    return Err(Error::InvalidSegmentRouting(
                        "SR response echoed a future tick",
                    ));
                }
                let rtt = u32::try_from(now_micros - response.tick_micros).unwrap_or(u32::MAX);
                monitor
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .accept_response(response, Instant::now(), rtt)?;
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

fn spawn_packet_sender(
    socket: Arc<UdpSocket>,
    device: Arc<dyn PacketDevice>,
    cipher: Arc<dyn DataCipher>,
    info: SessionInfo,
    sr_runtime: Option<Arc<SrRuntime>>,
    running: Arc<AtomicBool>,
    failures: mpsc::Sender<WorkerFailure>,
) -> Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("openiwan-packet-sender".into())
        .spawn(move || {
            let mut buffer = vec![0_u8; usize::from(info.mtu).max(2_048) * 2 + 64];
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
                    Ok(packet) => packet,
                    Err(error) => {
                        warn!(%error, "dropping malformed TUN packet");
                        continue;
                    }
                };

                let datagrams = if let Some(runtime) = &sr_runtime {
                    sr::encode_data(
                        inner,
                        usize::from(info.mtu),
                        runtime.next_fragment_id(),
                        &runtime.config.links,
                        info.sr_tuple(),
                        cipher.as_ref(),
                        &runtime.outer_cipher,
                    )
                } else {
                    encode_traditional_data(inner, &info, cipher.as_ref())
                };
                let datagrams = match datagrams {
                    Ok(datagrams) => datagrams,
                    Err(error) => {
                        warn!(%error, "cannot encapsulate outbound packet");
                        continue;
                    }
                };
                for datagram in datagrams {
                    if let Err(error) = socket.send(&datagram) {
                        let _ = failures.send(WorkerFailure::Transport(error));
                        return;
                    }
                }
            }
        })
        .map_err(Error::Io)
}

fn encode_traditional_data(
    packet: &[u8],
    info: &SessionInfo,
    cipher: &dyn DataCipher,
) -> Result<Vec<Vec<u8>>> {
    if packet.len() > usize::from(info.mtu) {
        return Err(Error::FragmentTooLarge);
    }
    let (packet_type, encryption, payload) = match info.encryption {
        EncryptionMethod::None => (PacketType::Data, EncryptionMethod::None, packet.to_vec()),
        EncryptionMethod::Xor | EncryptionMethod::Aes => (
            PacketType::DataEncrypted,
            info.encryption,
            cipher.encrypt(packet)?,
        ),
    };
    Ok(vec![protocol::encode_data(
        PacketHeader::new(packet_type, encryption, info.session_id, info.token),
        &payload,
    )])
}

#[derive(Debug)]
struct HeartbeatTracker {
    last_response: Instant,
    missed: u32,
    current: u32,
    minimum: u32,
    maximum: u32,
}

impl HeartbeatTracker {
    fn new() -> Self {
        Self {
            last_response: Instant::now(),
            missed: 0,
            current: 0,
            minimum: 0,
            maximum: 0,
        }
    }

    fn request_body(&mut self, tick_micros: u64) -> EchoBody {
        self.missed = self.missed.saturating_add(1);
        EchoBody::new(
            tick_micros,
            EchoDelayStats {
                current_micros: self.current,
                minimum_micros: self.minimum,
                maximum_micros: self.maximum,
            },
        )
    }

    fn observe(&mut self, rtt: u32) {
        self.last_response = Instant::now();
        self.missed = 0;
        self.current = rtt;
        self.minimum = if self.minimum == 0 {
            rtt
        } else {
            self.minimum.min(rtt)
        };
        self.maximum = self.maximum.max(rtt);
    }

    fn timed_out(&self) -> bool {
        self.missed >= HEARTBEAT_MAX_MISSES || self.last_response.elapsed() > HEARTBEAT_TIMEOUT
    }
}

fn spawn_traditional_heartbeat(
    socket: Arc<UdpSocket>,
    info: SessionInfo,
    tracker: Arc<Mutex<HeartbeatTracker>>,
    running: Arc<AtomicBool>,
    monotonic_origin: Instant,
    failures: mpsc::Sender<WorkerFailure>,
) -> Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("openiwan-heartbeat".into())
        .spawn(move || {
            while running.load(Ordering::Acquire) {
                wait_interruptibly(HEARTBEAT_INTERVAL, &running);
                if !running.load(Ordering::Acquire) {
                    break;
                }
                let echo = {
                    let mut tracker = tracker
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if tracker.timed_out() {
                        let _ = failures.send(WorkerFailure::HeartbeatTimeout);
                        running.store(false, Ordering::Release);
                        break;
                    }
                    tracker.request_body(monotonic_micros(monotonic_origin))
                };
                let packet =
                    protocol::build_echo_request(info.header(PacketType::EchoRequest), echo);
                if let Err(error) = socket.send(&packet) {
                    let _ = failures.send(WorkerFailure::Transport(error));
                    running.store(false, Ordering::Release);
                    break;
                }
            }
        })
        .map_err(Error::Io)
}

fn spawn_sr_monitor(
    socket: Arc<UdpSocket>,
    info: SessionInfo,
    runtime: Arc<SrRuntime>,
    monitor: Arc<Mutex<SrMonitor>>,
    running: Arc<AtomicBool>,
    monotonic_origin: Instant,
    failures: mpsc::Sender<WorkerFailure>,
) -> Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("openiwan-sr-monitor".into())
        .spawn(move || {
            let started = Instant::now();
            while running.load(Ordering::Acquire) {
                let body = {
                    let mut monitor = monitor
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let state = monitor.update_peer_state(Instant::now());
                    if state == SrMonitorState::PeerDown
                        || (state == SrMonitorState::Probing
                            && started.elapsed() > sr::SR_PEER_DOWN_AFTER)
                    {
                        let _ = failures.send(WorkerFailure::HeartbeatTimeout);
                        running.store(false, Ordering::Release);
                        break;
                    }
                    monitor.request(monotonic_micros(monotonic_origin))
                };
                let packet = match sr::encode_monitor_datagram(
                    PacketType::EchoRequest,
                    body,
                    &runtime.config.links,
                    info.sr_tuple(),
                ) {
                    Ok(packet) => packet,
                    Err(error) => {
                        warn!(%error, "cannot encode SR monitor request");
                        let _ = failures.send(WorkerFailure::HeartbeatTimeout);
                        running.store(false, Ordering::Release);
                        break;
                    }
                };
                if let Err(error) = socket.send(&packet) {
                    let _ = failures.send(WorkerFailure::Transport(error));
                    running.store(false, Ordering::Release);
                    break;
                }
                wait_interruptibly(sr::SR_MONITOR_PERIOD, &running);
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

fn require_encryption(header: PacketHeader, expected: EncryptionMethod) -> Result<()> {
    if header.encryption != expected {
        return Err(Error::InvalidConfig(format!(
            "packet encryption {} does not match expected {expected}",
            header.encryption
        )));
    }
    Ok(())
}

fn parse_open_ack(
    packet: &DecodedPacket,
    peer: SocketAddr,
    expected_nonce: u32,
    requested_mtu: u16,
) -> Result<SessionInfo> {
    let attributes = Tlv::parse_all(&packet.body)?;
    if let Some(attribute) = protocol::find_tlv(&attributes, TlvType::AuthVerify)
        && attribute.first_u32()? != expected_nonce
    {
        return Err(Error::AuthenticationVerifyMismatch);
    }

    let mut encryption = packet.header.encryption;
    let mut mtu = requested_mtu;
    let mut address = None;
    let mut gateway = None;
    let mut dns_servers = Vec::new();
    for attribute in &attributes {
        match attribute.kind {
            TlvType::Mtu => {
                mtu = attribute
                    .as_integer()
                    .ok()
                    .and_then(|value| u16::try_from(value).ok())
                    .filter(|value| (576..=9_000).contains(value))
                    .unwrap_or(requested_mtu);
            }
            TlvType::Ip => {
                if let Ok(value) = attribute.first_ipv4() {
                    address = Some(IpAddr::V4(value));
                }
            }
            TlvType::Dns => {
                if let Ok(value) = attribute.first_ipv4() {
                    dns_servers = vec![IpAddr::V4(value)];
                }
            }
            TlvType::Gateway => {
                if let Ok(value) = attribute.first_ipv4() {
                    gateway = Some(IpAddr::V4(value));
                }
            }
            TlvType::Encrypt => {
                encryption = match attribute.as_integer() {
                    Ok(1) => EncryptionMethod::Xor,
                    Ok(2) => EncryptionMethod::Aes,
                    _ => EncryptionMethod::None,
                };
            }
            _ => {}
        }
    }

    Ok(SessionInfo {
        peer,
        session_id: packet.header.session_id,
        token: packet.header.token,
        encryption,
        mtu,
        address,
        gateway,
        dns_servers,
        segment_routing: false,
    })
}

fn parse_rejection(body: &[u8], expected_nonce: u32) -> Result<Error> {
    let mut message_bytes = body.to_vec();
    for offset in 0..body.len() {
        let Ok(attributes) = Tlv::parse_complete(&body[offset..]) else {
            continue;
        };
        let has_username = protocol::find_tlv(&attributes, TlvType::Username).is_some();
        let Some(auth_verify) = protocol::find_tlv(&attributes, TlvType::AuthVerify) else {
            continue;
        };
        if !has_username || auth_verify.value.len() != 4 {
            continue;
        }
        if auth_verify.first_u32()? != expected_nonce {
            return Err(Error::AuthenticationVerifyMismatch);
        }
        message_bytes = protocol::find_tlv(&attributes, TlvType::ErrorMessage).map_or_else(
            || body[..offset].to_vec(),
            |attribute| attribute.value.clone(),
        );
        break;
    }
    let message = String::from_utf8_lossy(&message_bytes).trim().to_owned();
    Ok(Error::AuthenticationRejected {
        code: rejection_code(&message),
        message,
    })
}

fn rejection_code(message: &str) -> u16 {
    let uppercase = message.trim().to_uppercase();
    for (keyword, code) in [
        ("TOOLONG", 2100),
        ("FREEIP", 2111),
        ("PPPOECLNT", 2108),
        ("PPOECLNT", 2108),
        ("CLNT", 2108),
        ("PPPOE_INSTAL", 2112),
        ("PPOE_INSTAL", 2112),
        ("PPPOEINSTALL", 2112),
        ("PPOEINSTALL", 2112),
        ("PPPOE", 2112),
        ("PPOE", 2112),
        ("FAIL", 2116),
        ("NAME", 2102),
        ("PASS", 2105),
        ("ABLED", 2103),
        ("PIRED", 2104),
        ("FULL", 2115),
        ("EMPTY", 2115),
        ("POOL", 2106),
        ("NO_ENTRY", 2107),
        ("ENTRY", 2107),
        ("BIND", 2109),
        ("NULL", 2110),
        ("POLL", 2101),
    ] {
        if uppercase.contains(keyword) {
            return code;
        }
    }
    2999
}

pub fn ping(server: SocketAddr, timeout: Duration) -> Result<Duration> {
    let bind_address = match server {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_address)?;
    socket.connect(server)?;
    socket.set_read_timeout(Some(timeout))?;
    let started = Instant::now();
    socket.send(&protocol::build_ping_request())?;
    let mut buffer = [0_u8; 2_048];
    let length = socket.recv(&mut buffer).map_err(|error| {
        if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) {
            Error::Timeout("ping")
        } else {
            Error::Io(error)
        }
    })?;
    if length != protocol::CONTROL_PREFIX_LEN {
        return Err(Error::InvalidPingResponse);
    }
    let response = protocol::decode_packet(&buffer[..length])?;
    if response.header.packet_type != PacketType::PingResponse
        || response.header.encryption != EncryptionMethod::None
        || response.header.session_id != protocol::PING_SESSION_ID
        || response.header.token != protocol::PING_TOKEN
        || !response.body.is_empty()
    {
        return Err(Error::InvalidPingResponse);
    }
    Ok(started.elapsed())
}

fn random_nonzero_u32() -> Result<u32> {
    loop {
        let value =
            getrandom::u32().map_err(|_| Error::Crypto("system randomness is unavailable"))?;
        if value != 0 {
            return Ok(value);
        }
    }
}

fn monotonic_micros(origin: Instant) -> u64 {
    origin.elapsed().as_micros().try_into().unwrap_or(u64::MAX)
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
    use crate::protocol::encode_control;

    #[test]
    fn plain_rejection_keeps_its_first_character() {
        let error = parse_rejection(b"bad password", 1).unwrap();
        assert!(matches!(
            error,
            Error::AuthenticationRejected {
                code: 2105,
                ref message
            } if message == "bad password"
        ));
    }

    #[test]
    fn structured_rejection_validates_nonce_and_err_msg() {
        let mut body = b"prefix".to_vec();
        for tlv in [
            Tlv::new(TlvType::Username, b"alice").unwrap(),
            Tlv::auth_verify(7),
            Tlv::new(TlvType::ErrorMessage, b"POOL FULL").unwrap(),
        ] {
            tlv.encode(&mut body).unwrap();
        }
        assert!(matches!(
            parse_rejection(&body, 7).unwrap(),
            Error::AuthenticationRejected { code: 2115, .. }
        ));
        assert!(matches!(
            parse_rejection(&body, 8),
            Err(Error::AuthenticationVerifyMismatch)
        ));
    }

    #[test]
    fn open_ack_accepts_android_integer_widths_and_omitted_nonce() {
        let header = PacketHeader::new(
            PacketType::OpenAck,
            EncryptionMethod::Xor,
            0x1234,
            0x5060_7080,
        );
        let mut body = Vec::new();
        Tlv::new(TlvType::Mtu, 1400_u32.to_be_bytes())
            .unwrap()
            .encode(&mut body)
            .unwrap();
        Tlv::new(TlvType::Encrypt, [99])
            .unwrap()
            .encode(&mut body)
            .unwrap();
        let packet = protocol::decode_packet(&encode_control(header, &body)).unwrap();
        let info = parse_open_ack(&packet, "127.0.0.1:6001".parse().unwrap(), 7, 1400).unwrap();
        assert_eq!(info.mtu, 1400);
        assert_eq!(info.encryption, EncryptionMethod::None);
    }

    #[test]
    fn open_ack_skips_bad_ip_fields_and_uses_last_valid_values() {
        let header = PacketHeader::new(
            PacketType::OpenAck,
            EncryptionMethod::Xor,
            0x1234,
            0x5060_7080,
        );
        let mut body = Vec::new();
        for tlv in [
            Tlv::new(TlvType::Ip, [192, 0]).unwrap(),
            Tlv::new(TlvType::Ip, [192, 0, 2, 1, 99]).unwrap(),
            Tlv::new(TlvType::Dns, [0, 0, 0, 0]).unwrap(),
            Tlv::new(TlvType::Encrypt, [1]).unwrap(),
            Tlv::new(TlvType::Encrypt, [0, 0, 2]).unwrap(),
        ] {
            tlv.encode(&mut body).unwrap();
        }
        let packet = protocol::decode_packet(&encode_control(header, &body)).unwrap();
        let info = parse_open_ack(&packet, "127.0.0.1:6001".parse().unwrap(), 7, 1400).unwrap();
        assert_eq!(info.address, Some("192.0.2.1".parse().unwrap()));
        assert_eq!(info.dns_servers, ["0.0.0.0".parse::<IpAddr>().unwrap()]);
        assert_eq!(info.encryption, EncryptionMethod::None);
    }

    #[test]
    fn traditional_plain_path_uses_data_for_ipv6() {
        let packet = {
            let mut value = vec![0_u8; 40];
            value[0] = 0x60;
            value
        };
        let info = SessionInfo {
            peer: "127.0.0.1:6001".parse().unwrap(),
            session_id: 1,
            token: 2,
            encryption: EncryptionMethod::None,
            mtu: 1400,
            address: None,
            gateway: None,
            dns_servers: Vec::new(),
            segment_routing: false,
        };
        let datagram = encode_traditional_data(&packet, &info, &crypto::NoCipher).unwrap();
        assert_eq!(datagram[0][0], PacketType::Data as u8);
    }

    #[test]
    fn debug_output_redacts_credentials() {
        let client =
            Client::new(ClientConfig::new("127.0.0.1:6001"), "alice", "very-secret").unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("very-secret"));
    }
}
