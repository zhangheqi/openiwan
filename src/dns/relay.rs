use super::PhysicalResolver;
use hickory_proto::op::{Message, MessageType};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos"
))]
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

const MAX_UDP_DNS_MESSAGE: usize = 65_507;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayConfig {
    pub timeout: Duration,
    pub max_concurrent: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            max_concurrent: 64,
        }
    }
}

#[derive(Debug)]
pub struct DnsRelay {
    config: RelayConfig,
    resolvers: RwLock<Arc<[PhysicalResolver]>>,
    generation: AtomicU64,
    active: AtomicUsize,
    next_id: AtomicU16,
}

impl DnsRelay {
    pub fn new(config: RelayConfig, resolvers: Vec<PhysicalResolver>) -> Self {
        let seed = random_id_seed();
        Self {
            config,
            resolvers: RwLock::new(resolvers.into()),
            generation: AtomicU64::new(1),
            active: AtomicUsize::new(0),
            next_id: AtomicU16::new(seed),
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn update_resolvers(&self, resolvers: Vec<PhysicalResolver>) -> u64 {
        *self
            .resolvers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = resolvers.into();
        self.generation.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub fn reset_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub fn has_resolvers(&self) -> bool {
        !self
            .resolvers
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }

    pub fn relay(&self, request: &[u8], generation: u64) -> io::Result<Vec<u8>> {
        let _permit = self.acquire()?;
        if generation != self.generation() {
            return Err(io::Error::new(
                ErrorKind::Interrupted,
                "DNS relay generation changed",
            ));
        }
        let request_message = Message::from_vec(request)
            .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error.to_string()))?;
        if request_message.message_type() != MessageType::Query
            || request_message.queries().len() != 1
        {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "DNS relay requires one query",
            ));
        }
        let original_id = request_message.id();
        let resolvers = Arc::clone(
            &self
                .resolvers
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if resolvers.is_empty() {
            return Err(io::Error::new(
                ErrorKind::NotFound,
                "no physical DNS resolver is available",
            ));
        }

        let mut last_error = None;
        for resolver in resolvers.iter() {
            if generation != self.generation() {
                return Err(io::Error::new(
                    ErrorKind::Interrupted,
                    "DNS relay generation changed",
                ));
            }
            let relay_id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let mut relayed = request_message.clone();
            relayed.set_id(relay_id);
            let request_bytes = relayed
                .to_vec()
                .map_err(|error| io::Error::new(ErrorKind::InvalidData, error.to_string()))?;
            match exchange(resolver, &request_bytes, self.config.timeout) {
                Ok(mut response) => {
                    if let Err(error) = validate_response(&relayed, &response) {
                        last_error = Some(error);
                        continue;
                    }
                    if generation != self.generation() {
                        return Err(io::Error::new(
                            ErrorKind::Interrupted,
                            "DNS relay generation changed",
                        ));
                    }
                    response.set_id(original_id);
                    let response = response.to_vec().map_err(|error| {
                        io::Error::new(ErrorKind::InvalidData, error.to_string())
                    })?;
                    if response.len() > MAX_UDP_DNS_MESSAGE {
                        return Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "DNS response is too large for an IPv4 UDP packet",
                        ));
                    }
                    return Ok(response);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(ErrorKind::TimedOut, "all physical DNS resolvers failed")
        }))
    }

    fn acquire(&self) -> io::Result<RelayPermit<'_>> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.config.max_concurrent {
                return Err(io::Error::new(
                    ErrorKind::WouldBlock,
                    "DNS relay concurrency limit reached",
                ));
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(RelayPermit(&self.active)),
                Err(actual) => current = actual,
            }
        }
    }
}

#[derive(Debug)]
struct RelayPermit<'a>(&'a AtomicUsize);

impl Drop for RelayPermit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn exchange(resolver: &PhysicalResolver, request: &[u8], timeout: Duration) -> io::Result<Message> {
    match exchange_udp(resolver, request, timeout) {
        Ok(response) if response.truncated() => exchange_tcp(resolver, request, timeout),
        Ok(response) => Ok(response),
        Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
            exchange_tcp(resolver, request, timeout)
        }
        Err(error) => Err(error),
    }
}

fn exchange_udp(
    resolver: &PhysicalResolver,
    request: &[u8],
    timeout: Duration,
) -> io::Result<Message> {
    let socket = Socket::new(
        Domain::for_address(resolver.address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    bind_physical(&socket, resolver)?;
    let bind = if resolver.address.is_ipv4() {
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
    } else {
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
    };
    socket.bind(&SockAddr::from(bind))?;
    socket.connect(&SockAddr::from(resolver.address))?;
    let socket: UdpSocket = socket.into();
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    socket.send(request)?;
    let requested_size = Message::from_vec(request)
        .map_or(512, |request| usize::from(request.max_payload()))
        .clamp(512, MAX_UDP_DNS_MESSAGE);
    let mut buffer = vec![0_u8; requested_size];
    let length = socket.recv(&mut buffer)?;
    Message::from_vec(&buffer[..length])
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error.to_string()))
}

fn exchange_tcp(
    resolver: &PhysicalResolver,
    request: &[u8],
    timeout: Duration,
) -> io::Result<Message> {
    let request_length = u16::try_from(request.len())
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "DNS query is too large"))?;
    let socket = Socket::new(
        Domain::for_address(resolver.address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    bind_physical(&socket, resolver)?;
    socket.connect_timeout(&SockAddr::from(resolver.address), timeout)?;
    let mut stream: TcpStream = socket.into();
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(&request_length.to_be_bytes())?;
    stream.write_all(request)?;
    stream.flush()?;
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length)?;
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "empty DNS-over-TCP response",
        ));
    }
    let mut response = vec![0_u8; length];
    stream.read_exact(&mut response)?;
    Message::from_vec(&response)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error.to_string()))
}

fn validate_response(request: &Message, response: &Message) -> io::Result<()> {
    if response.message_type() != MessageType::Response
        || response.id() != request.id()
        || response.op_code() != request.op_code()
        || response.queries() != request.queries()
    {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "physical DNS response does not match the query",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_physical(socket: &Socket, resolver: &PhysicalResolver) -> io::Result<()> {
    if let Some(name) = &resolver.interface_name {
        socket.bind_device(Some(name.as_bytes()))?;
    }
    Ok(())
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos"
))]
fn bind_physical(socket: &Socket, resolver: &PhysicalResolver) -> io::Result<()> {
    if let Some(index) = resolver.interface_index.and_then(NonZeroU32::new) {
        if resolver.address.is_ipv4() {
            socket.bind_device_by_index_v4(Some(index))?;
        } else {
            socket.bind_device_by_index_v6(Some(index))?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn bind_physical(socket: &Socket, resolver: &PhysicalResolver) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket as _;
    use windows_sys::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET_ERROR, setsockopt,
    };
    let Some(index) = resolver.interface_index else {
        return Ok(());
    };
    let value = index.to_be_bytes();
    let (level, option) = if resolver.address.is_ipv4() {
        (IPPROTO_IP, IP_UNICAST_IF)
    } else {
        (IPPROTO_IPV6, IPV6_UNICAST_IF)
    };
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            level,
            option,
            value.as_ptr().cast(),
            value.len() as i32,
        )
    };
    if result == SOCKET_ERROR {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
    windows
)))]
fn bind_physical(_socket: &Socket, _resolver: &PhysicalResolver) -> io::Result<()> {
    Ok(())
}

fn random_id_seed() -> u16 {
    let mut bytes = [0_u8; 2];
    if getrandom::fill(&mut bytes).is_ok() {
        u16::from_ne_bytes(bytes)
    } else {
        std::process::id() as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::net::{TcpListener, UdpSocket};
    use std::thread;

    fn query(id: u16) -> Message {
        let mut query = Message::new();
        query
            .set_id(id)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .add_query(Query::query(
                Name::from_ascii("example.test").unwrap(),
                RecordType::A,
            ));
        query
    }

    #[test]
    fn rejects_mismatched_transaction_or_question() {
        let request = query(1);
        let mut response = query(2);
        response.set_message_type(MessageType::Response);
        assert!(validate_response(&request, &response).is_err());
        response.set_id(1);
        assert!(validate_response(&request, &response).is_ok());
    }

    #[test]
    fn generation_invalidates_in_flight_work() {
        let relay = DnsRelay::new(RelayConfig::default(), Vec::new());
        let generation = relay.generation();
        assert!(relay.update_resolvers(Vec::new()) > generation);
        assert_eq!(
            relay
                .relay(&query(7).to_vec().unwrap(), generation)
                .unwrap_err()
                .kind(),
            ErrorKind::Interrupted
        );
    }

    #[test]
    fn concurrency_limit_fails_fast() {
        let relay = DnsRelay::new(
            RelayConfig {
                max_concurrent: 1,
                ..RelayConfig::default()
            },
            Vec::new(),
        );
        let _permit = relay.acquire().unwrap();
        assert_eq!(relay.acquire().unwrap_err().kind(), ErrorKind::WouldBlock);
    }

    #[test]
    fn retries_truncated_udp_over_tcp_and_restores_transaction_id() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(address).unwrap();
        let server = thread::spawn(move || {
            let mut buffer = [0_u8; 512];
            let (length, peer) = udp.recv_from(&mut buffer).unwrap();
            let mut truncated = Message::from_vec(&buffer[..length]).unwrap();
            truncated
                .set_message_type(MessageType::Response)
                .set_truncated(true);
            udp.send_to(&truncated.to_vec().unwrap(), peer).unwrap();

            let (mut stream, _) = tcp.accept().unwrap();
            let mut length = [0_u8; 2];
            stream.read_exact(&mut length).unwrap();
            let mut request = vec![0_u8; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut request).unwrap();
            let mut response = Message::from_vec(&request).unwrap();
            response
                .set_message_type(MessageType::Response)
                .set_truncated(false);
            let response = response.to_vec().unwrap();
            stream
                .write_all(&u16::try_from(response.len()).unwrap().to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        });

        let relay = DnsRelay::new(
            RelayConfig {
                timeout: Duration::from_secs(1),
                max_concurrent: 1,
            },
            vec![PhysicalResolver {
                address,
                interface_name: None,
                interface_index: None,
            }],
        );
        let response = relay
            .relay(&query(0x1234).to_vec().unwrap(), relay.generation())
            .unwrap();
        assert_eq!(Message::from_vec(&response).unwrap().id(), 0x1234);
        server.join().unwrap();
    }

    #[test]
    fn retries_udp_timeout_over_tcp() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(address).unwrap();
        let server = thread::spawn(move || {
            let mut ignored = [0_u8; 512];
            udp.recv_from(&mut ignored).unwrap();

            let (mut stream, _) = tcp.accept().unwrap();
            let mut length = [0_u8; 2];
            stream.read_exact(&mut length).unwrap();
            let mut request = vec![0_u8; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut request).unwrap();
            let mut response = Message::from_vec(&request).unwrap();
            response.set_message_type(MessageType::Response);
            let response = response.to_vec().unwrap();
            stream
                .write_all(&u16::try_from(response.len()).unwrap().to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        });

        let relay = DnsRelay::new(
            RelayConfig {
                timeout: Duration::from_millis(50),
                max_concurrent: 1,
            },
            vec![PhysicalResolver {
                address,
                interface_name: None,
                interface_index: None,
            }],
        );
        let response = relay
            .relay(&query(0x4321).to_vec().unwrap(), relay.generation())
            .unwrap();
        assert_eq!(Message::from_vec(&response).unwrap().id(), 0x4321);
        server.join().unwrap();
    }
}
