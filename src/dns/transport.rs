//! DNS resolution over the route-free iWAN userspace network stack.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use std::collections::HashSet;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tokio_smoltcp::Net;

const DNS_PORT: u16 = 53;
const MAX_CNAME_DEPTH: usize = 8;
const UDP_RESPONSE_SIZE: usize = 4_096;

#[derive(Debug)]
pub struct DnsLookup {
    pub addresses: Vec<IpAddr>,
    pub ttl: Duration,
}

pub async fn lookup(
    net: &Arc<Net>,
    server: SocketAddr,
    host: &str,
    ipv4: bool,
    query_timeout: Duration,
    next_id: &AtomicU16,
) -> io::Result<DnsLookup> {
    let mut name = Name::from_ascii(host)
        .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error.to_string()))?;
    name.set_fqdn(true);
    let record_type = if ipv4 {
        RecordType::A
    } else {
        RecordType::AAAA
    };
    let mut visited = HashSet::new();

    for _ in 0..MAX_CNAME_DEPTH {
        if !visited.insert(name.clone()) {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "DNS CNAME loop detected",
            ));
        }
        let id = next_id.fetch_add(1, Ordering::Relaxed);
        let request = build_query(id, name.clone(), record_type)?;
        let response = timeout(query_timeout, exchange(net, server, &request, id))
            .await
            .map_err(|_| io::Error::new(ErrorKind::TimedOut, "DNS query timed out"))??;
        let parsed = parse_response(response, id, &name, record_type)?;
        if !parsed.addresses.is_empty() {
            return Ok(parsed.into_lookup());
        }
        name = parsed.canonical_name.ok_or_else(|| {
            io::Error::new(
                ErrorKind::AddrNotAvailable,
                format!("DNS returned no {record_type} records for {host}"),
            )
        })?;
    }

    Err(io::Error::new(
        ErrorKind::InvalidData,
        "DNS CNAME chain is too deep",
    ))
}

fn build_query(id: u16, name: Name, record_type: RecordType) -> io::Result<Vec<u8>> {
    let mut request = Message::new();
    request
        .set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .add_query(Query::query(name, record_type));
    request
        .to_vec()
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error.to_string()))
}

async fn exchange(
    net: &Arc<Net>,
    server: SocketAddr,
    request: &[u8],
    id: u16,
) -> io::Result<Message> {
    let response = exchange_udp(net, server, request, id).await?;
    if response.truncated() {
        exchange_tcp(net, server, request, id).await
    } else {
        Ok(response)
    }
}

async fn exchange_udp(
    net: &Arc<Net>,
    server: SocketAddr,
    request: &[u8],
    id: u16,
) -> io::Result<Message> {
    let bind_address = if server.is_ipv4() {
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
    } else {
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
    };
    let socket = net.udp_bind(bind_address).await?;
    socket.send_to(request, server).await?;

    let mut buffer = [0_u8; UDP_RESPONSE_SIZE];
    loop {
        let (length, source) = socket.recv_from(&mut buffer).await?;
        if source != server {
            continue;
        }
        let response = Message::from_vec(&buffer[..length])
            .map_err(|error| io::Error::new(ErrorKind::InvalidData, error.to_string()))?;
        if response.id() == id {
            return Ok(response);
        }
    }
}

async fn exchange_tcp(
    net: &Arc<Net>,
    server: SocketAddr,
    request: &[u8],
    id: u16,
) -> io::Result<Message> {
    let request_length = u16::try_from(request.len())
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "DNS query is too large"))?;
    let mut stream = net.tcp_connect(server).await?;
    stream.write_all(&request_length.to_be_bytes()).await?;
    stream.write_all(request).await?;
    stream.flush().await?;

    let response_length = usize::from(stream.read_u16().await?);
    if response_length == 0 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "invalid DNS-over-TCP response length",
        ));
    }
    let mut response = vec![0_u8; response_length];
    stream.read_exact(&mut response).await?;
    let response = Message::from_vec(&response)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error.to_string()))?;
    if response.id() != id {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "DNS-over-TCP transaction ID mismatch",
        ));
    }
    Ok(response)
}

struct ParsedResponse {
    addresses: Vec<IpAddr>,
    canonical_name: Option<Name>,
    ttl: Duration,
}

fn parse_response(
    response: Message,
    id: u16,
    name: &Name,
    record_type: RecordType,
) -> io::Result<ParsedResponse> {
    if response.id() != id
        || response.message_type() != MessageType::Response
        || response.op_code() != OpCode::Query
    {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "DNS response header does not match the query",
        ));
    }
    if response.response_code() != ResponseCode::NoError {
        let kind = if response.response_code() == ResponseCode::NXDomain {
            ErrorKind::NotFound
        } else {
            ErrorKind::Other
        };
        return Err(io::Error::new(
            kind,
            format!("DNS server returned {}", response.response_code()),
        ));
    }
    if response.queries().len() != 1
        || response.queries()[0].name() != name
        || response.queries()[0].query_type() != record_type
    {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "DNS response question does not match the query",
        ));
    }

    let mut accepted_names = HashSet::from([name.clone()]);
    let mut canonical_name = None;
    let mut ttl = u32::MAX;
    for _ in 0..MAX_CNAME_DEPTH {
        let mut changed = false;
        for record in response.answers() {
            if accepted_names.contains(record.name())
                && let RData::CNAME(target) = record.data()
                && accepted_names.insert(target.0.clone())
            {
                canonical_name = Some(target.0.clone());
                ttl = ttl.min(record.ttl());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut addresses = Vec::new();
    for record in response.answers() {
        if !accepted_names.contains(record.name()) {
            continue;
        }
        match record.data() {
            RData::A(address) if record_type == RecordType::A => {
                addresses.push(IpAddr::V4(address.0));
                ttl = ttl.min(record.ttl());
            }
            RData::AAAA(address) if record_type == RecordType::AAAA => {
                addresses.push(IpAddr::V6(address.0));
                ttl = ttl.min(record.ttl());
            }
            _ => {}
        }
    }
    let mut seen_addresses = HashSet::new();
    addresses.retain(|address| seen_addresses.insert(*address));
    let ttl = if ttl == u32::MAX { 0 } else { ttl };
    Ok(ParsedResponse {
        addresses,
        canonical_name,
        ttl: Duration::from_secs(u64::from(ttl)),
    })
}

impl From<ParsedResponse> for DnsLookup {
    fn from(response: ParsedResponse) -> Self {
        Self {
            addresses: response.addresses,
            ttl: response.ttl,
        }
    }
}

impl ParsedResponse {
    fn into_lookup(self) -> DnsLookup {
        self.into()
    }
}

pub const fn default_port() -> u16 {
    DNS_PORT
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::{RData, Record};

    #[test]
    fn parses_valid_address_response_and_ttl() {
        let name = Name::from_ascii("api.example.test").unwrap();
        let mut response = Message::new();
        response
            .set_id(42)
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_response_code(ResponseCode::NoError)
            .add_query(Query::query(name.clone(), RecordType::A))
            .add_answer(Record::from_rdata(
                name.clone(),
                120,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 10))),
            ))
            .add_answer(Record::from_rdata(
                name.clone(),
                90,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 5))),
            ))
            .add_answer(Record::from_rdata(
                name.clone(),
                60,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 10))),
            ));

        let parsed = parse_response(response, 42, &name, RecordType::A).unwrap();
        assert_eq!(
            parsed.addresses,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            ]
        );
        assert_eq!(parsed.ttl, Duration::from_secs(60));
    }

    #[test]
    fn validates_transaction_and_follows_matching_cname() {
        let name = Name::from_ascii("api.example.test").unwrap();
        let target = Name::from_ascii("internal.example.test").unwrap();
        let mut response = Message::new();
        response
            .set_id(7)
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_response_code(ResponseCode::NoError)
            .add_query(Query::query(name.clone(), RecordType::A))
            .add_answer(Record::from_rdata(
                name.clone(),
                30,
                RData::CNAME(CNAME(target.clone())),
            ))
            .add_answer(Record::from_rdata(
                Name::from_ascii("unrelated.example.test").unwrap(),
                30,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 99))),
            ));

        let parsed = parse_response(response, 7, &name, RecordType::A).unwrap();
        assert_eq!(parsed.canonical_name, Some(target));
        assert!(parsed.addresses.is_empty());
        assert!(parse_response(Message::new(), 7, &name, RecordType::A).is_err());
    }
}
