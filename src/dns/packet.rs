use super::EffectiveDnsPolicy;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::RecordType;
use std::net::Ipv4Addr;
use std::sync::Arc;

const IPV4_MIN_HEADER: usize = 20;
const UDP_HEADER: usize = 8;
const DNS_PORT: u16 = 53;
const ENCRYPTED_DNS_PORT: u16 = 853;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsPacketAction {
    Pass,
    Drop,
    Inject(Vec<u8>),
    Relay(DnsRelayRequest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRelayRequest {
    dns_request: Vec<u8>,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    identification: u16,
}

impl DnsRelayRequest {
    pub fn dns_request(&self) -> &[u8] {
        &self.dns_request
    }

    pub fn response_packet(&self, dns_response: &[u8]) -> Option<Vec<u8>> {
        build_udp_response(
            self.destination,
            self.source,
            self.destination_port,
            self.source_port,
            self.identification,
            dns_response,
        )
    }

    pub fn servfail_packet(&self) -> Option<Vec<u8>> {
        let request = Message::from_vec(&self.dns_request).ok()?;
        let response = synthetic_response(&request, ResponseCode::ServFail)?;
        self.response_packet(&response)
    }
}

#[derive(Debug, Clone)]
pub struct DnsPacketEngine {
    policy: Arc<EffectiveDnsPolicy>,
}

impl DnsPacketEngine {
    pub fn new(policy: EffectiveDnsPolicy) -> Self {
        Self {
            policy: Arc::new(policy),
        }
    }

    pub(crate) fn from_shared(policy: Arc<EffectiveDnsPolicy>) -> Self {
        Self { policy }
    }

    pub fn policy(&self) -> &EffectiveDnsPolicy {
        &self.policy
    }

    pub fn process(&self, packet: &[u8]) -> DnsPacketAction {
        if !self.policy.engine_enabled() {
            return DnsPacketAction::Pass;
        }
        let Some(ipv4) = Ipv4Packet::parse(packet) else {
            return DnsPacketAction::Pass;
        };
        if ipv4.fragmented {
            return DnsPacketAction::Pass;
        }

        let destination_port = match ipv4.protocol {
            6 | 17 => ipv4
                .payload
                .get(2..4)
                .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]])),
            _ => None,
        };
        if self.policy.block_encrypted_dns && destination_port == Some(ENCRYPTED_DNS_PORT) {
            return DnsPacketAction::Drop;
        }
        if ipv4.protocol != 17 {
            return DnsPacketAction::Pass;
        }
        let Some(udp) = UdpPacket::parse(ipv4.payload) else {
            return DnsPacketAction::Pass;
        };
        if udp.destination_port != DNS_PORT {
            return DnsPacketAction::Pass;
        }
        let Ok(request) = Message::from_vec(udp.payload) else {
            return DnsPacketAction::Pass;
        };
        if request.message_type != MessageType::Query || request.queries.len() != 1 {
            return DnsPacketAction::Pass;
        }
        let query = &request.queries[0];
        let name = query.name().to_utf8();

        let synthetic = if self.policy.blocks_doh_host(&name) {
            Some(ResponseCode::NXDomain)
        } else if self.policy.dns_routing_enabled() && query.query_type() == RecordType::AAAA {
            Some(ResponseCode::NoError)
        } else {
            None
        };
        if let Some(code) = synthetic {
            let Some(dns) = synthetic_response(&request, code) else {
                return DnsPacketAction::Pass;
            };
            return build_udp_response(
                ipv4.destination,
                ipv4.source,
                udp.destination_port,
                udp.source_port,
                ipv4.identification,
                &dns,
            )
            .map_or(DnsPacketAction::Pass, DnsPacketAction::Inject);
        }
        if !self.policy.dns_routing_enabled() {
            return DnsPacketAction::Pass;
        }
        if self.policy.routes_through_tunnel(&name) {
            DnsPacketAction::Pass
        } else {
            DnsPacketAction::Relay(DnsRelayRequest {
                dns_request: udp.payload.to_vec(),
                source: ipv4.source,
                destination: ipv4.destination,
                source_port: udp.source_port,
                destination_port: udp.destination_port,
                identification: ipv4.identification,
            })
        }
    }
}

struct Ipv4Packet<'a> {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    identification: u16,
    protocol: u8,
    fragmented: bool,
    payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    fn parse(packet: &'a [u8]) -> Option<Self> {
        if packet.len() < IPV4_MIN_HEADER || packet[0] >> 4 != 4 {
            return None;
        }
        let header_length = usize::from(packet[0] & 0x0f) * 4;
        let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        if header_length < IPV4_MIN_HEADER
            || header_length > total_length
            || total_length > packet.len()
        {
            return None;
        }
        let fragment = u16::from_be_bytes([packet[6], packet[7]]);
        Some(Self {
            source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
            destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
            identification: u16::from_be_bytes([packet[4], packet[5]]),
            protocol: packet[9],
            fragmented: fragment & 0x3fff != 0,
            payload: &packet[header_length..total_length],
        })
    }
}

struct UdpPacket<'a> {
    source_port: u16,
    destination_port: u16,
    payload: &'a [u8],
}

impl<'a> UdpPacket<'a> {
    fn parse(packet: &'a [u8]) -> Option<Self> {
        if packet.len() < UDP_HEADER {
            return None;
        }
        let length = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
        if length < UDP_HEADER || length > packet.len() {
            return None;
        }
        Some(Self {
            source_port: u16::from_be_bytes([packet[0], packet[1]]),
            destination_port: u16::from_be_bytes([packet[2], packet[3]]),
            payload: &packet[UDP_HEADER..length],
        })
    }
}

fn synthetic_response(request: &Message, code: ResponseCode) -> Option<Vec<u8>> {
    let mut response = Message::response(request.id, request.op_code);
    response.metadata.recursion_desired = request.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.response_code = code;
    response.add_queries(request.queries.iter().cloned());
    response.to_vec().ok()
}

fn build_udp_response(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    identification: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_length = UDP_HEADER.checked_add(payload.len())?;
    let total_length = IPV4_MIN_HEADER.checked_add(udp_length)?;
    let udp_length_u16 = u16::try_from(udp_length).ok()?;
    let total_length_u16 = u16::try_from(total_length).ok()?;
    let mut packet = vec![0_u8; total_length];

    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_length_u16.to_be_bytes());
    packet[4..6].copy_from_slice(&identification.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let ip_checksum = checksum(&packet[..IPV4_MIN_HEADER]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp = &mut packet[IPV4_MIN_HEADER..];
    udp[0..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_length_u16.to_be_bytes());
    udp[UDP_HEADER..].copy_from_slice(payload);
    let udp_checksum = udp_checksum(source, destination, udp);
    udp[6..8].copy_from_slice(&udp_checksum.to_be_bytes());
    Some(packet)
}

fn udp_checksum(source: Ipv4Addr, destination: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut sum = 0_u32;
    add_bytes(&mut sum, &source.octets());
    add_bytes(&mut sum, &destination.octets());
    sum += 17;
    sum += u32::try_from(udp.len()).unwrap_or(u32::MAX);
    add_bytes(&mut sum, udp);
    finish_checksum(sum)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    add_bytes(&mut sum, bytes);
    finish_checksum(sum)
}

fn add_bytes(sum: &mut u32, bytes: &[u8]) {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        *sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(last) = chunks.remainder().first() {
        *sum += u32::from(*last) << 8;
    }
}

fn finish_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    if checksum == 0 { 0xffff } else { checksum }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{DnsServerMode, SplitDnsMode};
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::Name;

    fn query(record_type: RecordType, name: &str, transport: u8, port: u16) -> Vec<u8> {
        let mut dns = Message::new(7, MessageType::Query, OpCode::Query);
        dns.metadata.recursion_desired = true;
        dns.add_query(Query::query(Name::from_ascii(name).unwrap(), record_type));
        let dns = dns.to_vec().unwrap();
        if transport == 17 {
            let mut packet = build_udp_response(
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(192, 0, 2, 53),
                55_000,
                port,
                1,
                &dns,
            )
            .unwrap();
            packet[10..12].fill(0);
            let checksum = checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            packet
        } else {
            let mut packet = vec![0_u8; 40];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
            packet[8] = 64;
            packet[9] = transport;
            packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
            packet[16..20].copy_from_slice(&[192, 0, 2, 53]);
            packet[20..22].copy_from_slice(&55_000_u16.to_be_bytes());
            packet[22..24].copy_from_slice(&port.to_be_bytes());
            packet
        }
    }

    fn engine() -> DnsPacketEngine {
        DnsPacketEngine::new(EffectiveDnsPolicy {
            server_mode: DnsServerMode::Server,
            servers: vec![Ipv4Addr::new(192, 0, 2, 53)],
            split_mode: SplitDnsMode::TunnelAll,
            inclusive: Vec::new(),
            exclusive: Vec::new(),
            block_encrypted_dns: true,
            doh_hosts: vec!["dns.example.test".into(), "use-application-dns.net".into()],
        })
    }

    #[test]
    fn synthesizes_empty_aaaa_and_doh_nxdomain() {
        let DnsPacketAction::Inject(packet) =
            engine().process(&query(RecordType::AAAA, "example.test", 17, 53))
        else {
            panic!("expected injection");
        };
        let ipv4 = Ipv4Packet::parse(&packet).unwrap();
        let udp = UdpPacket::parse(ipv4.payload).unwrap();
        let response = Message::from_vec(udp.payload).unwrap();
        assert_eq!(response.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());

        let DnsPacketAction::Inject(packet) =
            engine().process(&query(RecordType::A, "dns.example.test", 17, 53))
        else {
            panic!("expected injection");
        };
        let ipv4 = Ipv4Packet::parse(&packet).unwrap();
        let udp = UdpPacket::parse(ipv4.payload).unwrap();
        assert_eq!(
            Message::from_vec(udp.payload).unwrap().response_code,
            ResponseCode::NXDomain
        );

        let DnsPacketAction::Inject(packet) =
            engine().process(&query(RecordType::AAAA, "dns.example.test", 17, 53))
        else {
            panic!("expected injection");
        };
        let ipv4 = Ipv4Packet::parse(&packet).unwrap();
        let udp = UdpPacket::parse(ipv4.payload).unwrap();
        assert_eq!(
            Message::from_vec(udp.payload).unwrap().response_code,
            ResponseCode::NXDomain
        );
    }

    #[test]
    fn drops_tcp_and_udp_853_but_passes_other_traffic() {
        assert_eq!(
            engine().process(&query(RecordType::A, "example.test", 17, 853)),
            DnsPacketAction::Drop
        );
        assert_eq!(
            engine().process(&query(RecordType::A, "example.test", 6, 853)),
            DnsPacketAction::Drop
        );
        assert_eq!(engine().process(&[0, 1, 2]), DnsPacketAction::Pass);
    }

    #[test]
    fn encrypted_dns_blocking_works_without_dns_routing() {
        let mut policy = engine().policy().clone();
        policy.server_mode = DnsServerMode::Disabled;
        policy.servers.clear();
        policy.split_mode = SplitDnsMode::Off;
        let engine = DnsPacketEngine::new(policy);

        assert_eq!(
            engine.process(&query(RecordType::A, "example.test", 17, 853)),
            DnsPacketAction::Drop
        );
        assert_eq!(
            engine.process(&query(RecordType::A, "example.test", 6, 853)),
            DnsPacketAction::Drop
        );
        assert_eq!(
            engine.process(&query(RecordType::AAAA, "example.test", 17, 53)),
            DnsPacketAction::Pass
        );

        let DnsPacketAction::Inject(packet) =
            engine.process(&query(RecordType::AAAA, "dns.example.test", 17, 53))
        else {
            panic!("expected injection");
        };
        let ipv4 = Ipv4Packet::parse(&packet).unwrap();
        let udp = UdpPacket::parse(ipv4.payload).unwrap();
        assert_eq!(
            Message::from_vec(udp.payload).unwrap().response_code,
            ResponseCode::NXDomain
        );
    }

    #[test]
    fn relays_physical_and_passes_tunnel_queries() {
        let mut policy = engine().policy().clone();
        policy.split_mode = SplitDnsMode::Managed;
        policy.inclusive = vec!["@corp.test".parse().unwrap()];
        let engine = DnsPacketEngine::new(policy);
        assert!(matches!(
            engine.process(&query(RecordType::A, "public.test", 17, 53)),
            DnsPacketAction::Relay(_)
        ));
        assert_eq!(
            engine.process(&query(RecordType::A, "api.corp.test", 17, 53)),
            DnsPacketAction::Pass
        );
    }

    #[test]
    fn malformed_fragmented_and_multi_question_dns_fail_open() {
        let mut fragmented = query(RecordType::A, "dns.example.test", 17, 53);
        fragmented[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        fragmented[10..12].fill(0);
        let header_checksum = checksum(&fragmented[..20]);
        fragmented[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        assert_eq!(engine().process(&fragmented), DnsPacketAction::Pass);

        let mut malformed = query(RecordType::A, "dns.example.test", 17, 53);
        malformed[24..26].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(engine().process(&malformed), DnsPacketAction::Pass);

        let mut message = Message::new(9, MessageType::Query, OpCode::Query);
        message
            .add_query(Query::query(
                Name::from_ascii("dns.example.test").unwrap(),
                RecordType::A,
            ))
            .add_query(Query::query(
                Name::from_ascii("other.test").unwrap(),
                RecordType::A,
            ));
        let multi = build_udp_response(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(192, 0, 2, 53),
            55_000,
            53,
            2,
            &message.to_vec().unwrap(),
        )
        .unwrap();
        assert_eq!(engine().process(&multi), DnsPacketAction::Pass);
    }

    #[test]
    fn injected_response_has_valid_ipv4_and_udp_checksums() {
        let DnsPacketAction::Inject(packet) =
            engine().process(&query(RecordType::AAAA, "example.test", 17, 53))
        else {
            panic!("expected injection");
        };
        assert_eq!(checksum(&packet[..20]), 0xffff);
        let ipv4 = Ipv4Packet::parse(&packet).unwrap();
        assert_eq!(
            udp_checksum(ipv4.source, ipv4.destination, ipv4.payload),
            0xffff
        );
    }
}
