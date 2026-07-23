use crate::crypto;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub const HEADER_LEN: usize = 8;
pub const SIGNATURE_LEN: usize = 16;
pub const CONTROL_PREFIX_LEN: usize = HEADER_LEN + SIGNATURE_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketType {
    OpenReject = 0x11,
    OpenAck = 0x12,
    Open = 0x13,
    Data = 0x14,
    EchoRequest = 0x15,
    EchoResponse = 0x16,
    Close = 0x17,
    DataEncrypt = 0x18,
    DataDup = 0x19,
    DataEncDup = 0x20,
    IpFrag = 0x22,
    Data6 = 0x23,
    IpFrag6 = 0x24,
    SegRt = 0x28,
    PingRequest = 0x29,
    PingResponse = 0x2a,
}

impl PacketType {
    pub const ALL: [Self; 16] = [
        Self::OpenReject,
        Self::OpenAck,
        Self::Open,
        Self::Data,
        Self::EchoRequest,
        Self::EchoResponse,
        Self::Close,
        Self::DataEncrypt,
        Self::DataDup,
        Self::DataEncDup,
        Self::IpFrag,
        Self::Data6,
        Self::IpFrag6,
        Self::SegRt,
        Self::PingRequest,
        Self::PingResponse,
    ];

    pub const fn is_control(self) -> bool {
        matches!(
            self,
            Self::OpenReject
                | Self::OpenAck
                | Self::Open
                | Self::EchoRequest
                | Self::EchoResponse
                | Self::Close
                | Self::PingRequest
                | Self::PingResponse
        )
    }

    pub const fn is_data(self) -> bool {
        !self.is_control()
    }

    pub const fn is_encrypted_data(self) -> bool {
        matches!(self, Self::DataEncrypt | Self::DataEncDup)
    }
}

impl TryFrom<u8> for PacketType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| *kind as u8 == value)
            .ok_or(Error::UnknownPacketType(value))
    }
}

impl fmt::Display for PacketType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OpenReject => "OPENREJECT",
            Self::OpenAck => "OPENACK",
            Self::Open => "OPEN",
            Self::Data => "DATA",
            Self::EchoRequest | Self::PingRequest => "PINGREQUEST",
            Self::EchoResponse | Self::PingResponse => "PINGRESPONSE",
            Self::Close => "CLOSE",
            Self::DataEncrypt => "DATAENC",
            Self::DataDup => "DATADUP",
            Self::DataEncDup => "DATAENCDUP",
            Self::IpFrag => "IPFRAG",
            Self::Data6 => "DATA6",
            Self::IpFrag6 => "IPFRAG6",
            Self::SegRt => "SEGRT",
        })
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum EncryptionMethod {
    None = 0,
    #[default]
    Xor = 1,
    Aes = 2,
}

impl TryFrom<u8> for EncryptionMethod {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Xor),
            2 => Ok(Self::Aes),
            other => Err(Error::UnknownEncryptionMethod(other)),
        }
    }
}

impl FromStr for EncryptionMethod {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "none" | "0" => Ok(Self::None),
            "xor" | "1" => Ok(Self::Xor),
            "aes" | "aes128" | "2" => Ok(Self::Aes),
            _ => Err(Error::InvalidConfig(format!(
                "unknown encryption method {value:?}"
            ))),
        }
    }
}

impl fmt::Display for EncryptionMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::None => "none",
            Self::Xor => "xor",
            Self::Aes => "aes",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    pub packet_type: PacketType,
    pub encryption: EncryptionMethod,
    pub session_id: u16,
    pub token: u32,
}

impl PacketHeader {
    pub const fn new(
        packet_type: PacketType,
        encryption: EncryptionMethod,
        session_id: u16,
        token: u32,
    ) -> Self {
        Self {
            packet_type,
            encryption,
            session_id,
            token,
        }
    }

    pub fn encode(self) -> [u8; HEADER_LEN] {
        let mut output = [0_u8; HEADER_LEN];
        output[0] = self.packet_type as u8;
        output[1] = self.encryption as u8;
        output[2..4].copy_from_slice(&self.session_id.to_be_bytes());
        output[4..8].copy_from_slice(&self.token.to_be_bytes());
        output
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < HEADER_LEN {
            return Err(Error::PacketTooShort {
                minimum: HEADER_LEN,
                actual: input.len(),
            });
        }
        Ok(Self {
            packet_type: PacketType::try_from(input[0])?,
            encryption: EncryptionMethod::try_from(input[1])?,
            session_id: u16::from_be_bytes([input[2], input[3]]),
            token: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TlvType {
    Username = 0x01,
    Password = 0x02,
    Mtu = 0x03,
    Ip = 0x04,
    Dns = 0x05,
    Gateway = 0x06,
    Netmask = 0x07,
    Encrypt = 0x08,
    DupPacket = 0x09,
    Link = 0x0a,
    Ip6 = 0x0b,
    Dns6 = 0x0c,
    Gateway6 = 0x0d,
    ServerConfig = 0x0e,
    AuthVerify = 0x0f,
    RejectReason = 0x10,
}

impl TlvType {
    pub const ALL: [Self; 16] = [
        Self::Username,
        Self::Password,
        Self::Mtu,
        Self::Ip,
        Self::Dns,
        Self::Gateway,
        Self::Netmask,
        Self::Encrypt,
        Self::DupPacket,
        Self::Link,
        Self::Ip6,
        Self::Dns6,
        Self::Gateway6,
        Self::ServerConfig,
        Self::AuthVerify,
        Self::RejectReason,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Username => "USERNAME",
            Self::Password => "PASSWORD",
            Self::Mtu => "MTU",
            Self::Ip => "IP",
            Self::Dns => "DNS",
            Self::Gateway => "GATEWAY",
            Self::Netmask => "NETMASK",
            Self::Encrypt => "ENCRYPT",
            Self::DupPacket => "DUPPKT",
            Self::Link => "LINK",
            Self::Ip6 => "IP6",
            Self::Dns6 => "DNS6",
            Self::Gateway6 => "GATEWAY6",
            Self::ServerConfig => "SERVER_CONFIG",
            Self::AuthVerify => "AUTH_VERIFY",
            Self::RejectReason => "REJECT_REASON",
        }
    }
}

impl TryFrom<u8> for TlvType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| *kind as u8 == value)
            .ok_or_else(|| Error::InvalidTlv {
                offset: 0,
                reason: format!("unknown type 0x{value:02x}"),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    pub kind: TlvType,
    pub value: Vec<u8>,
}

impl Tlv {
    pub fn new(kind: TlvType, value: impl Into<Vec<u8>>) -> Result<Self> {
        let value = value.into();
        if value.len() + 2 > usize::from(u8::MAX) {
            return Err(Error::TlvTooLarge {
                kind: kind.name(),
                length: value.len(),
            });
        }
        Ok(Self { kind, value })
    }

    pub fn encode(&self, output: &mut Vec<u8>) -> Result<()> {
        let length = self.value.len() + 2;
        let length = u8::try_from(length).map_err(|_| Error::TlvTooLarge {
            kind: self.kind.name(),
            length: self.value.len(),
        })?;
        output.push(self.kind as u8);
        output.push(length);
        output.extend_from_slice(&self.value);
        Ok(())
    }

    pub fn parse_all(input: &[u8]) -> Result<Vec<Self>> {
        let mut attributes = Vec::new();
        let mut offset = 0;
        while offset < input.len() {
            if input.len() - offset < 2 {
                return Err(Error::InvalidTlv {
                    offset,
                    reason: "not enough data for the two-byte TLV header".into(),
                });
            }
            let kind = TlvType::try_from(input[offset]).map_err(|_| Error::InvalidTlv {
                offset,
                reason: format!("unknown type 0x{:02x}", input[offset]),
            })?;
            let length = usize::from(input[offset + 1]);
            if length < 2 {
                return Err(Error::InvalidTlv {
                    offset,
                    reason: format!("invalid total length {length}"),
                });
            }
            if offset + length > input.len() {
                return Err(Error::InvalidTlv {
                    offset,
                    reason: format!(
                        "declared length {length} exceeds {} remaining bytes",
                        input.len() - offset
                    ),
                });
            }
            attributes.push(Self {
                kind,
                value: input[offset + 2..offset + length].to_vec(),
            });
            offset += length;
        }
        Ok(attributes)
    }

    pub fn mtu(mtu: u16) -> Self {
        Self {
            kind: TlvType::Mtu,
            value: mtu.to_be_bytes().to_vec(),
        }
    }

    pub fn username(username: &str) -> Result<Self> {
        Self::new(TlvType::Username, username.as_bytes())
    }

    pub fn encrypted_password(password: [u8; 16]) -> Self {
        Self {
            kind: TlvType::Password,
            value: password.to_vec(),
        }
    }

    pub fn encryption(method: EncryptionMethod) -> Self {
        Self {
            kind: TlvType::Encrypt,
            value: vec![method as u8],
        }
    }

    pub fn link(link: u32) -> Self {
        Self {
            kind: TlvType::Link,
            value: link.to_be_bytes().to_vec(),
        }
    }

    pub fn auth_verify(nonce: u32) -> Self {
        Self {
            kind: TlvType::AuthVerify,
            value: nonce.to_be_bytes().to_vec(),
        }
    }

    pub fn as_u8(&self) -> Result<u8> {
        self.value
            .first()
            .copied()
            .filter(|_| self.value.len() == 1)
            .ok_or(Error::InvalidTlvValue(self.kind.name()))
    }

    pub fn as_u16(&self) -> Result<u16> {
        self.value
            .as_slice()
            .try_into()
            .map(u16::from_be_bytes)
            .map_err(|_| Error::InvalidTlvValue(self.kind.name()))
    }

    pub fn as_u32(&self) -> Result<u32> {
        self.value
            .as_slice()
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| Error::InvalidTlvValue(self.kind.name()))
    }

    pub fn as_ipv4(&self) -> Result<Ipv4Addr> {
        let octets: [u8; 4] = self
            .value
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidTlvValue(self.kind.name()))?;
        Ok(Ipv4Addr::from(octets))
    }

    pub fn as_ipv6(&self) -> Result<Ipv6Addr> {
        let octets: [u8; 16] = self
            .value
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidTlvValue(self.kind.name()))?;
        Ok(Ipv6Addr::from(octets))
    }

    pub fn as_string(&self) -> Result<String> {
        String::from_utf8(self.value.clone()).map_err(|_| Error::InvalidTlvValue(self.kind.name()))
    }
}

#[derive(Debug, Clone)]
pub struct DecodedPacket {
    pub header: PacketHeader,
    pub signature: Option<[u8; SIGNATURE_LEN]>,
    pub body: Vec<u8>,
}

pub fn calculate_signature(header: PacketHeader) -> [u8; SIGNATURE_LEN] {
    let mut input = [0_u8; HEADER_LEN + 2];
    input[..HEADER_LEN].copy_from_slice(&header.encode());
    input[HEADER_LEN..].copy_from_slice(b"mw");
    crypto::md5(&input)
}

pub fn encode_control(header: PacketHeader, body: &[u8]) -> Vec<u8> {
    debug_assert!(header.packet_type.is_control());
    let mut output = Vec::with_capacity(CONTROL_PREFIX_LEN + body.len());
    output.extend_from_slice(&header.encode());
    output.extend_from_slice(&calculate_signature(header));
    output.extend_from_slice(body);
    output
}

pub fn encode_data(header: PacketHeader, body: &[u8]) -> Vec<u8> {
    debug_assert!(header.packet_type.is_data());
    let mut output = Vec::with_capacity(HEADER_LEN + body.len());
    output.extend_from_slice(&header.encode());
    output.extend_from_slice(body);
    output
}

pub fn decode_packet(input: &[u8]) -> Result<DecodedPacket> {
    let header = PacketHeader::decode(input)?;
    if header.packet_type.is_control() {
        if input.len() < CONTROL_PREFIX_LEN {
            return Err(Error::PacketTooShort {
                minimum: CONTROL_PREFIX_LEN,
                actual: input.len(),
            });
        }
        let signature: [u8; SIGNATURE_LEN] = input[HEADER_LEN..CONTROL_PREFIX_LEN]
            .try_into()
            .expect("slice length is checked");
        if signature != calculate_signature(header) {
            return Err(Error::InvalidSignature);
        }
        Ok(DecodedPacket {
            header,
            signature: Some(signature),
            body: input[CONTROL_PREFIX_LEN..].to_vec(),
        })
    } else {
        Ok(DecodedPacket {
            header,
            signature: None,
            body: input[HEADER_LEN..].to_vec(),
        })
    }
}

pub fn build_open(
    username: &str,
    password: &str,
    mtu: u16,
    encryption: EncryptionMethod,
    first_hop_link: Option<u32>,
    auth_verify: Option<u32>,
) -> Result<Vec<u8>> {
    let mut attributes = vec![
        Tlv::mtu(mtu),
        Tlv::username(username)?,
        Tlv::encrypted_password(crypto::encrypt_password(password, username)),
        Tlv::encryption(encryption),
    ];
    if let Some(link) = first_hop_link {
        attributes.push(Tlv::link(link));
    }
    if let Some(nonce) = auth_verify {
        attributes.push(Tlv::auth_verify(nonce));
    }

    let mut body = Vec::new();
    for attribute in &attributes {
        attribute.encode(&mut body)?;
    }
    Ok(encode_control(
        PacketHeader::new(PacketType::Open, encryption, 0, 0),
        &body,
    ))
}

pub fn build_close(header: PacketHeader) -> Vec<u8> {
    encode_control(
        PacketHeader::new(
            PacketType::Close,
            header.encryption,
            header.session_id,
            header.token,
        ),
        &[],
    )
}

pub fn build_echo_request(header: PacketHeader, timestamp_micros: u64) -> Vec<u8> {
    encode_control(
        PacketHeader::new(
            PacketType::EchoRequest,
            header.encryption,
            header.session_id,
            header.token,
        ),
        &timestamp_micros.to_be_bytes(),
    )
}

pub fn build_echo_response(
    request: PacketHeader,
    timestamp_micros: u64,
    current_delay_micros: u32,
    min_delay_micros: u32,
    max_delay_micros: u32,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(20);
    body.extend_from_slice(&timestamp_micros.to_be_bytes());
    body.extend_from_slice(&current_delay_micros.to_be_bytes());
    body.extend_from_slice(&min_delay_micros.to_be_bytes());
    body.extend_from_slice(&max_delay_micros.to_be_bytes());
    encode_control(
        PacketHeader::new(
            PacketType::EchoResponse,
            request.encryption,
            request.session_id,
            request.token,
        ),
        &body,
    )
}

pub fn parse_echo_response(body: &[u8]) -> Result<(u64, u32, u32, u32)> {
    if body.len() < 20 {
        return Err(Error::PacketTooShort {
            minimum: 20,
            actual: body.len(),
        });
    }
    Ok((
        u64::from_be_bytes(body[0..8].try_into().expect("length checked")),
        u32::from_be_bytes(body[8..12].try_into().expect("length checked")),
        u32::from_be_bytes(body[12..16].try_into().expect("length checked")),
        u32::from_be_bytes(body[16..20].try_into().expect("length checked")),
    ))
}

pub fn build_ping_request() -> Vec<u8> {
    encode_control(
        PacketHeader::new(PacketType::PingRequest, EncryptionMethod::None, 0, 0),
        &[],
    )
}

pub fn find_tlv(attributes: &[Tlv], kind: TlvType) -> Option<&Tlv> {
    attributes.iter().find(|attribute| attribute.kind == kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_type_table_matches_230_binary() {
        assert_eq!(
            PacketType::ALL.map(|kind| kind as u8),
            [
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x22, 0x23, 0x24, 0x28,
                0x29, 0x2a
            ]
        );
    }

    #[test]
    fn header_round_trip() {
        let header = PacketHeader::new(
            PacketType::DataEncrypt,
            EncryptionMethod::Xor,
            0x1234,
            0x89ab_cdef,
        );
        assert_eq!(
            header.encode(),
            [0x18, 0x01, 0x12, 0x34, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(PacketHeader::decode(&header.encode()).unwrap(), header);
    }

    #[test]
    fn tlv_round_trip() {
        let attributes = [
            Tlv::mtu(1400),
            Tlv::username("alice").unwrap(),
            Tlv::auth_verify(0x1020_3040),
        ];
        let mut encoded = Vec::new();
        for attribute in &attributes {
            attribute.encode(&mut encoded).unwrap();
        }
        assert_eq!(Tlv::parse_all(&encoded).unwrap(), attributes);
    }

    #[test]
    fn control_signature_detects_modification() {
        let header = PacketHeader::new(PacketType::Close, EncryptionMethod::Xor, 1, 2);
        let mut packet = encode_control(header, &[]);
        assert_eq!(decode_packet(&packet).unwrap().header, header);
        packet[8] ^= 1;
        assert!(matches!(
            decode_packet(&packet),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn open_contains_auth_echo_last() {
        let packet = build_open(
            "alice",
            "secret",
            1400,
            EncryptionMethod::Xor,
            Some(7),
            Some(9),
        )
        .unwrap();
        let decoded = decode_packet(&packet).unwrap();
        let attributes = Tlv::parse_all(&decoded.body).unwrap();
        assert_eq!(
            attributes
                .iter()
                .map(|attribute| attribute.kind)
                .collect::<Vec<_>>(),
            vec![
                TlvType::Mtu,
                TlvType::Username,
                TlvType::Password,
                TlvType::Encrypt,
                TlvType::Link,
                TlvType::AuthVerify
            ]
        );
    }
}
