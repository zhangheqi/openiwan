//! Byte-exact traditional iWAN 2.3.0 framing.
//!
//! The implementation follows `reverse/IWAN_PROTOCOL_SPEC.md`, reconstructed
//! from the Android 2.3.0 APK.  Segment-routing envelopes are intentionally
//! parsed by [`crate::sr`] because their first bytes are not a standard iWAN
//! header even though byte zero is `SEGMENT_ROUTING`.

use crate::crypto;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

pub const HEADER_LEN: usize = 8;
pub const SIGNATURE_LEN: usize = 16;
pub const CONTROL_PREFIX_LEN: usize = HEADER_LEN + SIGNATURE_LEN;
pub const PING_SESSION_ID: u16 = u16::MAX;
pub const PING_TOKEN: u32 = u32::MAX;
pub const ECHO_BODY_LEN: usize = 20;

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
    DataEncrypted = 0x18,
    DataDup = 0x19,
    DataEncryptedDup = 0x20,
    IpFragment = 0x22,
    DataIpv6 = 0x23,
    IpFragmentIpv6 = 0x24,
    SegmentRouting = 0x28,
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
        Self::DataEncrypted,
        Self::DataDup,
        Self::DataEncryptedDup,
        Self::IpFragment,
        Self::DataIpv6,
        Self::IpFragmentIpv6,
        Self::SegmentRouting,
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
        !self.is_control() && !matches!(self, Self::SegmentRouting)
    }

    pub const fn is_encrypted_data(self) -> bool {
        matches!(self, Self::DataEncrypted | Self::DataEncryptedDup)
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
            Self::OpenReject => "OPEN_REJECT",
            Self::OpenAck => "OPEN_ACK",
            Self::Open => "OPEN",
            Self::Data => "DATA",
            Self::EchoRequest => "ECHO_REQUEST",
            Self::EchoResponse => "ECHO_RESPONSE",
            Self::Close => "CLOSE",
            Self::DataEncrypted => "DATA_ENCRYPTED",
            Self::DataDup => "DATA_DUP",
            Self::DataEncryptedDup => "DATA_ENC_DUP",
            Self::IpFragment => "IP_FRAGMENT",
            Self::DataIpv6 => "DATA_IPV6",
            Self::IpFragmentIpv6 => "IP_FRAGMENT_IPV6",
            Self::SegmentRouting => "SEGMENT_ROUTING",
            Self::PingRequest => "PING_REQUEST",
            Self::PingResponse => "PING_RESPONSE",
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
        if input[0] == PacketType::SegmentRouting as u8 {
            return Err(Error::InvalidSegmentRouting(
                "SR envelope must be parsed as an SR header",
            ));
        }
        Self::decode_inner(input)
    }

    /// Decode a standard-format header embedded inside an SR envelope.
    pub fn decode_inner(input: &[u8]) -> Result<Self> {
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

/// TLV registry retained by the Android 2.3.0 parser.
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
    AuthVerify = 0x0f,
    ErrorMessage = 0x10,
}

impl TlvType {
    pub const ALL: [Self; 12] = [
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
        Self::AuthVerify,
        Self::ErrorMessage,
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
            Self::DupPacket => "DUP_PKT",
            Self::Link => "LINK",
            Self::AuthVerify => "AUTH_VERIFY",
            Self::ErrorMessage => "ERR_MSG",
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
        if value.len() > 253 {
            return Err(Error::TlvTooLarge {
                kind: kind.name(),
                length: value.len(),
            });
        }
        Ok(Self { kind, value })
    }

    pub fn encode(&self, output: &mut Vec<u8>) -> Result<()> {
        let length = u8::try_from(self.value.len() + 2).map_err(|_| Error::TlvTooLarge {
            kind: self.kind.name(),
            length: self.value.len(),
        })?;
        output.push(self.kind as u8);
        output.push(length);
        output.extend_from_slice(&self.value);
        Ok(())
    }

    /// Reproduce the APK list loop: parse while at least three bytes remain and
    /// silently ignore a final one- or two-byte suffix.
    pub fn parse_all(input: &[u8]) -> Result<Vec<Self>> {
        let mut attributes = Vec::new();
        let mut offset = 0;
        while input.len() - offset >= 3 {
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

    /// Strict parser used when recognizing a structured `OPEN_REJECT` suffix.
    pub fn parse_complete(input: &[u8]) -> Result<Vec<Self>> {
        let attributes = Self::parse_all(input)?;
        let parsed_len = attributes.iter().map(|tlv| tlv.value.len() + 2).sum();
        if parsed_len != input.len() {
            return Err(Error::InvalidTlv {
                offset: parsed_len,
                reason: "trailing bytes do not form a complete TLV".into(),
            });
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
        Self::new(TlvType::Username, crypto::java_us_ascii(username))
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

    /// Shared Android integer decoder: only 1, 2, and 4 byte values exist.
    pub fn as_integer(&self) -> Result<u32> {
        match self.value.as_slice() {
            [value] => Ok(u32::from(*value)),
            [a, b] => Ok(u32::from(u16::from_be_bytes([*a, *b]))),
            [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
            _ => Err(Error::InvalidTlvValue(self.kind.name())),
        }
    }

    pub fn first_u32(&self) -> Result<u32> {
        let bytes = self
            .value
            .get(..4)
            .ok_or(Error::InvalidTlvValue(self.kind.name()))?;
        Ok(u32::from_be_bytes(
            bytes.try_into().expect("slice length checked"),
        ))
    }

    pub fn first_ipv4(&self) -> Result<Ipv4Addr> {
        let bytes = self
            .value
            .get(..4)
            .ok_or(Error::InvalidTlvValue(self.kind.name()))?;
        Ok(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).expect("slice length checked"),
        ))
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
        // The APK has an authentication-probe path that emits a raw 8-byte
        // CLOSE. Accepting it is required for bidirectional compatibility.
        if header.packet_type == PacketType::Close && input.len() == HEADER_LEN {
            return Ok(DecodedPacket {
                header,
                signature: None,
                body: Vec::new(),
            });
        }
        if input.len() < CONTROL_PREFIX_LEN {
            return Err(Error::PacketTooShort {
                minimum: CONTROL_PREFIX_LEN,
                actual: input.len(),
            });
        }
        let signature: [u8; SIGNATURE_LEN] = input[HEADER_LEN..CONTROL_PREFIX_LEN]
            .try_into()
            .expect("slice length checked");
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
    if let Some(nonce) = auth_verify.filter(|nonce| *nonce != 0) {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoDelayStats {
    pub current_micros: u32,
    pub minimum_micros: u32,
    pub maximum_micros: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoBody {
    pub tick_micros: u64,
    pub delay_stats: EchoDelayStats,
}

impl EchoBody {
    pub const fn new(tick_micros: u64, delay_stats: EchoDelayStats) -> Self {
        Self {
            tick_micros,
            delay_stats,
        }
    }

    pub fn encode(self) -> [u8; ECHO_BODY_LEN] {
        let mut body = [0_u8; ECHO_BODY_LEN];
        body[0..8].copy_from_slice(&self.tick_micros.to_le_bytes());
        body[8..12].copy_from_slice(&self.delay_stats.current_micros.to_le_bytes());
        body[12..16].copy_from_slice(&self.delay_stats.minimum_micros.to_le_bytes());
        body[16..20].copy_from_slice(&self.delay_stats.maximum_micros.to_le_bytes());
        body
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        if body.len() < ECHO_BODY_LEN {
            return Err(Error::PacketTooShort {
                minimum: ECHO_BODY_LEN,
                actual: body.len(),
            });
        }
        Ok(Self {
            tick_micros: u64::from_le_bytes(body[0..8].try_into().expect("length checked")),
            delay_stats: EchoDelayStats {
                current_micros: u32::from_le_bytes(body[8..12].try_into().expect("length checked")),
                minimum_micros: u32::from_le_bytes(
                    body[12..16].try_into().expect("length checked"),
                ),
                maximum_micros: u32::from_le_bytes(
                    body[16..20].try_into().expect("length checked"),
                ),
            },
        })
    }
}

pub fn build_echo_request(header: PacketHeader, echo: EchoBody) -> Vec<u8> {
    encode_control(
        PacketHeader::new(
            PacketType::EchoRequest,
            header.encryption,
            header.session_id,
            header.token,
        ),
        &echo.encode(),
    )
}

pub fn build_echo_response(request: PacketHeader, request_body: &[u8]) -> Result<Vec<u8>> {
    let body = EchoBody::decode(request_body)?.encode();
    Ok(encode_control(
        PacketHeader::new(
            PacketType::EchoResponse,
            request.encryption,
            request.session_id,
            request.token,
        ),
        &body,
    ))
}

pub fn build_ping_request() -> Vec<u8> {
    encode_control(
        PacketHeader::new(
            PacketType::PingRequest,
            EncryptionMethod::None,
            PING_SESSION_ID,
            PING_TOKEN,
        ),
        &[],
    )
}

pub fn build_ping_response() -> Vec<u8> {
    encode_control(
        PacketHeader::new(
            PacketType::PingResponse,
            EncryptionMethod::None,
            PING_SESSION_ID,
            PING_TOKEN,
        ),
        &[],
    )
}

pub fn find_tlv(attributes: &[Tlv], kind: TlvType) -> Option<&Tlv> {
    attributes.iter().find(|attribute| attribute.kind == kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(value: &str) -> Vec<u8> {
        let compact: String = value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        (0..compact.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&compact[offset..offset + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn packet_registry_matches_android_230() {
        assert_eq!(
            PacketType::ALL.map(|kind| kind as u8),
            [
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x22, 0x23, 0x24, 0x28,
                0x29, 0x2a
            ]
        );
    }

    #[test]
    fn ping_matches_specification_vector() {
        assert_eq!(
            build_ping_request(),
            decode_hex("2900ffffffffffff0a6dd17cf9e6d40493ee1f0e6b4dc521")
        );
    }

    #[test]
    fn signed_close_matches_specification_vector() {
        let header = PacketHeader::new(
            PacketType::Close,
            EncryptionMethod::Xor,
            0x1234,
            0x89ab_cdef,
        );
        assert_eq!(
            build_close(header),
            decode_hex("1701123489abcdefc1ee1606aa425b8bd62cafd88e89f052")
        );
        assert!(decode_packet(&header.encode()).is_ok());
    }

    #[test]
    fn open_matches_specification_vector() {
        assert_eq!(
            build_open("alice", "secret", 1400, EncryptionMethod::Xor, None, None).unwrap(),
            decode_hex(
                "13010000000000003601680de3a6b3dd336ac557c87b501b
                 030405780107616c6963650212567e3c4f58d08532529f8191
                 a0ae0d9d080301"
            )
        );
    }

    #[test]
    fn tlv_parser_matches_android_trailing_suffix_quirk() {
        let mut bytes = Vec::new();
        Tlv::mtu(1400).encode(&mut bytes).unwrap();
        bytes.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(Tlv::parse_all(&bytes).unwrap(), [Tlv::mtu(1400)]);
        assert!(Tlv::parse_complete(&bytes).is_err());
    }

    #[test]
    fn integer_and_prefix_decoders_match_android() {
        for (bytes, expected) in [
            (vec![2], 2),
            (vec![1, 2], 0x0102),
            (vec![1, 2, 3, 4], 0x0102_0304),
        ] {
            let tlv = Tlv::new(TlvType::Mtu, bytes).unwrap();
            assert_eq!(tlv.as_integer().unwrap(), expected);
        }
        let ip = Tlv::new(TlvType::Ip, [192, 0, 2, 1, 99]).unwrap();
        assert_eq!(ip.first_ipv4().unwrap(), Ipv4Addr::new(192, 0, 2, 1));
    }

    #[test]
    fn echo_body_is_twenty_bytes_and_little_endian() {
        let echo = EchoBody::new(
            0x0102_0304_0506_0708,
            EchoDelayStats {
                current_micros: 0x1112_1314,
                minimum_micros: 0x2122_2324,
                maximum_micros: 0x3132_3334,
            },
        );
        assert_eq!(
            echo.encode(),
            [
                8, 7, 6, 5, 4, 3, 2, 1, 0x14, 0x13, 0x12, 0x11, 0x24, 0x23, 0x22, 0x21, 0x34, 0x33,
                0x32, 0x31
            ]
        );
        assert_eq!(EchoBody::decode(&echo.encode()).unwrap(), echo);
    }
}
