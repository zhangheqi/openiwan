//! Segment Routing (SEGRT) transport recovered from iWAN Android 2.3.0.

use crate::crypto::{AES_BLOCK_LEN, DataCipher};
use crate::fragment::{Fragment, SrFragmentReassembler, fragment_sr_packet, trim_ip_packet};
use crate::protocol::{EncryptionMethod, HEADER_LEN, PacketHeader, PacketType};
use crate::{Error, Result};
use aes::{Aes128, Aes256};
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

pub const MAX_LINKS: usize = 6;
pub const SR_FIXED_HEADER_LEN: usize = 4;
pub const SR_MONITOR_BODY_LEN: usize = 40;
pub const SR_MONITOR_PERIOD: Duration = Duration::from_micros(1_000_000);
pub const SR_PEER_DOWN_AFTER: Duration = Duration::from_micros(5_000_000);

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum SrEncryptionAlgorithm {
    #[default]
    None = 0,
    Aes128 = 1,
    Aes256 = 2,
}

impl TryFrom<u8> for SrEncryptionAlgorithm {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Aes128),
            2 => Ok(Self::Aes256),
            _ => Err(Error::InvalidSegmentRouting(
                "unknown outer encryption algorithm",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrHeader {
    pub next_id: u8,
    pub links: Vec<u32>,
    pub algorithm: SrEncryptionAlgorithm,
    pub padding_length: u8,
}

impl SrHeader {
    pub fn outbound(
        forward_links: &[u32],
        algorithm: SrEncryptionAlgorithm,
        padding_length: u8,
    ) -> Result<Self> {
        validate_links(forward_links)?;
        if padding_length > 31 {
            return Err(Error::InvalidSegmentRouting(
                "padding length exceeds five-bit field",
            ));
        }
        let mut links = forward_links.to_vec();
        links.reverse();
        Ok(Self {
            next_id: u8::try_from(links.len() - 1).expect("at most six links"),
            links,
            algorithm,
            padding_length,
        })
    }

    pub fn parse(input: &[u8]) -> Result<(Self, usize)> {
        if input.len() < SR_FIXED_HEADER_LEN {
            return Err(Error::PacketTooShort {
                minimum: SR_FIXED_HEADER_LEN,
                actual: input.len(),
            });
        }
        if input[0] != PacketType::SegmentRouting as u8 {
            return Err(Error::InvalidSegmentRouting(
                "outer type is not SEGMENT_ROUTING",
            ));
        }
        let link_count = usize::from(input[2]);
        if !(1..=MAX_LINKS).contains(&link_count) {
            return Err(Error::InvalidSegmentRouting("link count is outside 1..=6"));
        }
        if usize::from(input[1]) >= link_count {
            return Err(Error::InvalidSegmentRouting(
                "next_id is outside the link array",
            ));
        }
        let header_length = SR_FIXED_HEADER_LEN + 4 * link_count;
        if input.len() < header_length {
            return Err(Error::PacketTooShort {
                minimum: header_length,
                actual: input.len(),
            });
        }
        let flags = input[3];
        let algorithm = SrEncryptionAlgorithm::try_from(flags & 0x07)?;
        let padding_length = flags >> 3;
        let mut links = Vec::with_capacity(link_count);
        for chunk in input[4..header_length].chunks_exact(4) {
            let link = u32::from_be_bytes(chunk.try_into().expect("chunk size is four"));
            if !(1..=0x00ff_ffff).contains(&link) {
                return Err(Error::InvalidSegmentRouting(
                    "link ID is outside 1..=0x00ffffff",
                ));
            }
            links.push(link);
        }
        Ok((
            Self {
                next_id: input[1],
                links,
                algorithm,
                padding_length,
            },
            header_length,
        ))
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_links(&self.links)?;
        if usize::from(self.next_id) >= self.links.len() {
            return Err(Error::InvalidSegmentRouting(
                "next_id is outside the link array",
            ));
        }
        if self.padding_length > 31 {
            return Err(Error::InvalidSegmentRouting(
                "padding length exceeds five-bit field",
            ));
        }
        let mut output = Vec::with_capacity(SR_FIXED_HEADER_LEN + 4 * self.links.len());
        output.push(PacketType::SegmentRouting as u8);
        output.push(self.next_id);
        output.push(u8::try_from(self.links.len()).expect("at most six links"));
        output.push((self.padding_length << 3) | self.algorithm as u8);
        for link in &self.links {
            output.extend_from_slice(&link.to_be_bytes());
        }
        Ok(output)
    }

    pub fn validate_return_path(&self, forward_links: &[u32]) -> Result<()> {
        validate_links(forward_links)?;
        if self.next_id != 0 {
            return Err(Error::InvalidSegmentRouting(
                "returned SR packet does not have next_id zero",
            ));
        }
        if self.links != forward_links {
            return Err(Error::InvalidSegmentRouting(
                "returned SR path does not match configuration",
            ));
        }
        Ok(())
    }
}

fn validate_links(links: &[u32]) -> Result<()> {
    if !(1..=MAX_LINKS).contains(&links.len()) {
        return Err(Error::InvalidSegmentRouting("link count is outside 1..=6"));
    }
    if links.iter().any(|link| !(1..=0x00ff_ffff).contains(link)) {
        return Err(Error::InvalidSegmentRouting(
            "link ID is outside 1..=0x00ffffff",
        ));
    }
    Ok(())
}

#[derive(Clone)]
pub struct SrOuterCipher {
    algorithm: SrEncryptionAlgorithm,
    key: [u8; 32],
}

impl std::fmt::Debug for SrOuterCipher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SrOuterCipher")
            .field("algorithm", &self.algorithm)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SrOuterCipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl SrOuterCipher {
    pub fn new(algorithm: SrEncryptionAlgorithm, raw_utf8_key: &str) -> Result<Self> {
        let required = match algorithm {
            SrEncryptionAlgorithm::None => 0,
            SrEncryptionAlgorithm::Aes128 => 16,
            SrEncryptionAlgorithm::Aes256 => 32,
        };
        if raw_utf8_key.len() < required {
            return Err(Error::InvalidConfig(format!(
                "SR {algorithm:?} key must contain at least {required} UTF-8 bytes"
            )));
        }
        let mut key = [0_u8; 32];
        key[..required].copy_from_slice(&raw_utf8_key.as_bytes()[..required]);
        Ok(Self { algorithm, key })
    }

    pub const fn algorithm(&self) -> SrEncryptionAlgorithm {
        self.algorithm
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, u8)> {
        if self.algorithm == SrEncryptionAlgorithm::None {
            return Ok((plaintext.to_vec(), 0));
        }
        let padding = (AES_BLOCK_LEN - plaintext.len() % AES_BLOCK_LEN) % AES_BLOCK_LEN;
        let mut output = vec![0_u8; plaintext.len() + padding];
        output[..plaintext.len()].copy_from_slice(plaintext);
        self.crypt_blocks(&mut output, true);
        Ok((
            output,
            u8::try_from(padding).expect("AES padding is at most 15"),
        ))
    }

    pub fn decrypt(&self, ciphertext: &[u8], padding_length: u8) -> Result<Vec<u8>> {
        if self.algorithm == SrEncryptionAlgorithm::None {
            if padding_length != 0 {
                return Err(Error::InvalidSegmentRouting(
                    "unencrypted SR packet declares padding",
                ));
            }
            return Ok(ciphertext.to_vec());
        }
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(AES_BLOCK_LEN) {
            return Err(Error::InvalidSegmentRouting(
                "outer ciphertext is empty or not block-aligned",
            ));
        }
        if usize::from(padding_length) >= ciphertext.len() {
            return Err(Error::InvalidSegmentRouting(
                "outer padding is not smaller than plaintext",
            ));
        }
        let mut output = ciphertext.to_vec();
        self.crypt_blocks(&mut output, false);
        output.truncate(output.len() - usize::from(padding_length));
        Ok(output)
    }

    fn crypt_blocks(&self, bytes: &mut [u8], encrypt: bool) {
        match self.algorithm {
            SrEncryptionAlgorithm::None => {}
            SrEncryptionAlgorithm::Aes128 => {
                let cipher = Aes128::new(GenericArray::from_slice(&self.key[..16]));
                for block in bytes.chunks_exact_mut(AES_BLOCK_LEN) {
                    if encrypt {
                        cipher.encrypt_block(GenericArray::from_mut_slice(block));
                    } else {
                        cipher.decrypt_block(GenericArray::from_mut_slice(block));
                    }
                }
            }
            SrEncryptionAlgorithm::Aes256 => {
                let cipher = Aes256::new(GenericArray::from_slice(&self.key));
                for block in bytes.chunks_exact_mut(AES_BLOCK_LEN) {
                    if encrypt {
                        cipher.encrypt_block(GenericArray::from_mut_slice(block));
                    } else {
                        cipher.decrypt_block(GenericArray::from_mut_slice(block));
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SrSessionTuple {
    pub session_id: u16,
    pub token: u32,
    pub encryption: EncryptionMethod,
}

impl SrSessionTuple {
    pub const fn header(
        self,
        packet_type: PacketType,
        encryption: EncryptionMethod,
    ) -> PacketHeader {
        PacketHeader::new(packet_type, encryption, self.session_id, self.token)
    }
}

/// Encode one IP packet into one normal SR datagram or exactly two fragments.
pub fn encode_data(
    packet: &[u8],
    payload_mtu: usize,
    fragment_id: u32,
    forward_links: &[u32],
    session: SrSessionTuple,
    session_cipher: &dyn DataCipher,
    outer_cipher: &SrOuterCipher,
) -> Result<Vec<Vec<u8>>> {
    let version = packet
        .first()
        .map(|byte| byte >> 4)
        .ok_or(Error::InvalidFragment("empty inner IP packet"))?;
    if !matches!(version, 4 | 6) {
        return Err(Error::InvalidFragment("unknown inner IP version"));
    }
    let packet = trim_ip_packet(packet)?;

    if packet.len() > payload_mtu {
        let inner_encryption_enabled = version == 4 && session.encryption != EncryptionMethod::None;
        if inner_encryption_enabled || outer_cipher.algorithm() != SrEncryptionAlgorithm::None {
            return Err(Error::FragmentEncryptionUnsupported);
        }
        let fragments = fragment_sr_packet(packet, payload_mtu, fragment_id)?;
        let packet_type = if version == 4 {
            PacketType::IpFragment
        } else {
            PacketType::IpFragmentIpv6
        };
        return fragments
            .iter()
            .map(|fragment| {
                let header = SrHeader::outbound(forward_links, SrEncryptionAlgorithm::None, 0)?;
                let mut datagram = header.encode()?;
                datagram.extend_from_slice(
                    &session.header(packet_type, EncryptionMethod::None).encode(),
                );
                datagram.extend_from_slice(&fragment.encode_sr()?);
                Ok(datagram)
            })
            .collect();
    }

    let (packet_type, inner_encryption, inner_payload) = if version == 6 {
        (
            PacketType::DataIpv6,
            EncryptionMethod::None,
            packet.to_vec(),
        )
    } else {
        match session.encryption {
            EncryptionMethod::None => (PacketType::Data, EncryptionMethod::None, packet.to_vec()),
            EncryptionMethod::Xor => (
                PacketType::DataEncrypted,
                EncryptionMethod::Xor,
                session_cipher.encrypt(packet)?,
            ),
            EncryptionMethod::Aes => {
                if !packet.len().is_multiple_of(AES_BLOCK_LEN) {
                    return Err(Error::FragmentEncryptionUnsupported);
                }
                (
                    PacketType::DataEncrypted,
                    EncryptionMethod::Aes,
                    session_cipher.encrypt(packet)?,
                )
            }
        }
    };
    if inner_payload.len() > payload_mtu {
        return Err(Error::FragmentEncryptionUnsupported);
    }

    let (outer_payload, padding_length) = outer_cipher.encrypt(&inner_payload)?;
    if outer_payload.len() > payload_mtu {
        return Err(Error::FragmentEncryptionUnsupported);
    }
    let sr_header = SrHeader::outbound(forward_links, outer_cipher.algorithm(), padding_length)?;
    let mut datagram =
        Vec::with_capacity(sr_header.encode()?.len() + HEADER_LEN + outer_payload.len());
    datagram.extend_from_slice(&sr_header.encode()?);
    datagram.extend_from_slice(&session.header(packet_type, inner_encryption).encode());
    datagram.extend_from_slice(&outer_payload);
    Ok(vec![datagram])
}

#[derive(Debug)]
pub enum SrDecoded {
    Data(Vec<u8>),
    Fragment {
        packet_type: PacketType,
        fragment: Fragment,
    },
    EchoRequest(SrMonitorBody),
    EchoResponse(SrMonitorBody),
}

pub fn decode_datagram(
    datagram: &[u8],
    forward_links: &[u32],
    session: SrSessionTuple,
    session_cipher: &dyn DataCipher,
    outer_cipher: &SrOuterCipher,
) -> Result<SrDecoded> {
    let (sr_header, sr_header_len) = SrHeader::parse(datagram)?;
    sr_header.validate_return_path(forward_links)?;
    if datagram.len() < sr_header_len + HEADER_LEN {
        return Err(Error::PacketTooShort {
            minimum: sr_header_len + HEADER_LEN,
            actual: datagram.len(),
        });
    }
    let inner = PacketHeader::decode_inner(&datagram[sr_header_len..])?;
    if inner.session_id != session.session_id || inner.token != session.token {
        return Err(Error::InvalidSegmentRouting(
            "inner session tuple does not match",
        ));
    }
    let wire_payload = &datagram[sr_header_len + HEADER_LEN..];

    match inner.packet_type {
        PacketType::EchoRequest | PacketType::EchoResponse => {
            if sr_header.algorithm != SrEncryptionAlgorithm::None
                || sr_header.padding_length != 0
                || inner.encryption != EncryptionMethod::None
            {
                return Err(Error::InvalidSegmentRouting("SR echo packet is encrypted"));
            }
            let monitor = SrMonitorBody::decode(wire_payload)?;
            if inner.packet_type == PacketType::EchoRequest {
                Ok(SrDecoded::EchoRequest(monitor))
            } else {
                Ok(SrDecoded::EchoResponse(monitor))
            }
        }
        PacketType::IpFragment | PacketType::IpFragmentIpv6 => {
            if sr_header.algorithm != SrEncryptionAlgorithm::None
                || sr_header.padding_length != 0
                || inner.encryption != EncryptionMethod::None
            {
                return Err(Error::FragmentEncryptionUnsupported);
            }
            Ok(SrDecoded::Fragment {
                packet_type: inner.packet_type,
                fragment: Fragment::parse_sr(wire_payload)?,
            })
        }
        PacketType::Data | PacketType::DataIpv6 | PacketType::DataEncrypted => {
            if sr_header.algorithm != outer_cipher.algorithm() {
                return Err(Error::InvalidSegmentRouting(
                    "outer algorithm does not match configuration",
                ));
            }
            let outer_plain = outer_cipher.decrypt(wire_payload, sr_header.padding_length)?;
            let plain = if inner.packet_type == PacketType::DataEncrypted {
                if inner.encryption != session.encryption
                    || !matches!(
                        session.encryption,
                        EncryptionMethod::Xor | EncryptionMethod::Aes
                    )
                {
                    return Err(Error::InvalidSegmentRouting(
                        "inner encryption does not match session",
                    ));
                }
                session_cipher.decrypt(&outer_plain)?
            } else {
                if inner.encryption != EncryptionMethod::None {
                    return Err(Error::InvalidSegmentRouting(
                        "plain inner packet has a nonzero encryption method",
                    ));
                }
                outer_plain
            };
            let expected_version = if inner.packet_type == PacketType::DataIpv6 {
                6
            } else {
                4
            };
            let packet = trim_ip_packet(&plain)?;
            if packet[0] >> 4 != expected_version {
                return Err(Error::InvalidSegmentRouting(
                    "inner packet type does not match IP version",
                ));
            }
            Ok(SrDecoded::Data(packet.to_vec()))
        }
        _ => Err(Error::InvalidSegmentRouting(
            "unsupported SR inner packet type",
        )),
    }
}

pub fn insert_fragment(
    reassembler: &mut SrFragmentReassembler,
    packet_type: PacketType,
    fragment: Fragment,
    now: Instant,
) -> Result<Option<Vec<u8>>> {
    let packet = reassembler.insert(fragment, now)?;
    if let Some(packet) = packet {
        let packet = trim_ip_packet(&packet)?;
        let expected = if packet_type == PacketType::IpFragment {
            4
        } else {
            6
        };
        if packet[0] >> 4 != expected {
            return Err(Error::InvalidFragment(
                "reassembled IP version does not match SR fragment type",
            ));
        }
        Ok(Some(packet.to_vec()))
    } else {
        Ok(None)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SrMonitorBody {
    pub tick_micros: u64,
    pub current_delay_micros: u32,
    pub minimum_delay_micros: u32,
    pub maximum_delay_micros: u32,
    pub sr_id: u32,
    pub version: u8,
    pub marker: u8,
    pub flags: u16,
    pub tx_count: u32,
    pub rx_count: u32,
}

impl SrMonitorBody {
    pub fn encode(self) -> [u8; SR_MONITOR_BODY_LEN] {
        let mut body = [0_u8; SR_MONITOR_BODY_LEN];
        body[0..8].copy_from_slice(&self.tick_micros.to_le_bytes());
        body[8..12].copy_from_slice(&self.current_delay_micros.to_le_bytes());
        body[12..16].copy_from_slice(&self.minimum_delay_micros.to_le_bytes());
        body[16..20].copy_from_slice(&self.maximum_delay_micros.to_le_bytes());
        body[20..24].copy_from_slice(b"SRID");
        body[24..28].copy_from_slice(&self.sr_id.to_be_bytes());
        body[28] = self.version;
        body[29] = self.marker;
        body[30..32].copy_from_slice(&self.flags.to_le_bytes());
        body[32..36].copy_from_slice(&self.tx_count.to_le_bytes());
        body[36..40].copy_from_slice(&self.rx_count.to_le_bytes());
        body
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        if body.len() < SR_MONITOR_BODY_LEN {
            return Err(Error::PacketTooShort {
                minimum: SR_MONITOR_BODY_LEN,
                actual: body.len(),
            });
        }
        if &body[20..24] != b"SRID" {
            return Err(Error::InvalidSegmentRouting(
                "SR monitor magic does not equal SRID",
            ));
        }
        Ok(Self {
            tick_micros: u64::from_le_bytes(body[0..8].try_into().expect("length checked")),
            current_delay_micros: u32::from_le_bytes(
                body[8..12].try_into().expect("length checked"),
            ),
            minimum_delay_micros: u32::from_le_bytes(
                body[12..16].try_into().expect("length checked"),
            ),
            maximum_delay_micros: u32::from_le_bytes(
                body[16..20].try_into().expect("length checked"),
            ),
            sr_id: u32::from_be_bytes(body[24..28].try_into().expect("length checked")),
            version: body[28],
            marker: body[29],
            flags: u16::from_le_bytes(body[30..32].try_into().expect("length checked")),
            tx_count: u32::from_le_bytes(body[32..36].try_into().expect("length checked")),
            rx_count: u32::from_le_bytes(body[36..40].try_into().expect("length checked")),
        })
    }
}

pub fn encode_monitor_datagram(
    packet_type: PacketType,
    body: SrMonitorBody,
    forward_links: &[u32],
    session: SrSessionTuple,
) -> Result<Vec<u8>> {
    if !matches!(
        packet_type,
        PacketType::EchoRequest | PacketType::EchoResponse
    ) {
        return Err(Error::InvalidSegmentRouting(
            "monitor inner type is not echo",
        ));
    }
    let header = SrHeader::outbound(forward_links, SrEncryptionAlgorithm::None, 0)?;
    let mut datagram = header.encode()?;
    datagram.extend_from_slice(&session.header(packet_type, EncryptionMethod::None).encode());
    datagram.extend_from_slice(&body.encode());
    Ok(datagram)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrMonitorState {
    Idle,
    Probing,
    Established,
    PeerDown,
}

#[derive(Debug)]
pub struct SrMonitor {
    state: SrMonitorState,
    sr_id: u32,
    tx_count: u32,
    rx_count: u32,
    last_response: Option<Instant>,
    delay: DelayAccumulator,
}

impl SrMonitor {
    pub const fn new(sr_id: u32) -> Self {
        Self {
            state: SrMonitorState::Idle,
            sr_id,
            tx_count: 0,
            rx_count: 0,
            last_response: None,
            delay: DelayAccumulator::new(),
        }
    }

    pub const fn state(&self) -> SrMonitorState {
        self.state
    }

    pub fn request(&mut self, tick_micros: u64) -> SrMonitorBody {
        let initial = matches!(self.state, SrMonitorState::Idle | SrMonitorState::PeerDown);
        if initial {
            self.tx_count = 1;
            self.rx_count = 0;
            self.state = SrMonitorState::Probing;
        } else {
            self.tx_count = self.tx_count.wrapping_add(1);
        }
        SrMonitorBody {
            tick_micros,
            current_delay_micros: self.delay.current,
            minimum_delay_micros: self.delay.minimum,
            maximum_delay_micros: self.delay.maximum,
            sr_id: self.sr_id,
            version: 0,
            marker: 0x79,
            flags: u16::from(initial),
            tx_count: self.tx_count,
            rx_count: self.rx_count,
        }
    }

    pub fn accept_response(
        &mut self,
        response: SrMonitorBody,
        now: Instant,
        rtt_micros: u32,
    ) -> Result<()> {
        if response.sr_id != self.sr_id {
            return Err(Error::InvalidSegmentRouting(
                "SR monitor response has the wrong SR ID",
            ));
        }
        if response.flags & 0x0002 == 0 {
            return Err(Error::InvalidSegmentRouting(
                "SR monitor response does not enable counter processing",
            ));
        }
        self.rx_count = response.rx_count;
        self.last_response = Some(now);
        self.delay.observe(rtt_micros);
        self.state = SrMonitorState::Established;
        Ok(())
    }

    pub fn update_peer_state(&mut self, now: Instant) -> SrMonitorState {
        if self
            .last_response
            .and_then(|last| now.checked_duration_since(last))
            .is_some_and(|age| age > SR_PEER_DOWN_AFTER)
        {
            self.state = SrMonitorState::PeerDown;
        }
        self.state
    }
}

#[derive(Debug, Clone, Copy)]
struct DelayAccumulator {
    current: u32,
    minimum: u32,
    maximum: u32,
}

impl DelayAccumulator {
    const fn new() -> Self {
        Self {
            current: 0,
            minimum: 0,
            maximum: 0,
        }
    }

    fn observe(&mut self, value: u32) {
        self.current = value;
        self.minimum = if self.minimum == 0 {
            value
        } else {
            self.minimum.min(value)
        };
        self.maximum = self.maximum.max(value);
    }
}

#[derive(Debug, Default)]
pub struct SrMonitorResponder {
    active: bool,
    receive_count: u32,
}

impl SrMonitorResponder {
    pub fn respond(&mut self, request: SrMonitorBody) -> Option<SrMonitorBody> {
        if request.flags & 0x0001 != 0 {
            self.active = true;
            self.receive_count = 1;
            Some(SrMonitorBody {
                flags: 0x0003,
                tx_count: request.tx_count,
                rx_count: 1,
                ..request
            })
        } else if self.active {
            self.receive_count = self.receive_count.wrapping_add(1);
            Some(SrMonitorBody {
                flags: 0x0002,
                tx_count: request.tx_count,
                rx_count: self.receive_count,
                ..request
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::NoCipher;

    fn decode_hex(value: &str) -> Vec<u8> {
        let compact: String = value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        (0..compact.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&compact[offset..offset + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn sr_header_matches_specification_vector() {
        let header = SrHeader::outbound(
            &[0x0000_0001, 0x0000_0102, 0x00ab_cdef],
            SrEncryptionAlgorithm::None,
            0,
        )
        .unwrap();
        assert_eq!(
            header.encode().unwrap(),
            decode_hex("2802030000abcdef0000010200000001")
        );
    }

    #[test]
    fn outer_aes_matches_specification_vector() {
        let cipher = SrOuterCipher::new(SrEncryptionAlgorithm::Aes128, "0123456789abcdef").unwrap();
        let plain = decode_hex("450000140000000040010000c0000201c6336402");
        let tuple = SrSessionTuple {
            session_id: 0x1234,
            token: 0x89ab_cdef,
            encryption: EncryptionMethod::None,
        };
        assert_eq!(
            encode_data(&plain, 1400, 1, &[1], tuple, &NoCipher, &cipher).unwrap()[0],
            decode_hex(
                "28000161000000011400123489abcdef
                 0a1a12230e47a826f61cd0c3ce7c3b5a
                 c5ae982289e5311a947d83d2bb4f8584"
            )
        );
    }

    #[test]
    fn ipv6_fragmentation_disables_negotiated_inner_encryption() {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x60;
        let tuple = SrSessionTuple {
            session_id: 0x1234,
            token: 0x89ab_cdef,
            encryption: EncryptionMethod::Aes,
        };
        let outer = SrOuterCipher::new(SrEncryptionAlgorithm::None, "").unwrap();
        let datagrams = encode_data(&packet, 32, 1, &[1], tuple, &NoCipher, &outer).unwrap();
        assert_eq!(datagrams.len(), 2);
        for datagram in datagrams {
            let (header, header_length) = SrHeader::parse(&datagram).unwrap();
            assert_eq!(header.algorithm, SrEncryptionAlgorithm::None);
            let inner = PacketHeader::decode_inner(&datagram[header_length..]).unwrap();
            assert_eq!(inner.packet_type, PacketType::IpFragmentIpv6);
            assert_eq!(inner.encryption, EncryptionMethod::None);
        }
    }

    #[test]
    fn returned_path_is_directional() {
        let (returned, _) =
            SrHeader::parse(&decode_hex("28000300000000010000010200abcdef")).unwrap();
        returned
            .validate_return_path(&[1, 0x102, 0x00ab_cdef])
            .unwrap();
    }

    #[test]
    fn monitor_handshake_matches_recovered_flags() {
        let mut client = SrMonitor::new(7);
        let request = client.request(100);
        assert_eq!(
            (request.flags, request.tx_count, request.rx_count),
            (1, 1, 0)
        );
        let mut server = SrMonitorResponder::default();
        let response = server.respond(request).unwrap();
        assert_eq!(
            (response.flags, response.tx_count, response.rx_count),
            (3, 1, 1)
        );
        client
            .accept_response(response, Instant::now(), 50)
            .unwrap();
        assert_eq!(client.state(), SrMonitorState::Established);
        let later = client.request(200);
        assert_eq!(later.flags, 0);
        assert_eq!(server.respond(later).unwrap().flags, 2);
        assert!(
            SrMonitorResponder::default()
                .respond(SrMonitorBody { flags: 0, ..later })
                .is_none()
        );
    }

    #[test]
    fn monitor_body_uses_mixed_endianness() {
        let body = SrMonitorBody {
            tick_micros: 1,
            current_delay_micros: 2,
            minimum_delay_micros: 3,
            maximum_delay_micros: 4,
            sr_id: 0x0102_0304,
            version: 0,
            marker: 0x79,
            flags: 3,
            tx_count: 5,
            rx_count: 6,
        };
        let encoded = body.encode();
        assert_eq!(&encoded[20..28], b"SRID\x01\x02\x03\x04");
        assert_eq!(SrMonitorBody::decode(&encoded).unwrap(), body);
    }
}
