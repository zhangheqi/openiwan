//! Parser and bounded reassembly queue for legacy `IPFRAG`/`IPFRAG6` packets.
//!
//! The on-wire fragment prefix is eight bytes:
//!
//! ```text
//!  0               31 32                                             63
//! +-------------------+--+--+-------------------------+---------------+
//! | fragment id (BE)  |E |R | offset (13 bits)        | len (11 bits) |
//! +-------------------+--+--+-------------------------+---------------+
//! ```
//!
//! The second word is a native little-endian C bitfield in the macOS 2.3.0
//! client: bit 0 is EOP, bit 1 is reserved, bits 2..14 are the byte offset,
//! and bits 15..25 are the payload length.

use crate::{Error, Result};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const FRAGMENT_PREFIX_LEN: usize = 8;
pub const MAX_FRAGMENT_OFFSET: u16 = 0x1fff;
pub const MAX_FRAGMENT_LENGTH: u16 = 0x07ff;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    pub id: u32,
    pub end_of_packet: bool,
    pub offset: u16,
    pub data: Vec<u8>,
}

impl Fragment {
    pub fn parse(input: &[u8]) -> Result<Self> {
        if input.len() < FRAGMENT_PREFIX_LEN {
            return Err(Error::InvalidFragment("fewer than eight prefix bytes"));
        }
        let id = u32::from_be_bytes(input[0..4].try_into().expect("length checked"));
        let packed = u32::from_le_bytes(input[4..8].try_into().expect("length checked"));
        if packed & 0xfc00_0002 != 0 {
            return Err(Error::InvalidFragment("reserved bits are non-zero"));
        }
        let end_of_packet = packed & 1 != 0;
        let offset = ((packed >> 2) & u32::from(MAX_FRAGMENT_OFFSET)) as u16;
        let length = ((packed >> 15) & u32::from(MAX_FRAGMENT_LENGTH)) as usize;
        if length == 0 {
            return Err(Error::InvalidFragment("zero payload length"));
        }
        if input.len() - FRAGMENT_PREFIX_LEN < length {
            return Err(Error::InvalidFragment(
                "declared payload length exceeds datagram",
            ));
        }
        Ok(Self {
            id,
            end_of_packet,
            offset,
            data: input[FRAGMENT_PREFIX_LEN..FRAGMENT_PREFIX_LEN + length].to_vec(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.offset > MAX_FRAGMENT_OFFSET {
            return Err(Error::InvalidFragment("offset exceeds 13-bit field"));
        }
        let length = u16::try_from(self.data.len())
            .map_err(|_| Error::InvalidFragment("payload exceeds 11-bit length field"))?;
        if length == 0 || length > MAX_FRAGMENT_LENGTH {
            return Err(Error::InvalidFragment("payload length is outside 1..=2047"));
        }
        let mut packed = u32::from(self.offset) << 2;
        packed |= u32::from(length) << 15;
        packed |= u32::from(self.end_of_packet);

        let mut output = Vec::with_capacity(FRAGMENT_PREFIX_LEN + self.data.len());
        output.extend_from_slice(&self.id.to_be_bytes());
        output.extend_from_slice(&packed.to_le_bytes());
        output.extend_from_slice(&self.data);
        Ok(output)
    }

    pub fn end_offset(&self) -> Result<usize> {
        usize::from(self.offset)
            .checked_add(self.data.len())
            .ok_or(Error::FragmentTooLarge)
    }
}

#[derive(Debug)]
struct FragmentGroup {
    created: Instant,
    parts: Vec<Fragment>,
}

/// A denial-of-service-resistant fragment reassembly queue.
#[derive(Debug)]
pub struct FragmentReassembler {
    groups: HashMap<u32, FragmentGroup>,
    timeout: Duration,
    max_groups: usize,
    max_packet_size: usize,
}

impl Default for FragmentReassembler {
    fn default() -> Self {
        Self::new(Duration::from_secs(5), 256, u16::MAX as usize)
    }
}

impl FragmentReassembler {
    pub fn new(timeout: Duration, max_groups: usize, max_packet_size: usize) -> Self {
        Self {
            groups: HashMap::new(),
            timeout,
            max_groups,
            max_packet_size,
        }
    }

    pub fn clear(&mut self) {
        self.groups.clear();
    }

    pub fn pending_groups(&self) -> usize {
        self.groups.len()
    }

    pub fn purge_expired(&mut self, now: Instant) {
        self.groups.retain(|_, group| {
            now.checked_duration_since(group.created)
                .is_none_or(|age| age <= self.timeout)
        });
    }

    /// Insert one fragment. Returns the full IP packet once all offsets from
    /// zero through the EOP fragment are contiguous.
    pub fn insert(&mut self, fragment: Fragment, now: Instant) -> Result<Option<Vec<u8>>> {
        self.purge_expired(now);
        if fragment.end_offset()? > self.max_packet_size {
            return Err(Error::FragmentTooLarge);
        }
        if !self.groups.contains_key(&fragment.id) && self.groups.len() >= self.max_groups {
            if let Some(oldest_id) = self
                .groups
                .iter()
                .min_by_key(|(_, group)| group.created)
                .map(|(id, _)| *id)
            {
                self.groups.remove(&oldest_id);
            }
        }

        let id = fragment.id;
        let group = self.groups.entry(id).or_insert_with(|| FragmentGroup {
            created: now,
            parts: Vec::new(),
        });

        if group.parts.iter().any(|part| {
            part.offset == fragment.offset
                && part.end_of_packet == fragment.end_of_packet
                && part.data == fragment.data
        }) {
            return Ok(None);
        }

        let new_start = usize::from(fragment.offset);
        let new_end = fragment.end_offset()?;
        if group.parts.iter().any(|part| {
            let start = usize::from(part.offset);
            let end = start + part.data.len();
            new_start < end && start < new_end
        }) {
            self.groups.remove(&id);
            return Err(Error::InvalidFragment("overlapping fragment offsets"));
        }

        group.parts.push(fragment);
        group.parts.sort_unstable_by_key(|part| part.offset);

        let mut expected_offset = 0_usize;
        let mut total_length = None;
        let mut eop_index = None;
        for (index, part) in group.parts.iter().enumerate() {
            if usize::from(part.offset) != expected_offset {
                return Ok(None);
            }
            expected_offset = part.end_offset()?;
            if part.end_of_packet {
                total_length = Some(expected_offset);
                eop_index = Some(index);
                break;
            }
        }

        let Some(total_length) = total_length else {
            return Ok(None);
        };
        if eop_index.is_some_and(|index| index + 1 != group.parts.len()) {
            self.groups.remove(&id);
            return Err(Error::InvalidFragment("data follows the EOP fragment"));
        }
        if total_length > self.max_packet_size {
            self.groups.remove(&id);
            return Err(Error::FragmentTooLarge);
        }

        let group = self.groups.remove(&id).expect("group was just present");
        let mut packet = Vec::with_capacity(total_length);
        for part in group.parts {
            if packet.len() == total_length {
                break;
            }
            packet.extend_from_slice(&part.data);
        }
        if packet.len() != total_length {
            return Err(Error::InvalidFragment(
                "data follows EOP or reassembled length changed",
            ));
        }
        Ok(Some(packet))
    }
}

/// Remove protocol-level zero padding by using the length in the inner IP
/// header. The returned slice is validated but no transport checksum is
/// modified.
pub fn trim_ip_packet(packet: &[u8]) -> Result<&[u8]> {
    let Some(version) = packet.first().map(|byte| byte >> 4) else {
        return Err(Error::InvalidFragment("empty inner IP packet"));
    };
    let expected = match version {
        4 => {
            if packet.len() < 20 {
                return Err(Error::InvalidFragment("truncated IPv4 header"));
            }
            usize::from(u16::from_be_bytes([packet[2], packet[3]]))
        }
        6 => {
            if packet.len() < 40 {
                return Err(Error::InvalidFragment("truncated IPv6 header"));
            }
            40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]))
        }
        _ => return Err(Error::InvalidFragment("unknown inner IP version")),
    };
    if expected == 0 || expected > packet.len() {
        return Err(Error::InvalidFragment(
            "inner IP length exceeds decrypted payload",
        ));
    }
    Ok(&packet[..expected])
}

pub fn ipv4_header_checksum_is_valid(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return false;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || header_len > packet.len() {
        return false;
    }
    let mut sum = 0_u32;
    for pair in packet[..header_len].chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum == 0xffff
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment(id: u32, offset: u16, end: bool, data: &[u8]) -> Fragment {
        Fragment {
            id,
            end_of_packet: end,
            offset,
            data: data.to_vec(),
        }
    }

    #[test]
    fn wire_round_trip() {
        let original = fragment(0x1020_3040, 7, true, b"payload");
        let encoded = original.encode().unwrap();
        assert_eq!(&encoded[..4], &[0x10, 0x20, 0x30, 0x40]);
        assert_eq!(Fragment::parse(&encoded).unwrap(), original);
    }

    #[test]
    fn out_of_order_reassembly() {
        let now = Instant::now();
        let mut queue = FragmentReassembler::default();
        assert!(
            queue
                .insert(fragment(1, 5, true, b" world"), now)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            queue
                .insert(fragment(1, 0, false, b"hello"), now)
                .unwrap()
                .unwrap(),
            b"hello world"
        );
    }

    #[test]
    fn rejects_data_after_eop() {
        let now = Instant::now();
        let mut queue = FragmentReassembler::default();
        assert!(
            queue
                .insert(fragment(1, 4, false, b"tail"), now)
                .unwrap()
                .is_none()
        );
        assert!(queue.insert(fragment(1, 0, true, b"head"), now).is_err());
        assert_eq!(queue.pending_groups(), 0);
    }

    #[test]
    fn rejects_reserved_wire_bits() {
        let mut encoded = fragment(1, 0, true, b"x").encode().unwrap();
        encoded[4] |= 0x02;
        assert!(Fragment::parse(&encoded).is_err());
    }

    #[test]
    fn overlap_drops_group() {
        let now = Instant::now();
        let mut queue = FragmentReassembler::default();
        queue.insert(fragment(1, 0, false, b"hello"), now).unwrap();
        assert!(matches!(
            queue.insert(fragment(1, 4, true, b"oops"), now),
            Err(Error::InvalidFragment(_))
        ));
        assert_eq!(queue.pending_groups(), 0);
    }
}
