//! Traditional and segment-routing iWAN fragment codecs.

use crate::{Error, Result};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const FRAGMENT_PREFIX_LEN: usize = 8;
pub const MAX_FRAGMENT_OFFSET: u16 = 0x1fff;
pub const MAX_FRAGMENT_LENGTH: u16 = 0x07ff;
pub const MAX_REASSEMBLED_PACKET: usize = 8192;

const TRADITIONAL_TIMEOUT: Duration = Duration::from_millis(100);
const TRADITIONAL_MAX_GROUPS: usize = 256;
const SR_TIMEOUT: Duration = Duration::from_secs(2);
const SR_MAX_GROUPS: usize = 16;
const SR_MAX_BUFFERED_BYTES: usize = 262_144;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    pub id: u32,
    pub end_of_packet: bool,
    pub from_in: bool,
    pub offset: u16,
    pub data: Vec<u8>,
}

impl Fragment {
    pub fn parse_traditional(input: &[u8]) -> Result<Self> {
        Self::parse(input, FragmentIdEndian::Big)
    }

    pub fn parse_sr(input: &[u8]) -> Result<Self> {
        Self::parse(input, FragmentIdEndian::Little)
    }

    fn parse(input: &[u8], id_endian: FragmentIdEndian) -> Result<Self> {
        if input.len() < FRAGMENT_PREFIX_LEN {
            return Err(Error::InvalidFragment("fewer than eight prefix bytes"));
        }
        let id_bytes = input[0..4].try_into().expect("length checked");
        let id = match id_endian {
            FragmentIdEndian::Big => u32::from_be_bytes(id_bytes),
            FragmentIdEndian::Little => u32::from_le_bytes(id_bytes),
        };
        let packed = u32::from_le_bytes(input[4..8].try_into().expect("length checked"));
        if packed & 0xfc00_0000 != 0 {
            return Err(Error::InvalidFragment("reserved bits are non-zero"));
        }
        let end_of_packet = packed & 1 != 0;
        let from_in = packed & 2 != 0;
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
        let fragment = Self {
            id,
            end_of_packet,
            from_in,
            offset,
            data: input[FRAGMENT_PREFIX_LEN..FRAGMENT_PREFIX_LEN + length].to_vec(),
        };
        if fragment.end_offset()? > MAX_REASSEMBLED_PACKET {
            return Err(Error::FragmentTooLarge);
        }
        Ok(fragment)
    }

    pub fn encode_traditional(&self) -> Result<Vec<u8>> {
        self.encode(FragmentIdEndian::Big)
    }

    pub fn encode_sr(&self) -> Result<Vec<u8>> {
        self.encode(FragmentIdEndian::Little)
    }

    fn encode(&self, id_endian: FragmentIdEndian) -> Result<Vec<u8>> {
        if self.offset > MAX_FRAGMENT_OFFSET {
            return Err(Error::InvalidFragment("offset exceeds 13-bit field"));
        }
        let length = u16::try_from(self.data.len())
            .map_err(|_| Error::InvalidFragment("payload exceeds 11-bit length field"))?;
        if length == 0 || length > MAX_FRAGMENT_LENGTH {
            return Err(Error::InvalidFragment("payload length is outside 1..=2047"));
        }
        if self.end_offset()? > MAX_REASSEMBLED_PACKET {
            return Err(Error::FragmentTooLarge);
        }
        let mut packed = u32::from(self.offset) << 2;
        packed |= u32::from(length) << 15;
        packed |= u32::from(self.end_of_packet);
        packed |= u32::from(self.from_in) << 1;

        let mut output = Vec::with_capacity(FRAGMENT_PREFIX_LEN + self.data.len());
        let id_bytes = match id_endian {
            FragmentIdEndian::Big => self.id.to_be_bytes(),
            FragmentIdEndian::Little => self.id.to_le_bytes(),
        };
        output.extend_from_slice(&id_bytes);
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

#[derive(Debug, Clone, Copy)]
enum FragmentIdEndian {
    Big,
    Little,
}

#[derive(Debug)]
struct TraditionalPending {
    created: Instant,
    fragment: Fragment,
}

/// Traditional two-fragment reassembly, ordered by EOP, with a 100 ms
/// matching window.
#[derive(Debug, Default)]
pub struct TraditionalFragmentReassembler {
    groups: HashMap<u32, TraditionalPending>,
}

impl TraditionalFragmentReassembler {
    pub fn clear(&mut self) {
        self.groups.clear();
    }

    pub fn pending_groups(&self) -> usize {
        self.groups.len()
    }

    pub fn purge_expired(&mut self, now: Instant) {
        self.groups.retain(|_, pending| {
            now.checked_duration_since(pending.created)
                .is_none_or(|age| age <= TRADITIONAL_TIMEOUT)
        });
    }

    pub fn insert(&mut self, fragment: Fragment, now: Instant) -> Result<Option<Vec<u8>>> {
        self.purge_expired(now);
        if fragment.data.len() > MAX_REASSEMBLED_PACKET {
            return Err(Error::FragmentTooLarge);
        }

        if let Some(first) = self.groups.remove(&fragment.id) {
            if first.fragment.end_of_packet == fragment.end_of_packet {
                self.groups.insert(
                    fragment.id,
                    TraditionalPending {
                        created: now,
                        fragment,
                    },
                );
                return Ok(None);
            }
            let (prefix, suffix) = if first.fragment.end_of_packet {
                (&fragment, &first.fragment)
            } else {
                (&first.fragment, &fragment)
            };
            let total = prefix
                .data
                .len()
                .checked_add(suffix.data.len())
                .ok_or(Error::FragmentTooLarge)?;
            if total > MAX_REASSEMBLED_PACKET {
                return Err(Error::FragmentTooLarge);
            }
            let mut packet = Vec::with_capacity(total);
            packet.extend_from_slice(&prefix.data);
            packet.extend_from_slice(&suffix.data);
            return Ok(Some(packet));
        }

        if self.groups.len() >= TRADITIONAL_MAX_GROUPS
            && let Some(oldest) = self
                .groups
                .iter()
                .min_by_key(|(_, pending)| pending.created)
                .map(|(id, _)| *id)
        {
            self.groups.remove(&oldest);
        }
        self.groups.insert(
            fragment.id,
            TraditionalPending {
                created: now,
                fragment,
            },
        );
        Ok(None)
    }
}

#[derive(Debug)]
struct SrFragmentGroup {
    created: Instant,
    parts: Vec<Fragment>,
    buffered_bytes: usize,
}

/// Offset-aware bounded SR fragment reassembler.
#[derive(Debug, Default)]
pub struct SrFragmentReassembler {
    groups: HashMap<u32, SrFragmentGroup>,
    buffered_bytes: usize,
}

impl SrFragmentReassembler {
    pub fn clear(&mut self) {
        self.groups.clear();
        self.buffered_bytes = 0;
    }

    pub fn pending_groups(&self) -> usize {
        self.groups.len()
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    pub fn purge_expired(&mut self, now: Instant) {
        let expired: Vec<u32> = self
            .groups
            .iter()
            .filter_map(|(id, group)| {
                now.checked_duration_since(group.created)
                    .is_some_and(|age| age > SR_TIMEOUT)
                    .then_some(*id)
            })
            .collect();
        for id in expired {
            self.remove_group(id);
        }
    }

    pub fn insert(&mut self, fragment: Fragment, now: Instant) -> Result<Option<Vec<u8>>> {
        self.purge_expired(now);
        if fragment.end_offset()? > MAX_REASSEMBLED_PACKET {
            return Err(Error::FragmentTooLarge);
        }
        if let Some(group) = self.groups.get(&fragment.id)
            && group
                .parts
                .iter()
                .any(|part| part.offset == fragment.offset)
        {
            return Ok(None);
        }

        if !self.groups.contains_key(&fragment.id) && self.groups.len() >= SR_MAX_GROUPS {
            return Err(Error::FragmentTooLarge);
        }
        if self.buffered_bytes + fragment.data.len() > SR_MAX_BUFFERED_BYTES {
            return Err(Error::FragmentTooLarge);
        }

        let id = fragment.id;
        let new_start = usize::from(fragment.offset);
        let new_end = fragment.end_offset()?;
        let group = self.groups.entry(id).or_insert_with(|| SrFragmentGroup {
            created: now,
            parts: Vec::new(),
            buffered_bytes: 0,
        });
        if group.parts.iter().any(|part| {
            let start = usize::from(part.offset);
            let end = start + part.data.len();
            new_start < end && start < new_end
        }) {
            self.remove_group(id);
            return Err(Error::InvalidFragment("overlapping fragment offsets"));
        }

        self.buffered_bytes += fragment.data.len();
        group.buffered_bytes += fragment.data.len();
        group.parts.push(fragment);
        group.parts.sort_unstable_by_key(|part| part.offset);

        let mut expected_offset = 0_usize;
        let mut total_length = None;
        for part in &group.parts {
            if usize::from(part.offset) != expected_offset {
                return Ok(None);
            }
            expected_offset = part.end_offset()?;
            if part.end_of_packet {
                total_length = Some(expected_offset);
                break;
            }
        }
        let Some(total_length) = total_length else {
            return Ok(None);
        };
        if group
            .parts
            .iter()
            .any(|part| usize::from(part.offset) >= total_length)
        {
            self.remove_group(id);
            return Err(Error::InvalidFragment("data follows the EOP fragment"));
        }

        let group = self.groups.remove(&id).expect("group exists");
        self.buffered_bytes -= group.buffered_bytes;
        let mut packet = Vec::with_capacity(total_length);
        for part in group.parts {
            if packet.len() == total_length {
                break;
            }
            packet.extend_from_slice(&part.data);
        }
        if packet.len() != total_length {
            return Err(Error::InvalidFragment("fragment coverage changed"));
        }
        Ok(Some(packet))
    }

    fn remove_group(&mut self, id: u32) {
        if let Some(group) = self.groups.remove(&id) {
            self.buffered_bytes -= group.buffered_bytes;
        }
    }
}

/// Split an SR payload into the protocol-defined pair of fragments.
pub fn fragment_sr_packet(packet: &[u8], payload_mtu: usize, id: u32) -> Result<[Fragment; 2]> {
    if payload_mtu == 0
        || payload_mtu > usize::from(MAX_FRAGMENT_LENGTH)
        || packet.len() <= payload_mtu
        || packet.len() > payload_mtu.saturating_mul(2)
        || packet.len() > MAX_REASSEMBLED_PACKET
    {
        return Err(Error::FragmentTooLarge);
    }
    let second_offset = u16::try_from(payload_mtu).map_err(|_| Error::FragmentTooLarge)?;
    Ok([
        Fragment {
            id,
            end_of_packet: false,
            from_in: false,
            offset: 0,
            data: packet[..payload_mtu].to_vec(),
        },
        Fragment {
            id,
            end_of_packet: true,
            from_in: false,
            offset: second_offset,
            data: packet[payload_mtu..].to_vec(),
        },
    ])
}

/// Remove AES zero padding by trusting the inner IP length field.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment(id: u32, offset: u16, end: bool, data: &[u8]) -> Fragment {
        Fragment {
            id,
            end_of_packet: end,
            from_in: false,
            offset,
            data: data.to_vec(),
        }
    }

    #[test]
    fn fragment_words_match_specification_vectors() {
        let first = fragment(1, 0, false, &vec![0_u8; 1400]);
        assert_eq!(&first.encode_sr().unwrap()[4..8], &[0x00, 0x00, 0xbc, 0x02]);
        let second = fragment(1, 1400, true, &vec![0_u8; 600]);
        assert_eq!(
            &second.encode_sr().unwrap()[4..8],
            &[0xe1, 0x15, 0x2c, 0x01]
        );
    }

    #[test]
    fn traditional_and_sr_fragment_ids_have_different_endianness() {
        let value = fragment(0x0102_0304, 0, true, b"x");
        assert_eq!(&value.encode_traditional().unwrap()[..4], &[1, 2, 3, 4]);
        assert_eq!(&value.encode_sr().unwrap()[..4], &[4, 3, 2, 1]);
    }

    #[test]
    fn from_in_is_parsed_not_rejected() {
        let mut encoded = fragment(1, 0, true, b"x").encode_traditional().unwrap();
        encoded[4] |= 2;
        assert!(Fragment::parse_traditional(&encoded).unwrap().from_in);
    }

    #[test]
    fn traditional_reassembly_ignores_offsets_and_uses_eop_order() {
        let now = Instant::now();
        let mut queue = TraditionalFragmentReassembler::default();
        assert!(
            queue
                .insert(fragment(1, 999, true, b"tail"), now)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            queue
                .insert(fragment(1, 444, false, b"head"), now)
                .unwrap()
                .unwrap(),
            b"headtail"
        );
    }

    #[test]
    fn sr_reassembly_is_offset_aware_and_out_of_order() {
        let now = Instant::now();
        let mut queue = SrFragmentReassembler::default();
        queue.insert(fragment(1, 5, true, b" world"), now).unwrap();
        assert_eq!(
            queue
                .insert(fragment(1, 0, false, b"hello"), now)
                .unwrap()
                .unwrap(),
            b"hello world"
        );
        assert_eq!(queue.buffered_bytes(), 0);
    }

    #[test]
    fn sr_fragmenter_emits_exactly_two_parts() {
        let packet = vec![7_u8; 2000];
        let fragments = fragment_sr_packet(&packet, 1400, 9).unwrap();
        assert_eq!(fragments[0].data.len(), 1400);
        assert_eq!(fragments[1].offset, 1400);
        assert_eq!(fragments[1].data.len(), 600);
        assert!(fragments[1].end_of_packet);
    }
}
