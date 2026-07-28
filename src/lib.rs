//! `openiwan` is a client and protocol library for iWAN-compatible networks.
//!
//! The crate separates the byte-level protocol from system tunnel management.
//! Applications that already own a TUN device can use [`Client`] and
//! [`PacketDevice`] without invoking any platform commands.

pub mod client;
pub mod config;
pub mod crypto;
pub mod dns;
pub mod error;
pub mod fragment;
#[cfg(feature = "managed")]
pub mod managed;
pub mod protocol;
pub mod sr;
pub mod tun;

pub use client::{Client, ConnectedSession, PacketDevice, SessionEnd, SessionInfo};
pub use config::{ClientConfig, ReconnectPolicy, SegmentRoutingConfig};
pub use error::{Error, Result};
pub use protocol::{EncryptionMethod, PacketHeader, PacketType, Tlv, TlvType};
pub use sr::SrEncryptionAlgorithm;
