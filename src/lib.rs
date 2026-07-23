//! `openiwan` is an independent implementation of the client-side iWAN wire
//! protocol used by Panabit iWAN 2.3.0.
//!
//! The crate separates the byte-level protocol from system tunnel management.
//! Applications that already own a TUN device can use [`Client`] and
//! [`PacketDevice`] without invoking any platform commands.

pub mod client;
pub mod config;
pub mod crypto;
pub mod error;
pub mod fragment;
pub mod protocol;
pub mod tun;

pub use client::{Client, ConnectedSession, PacketDevice, SessionEnd, SessionInfo};
pub use config::{ClientConfig, ReconnectPolicy};
pub use error::{Error, Result};
pub use protocol::{EncryptionMethod, PacketHeader, PacketType, Tlv, TlvType};
