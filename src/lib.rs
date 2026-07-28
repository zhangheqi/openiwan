//! Client and protocol support for iWAN-compatible networks.
//!
//! The crate separates the byte-level protocol from system tunnel management.
//! Applications that already own a TUN device can use [`Client`] and
//! [`PacketDevice`] without invoking any platform commands.
//!
//! # Main APIs
//!
//! - [`Client`] authenticates direct connections and creates a
//!   [`ConnectedSession`].
//! - [`PacketDevice`] exchanges IP packets without configuring a system TUN
//!   interface.
//! - [`ClientConfig`] configures transport, encryption, reconnection, and
//!   Segment Routing.
//! - [`protocol`] contains wire-level packet and TLV types.
//! - `managed` contains controller authentication and connection discovery
//!   when the `managed` feature is enabled.
//!
//! # Example
//!
//! ```no_run
//! use openiwan::{Client, ClientConfig, EncryptionMethod, Result};
//!
//! fn connect(password: String) -> Result<()> {
//!     let mut config = ClientConfig::new("vpn.example.com:443");
//!     config.encryption = EncryptionMethod::Aes;
//!
//!     let client = Client::new(config, "alice", password)?;
//!     let session = client.authenticate()?;
//!     session.close()
//! }
//! ```
//!
//! # Cargo features
//!
//! - `managed` enables controller-managed authentication, profiles, and saved
//!   credentials.
//! - `forward` enables TCP, HTTP, and HTTPS forwarding.
//!
//! Both features are enabled by default. Disable default features for a
//! protocol-only integration.

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
