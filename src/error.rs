use std::net::SocketAddr;

/// Errors returned by the protocol library and the command-line client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("packet is too short: expected at least {minimum} bytes, got {actual}")]
    PacketTooShort { minimum: usize, actual: usize },

    #[error("unsupported packet type 0x{0:02x}")]
    UnknownPacketType(u8),

    #[error("unsupported encryption method 0x{0:02x}")]
    UnknownEncryptionMethod(u8),

    #[error("invalid control-packet signature")]
    InvalidSignature,

    #[error("invalid TLV at offset {offset}: {reason}")]
    InvalidTlv { offset: usize, reason: String },

    #[error("TLV value for {kind} is too large ({length} bytes)")]
    TlvTooLarge { kind: &'static str, length: usize },

    #[error("required TLV {0} is missing")]
    MissingTlv(&'static str),

    #[error("invalid value in TLV {0}")]
    InvalidTlvValue(&'static str),

    #[error("cryptographic operation failed: {0}")]
    Crypto(&'static str),

    #[error("authentication was rejected (code {code}): {message}")]
    AuthenticationRejected { code: u16, message: String },

    #[error("authentication verification nonce mismatch")]
    AuthenticationVerifyMismatch,

    #[error("operation timed out: {0}")]
    Timeout(&'static str),

    #[error("endpoint returned a malformed stateless ping response")]
    InvalidPingResponse,

    #[error("session validation failed for packet from {peer}")]
    SessionMismatch { peer: SocketAddr },

    #[error("server closed the session")]
    SessionClosed,

    #[error("fragment is malformed: {0}")]
    InvalidFragment(&'static str),

    #[error("fragment group exceeded the configured maximum size")]
    FragmentTooLarge,

    #[error("segment-routing packet is malformed: {0}")]
    InvalidSegmentRouting(&'static str),

    #[error("segment-routing path is unavailable")]
    SegmentRoutingPeerDown,

    #[error("fragmentation with encryption is unsupported by iWAN 2.3.0")]
    FragmentEncryptionUnsupported,

    #[error("TUN operation failed: {0}")]
    Tun(String),

    #[error("external command failed: {program}: {message}")]
    CommandFailed { program: String, message: String },

    #[error("managed client flow failed: {0}")]
    ManagedFlow(String),

    #[error("privacy/network consent is required before domain lookup")]
    ConsentRequired,

    #[error("HTTP operation failed: {0}")]
    Http(String),

    #[error("OIDC authentication failed: {0}")]
    Oidc(String),

    #[error("controller operation failed: {0}")]
    Controller(String),

    #[error("controller rejected the request as unauthorized")]
    ControllerUnauthorized,

    #[error("controller rejected the request (HTTP {status}, code {code}): {message}")]
    ControllerRejected {
        status: u16,
        code: String,
        message: String,
    },

    #[error("posture configuration version does not match the controller")]
    PostureVersionMismatch,

    #[error("posture configuration is not loaded by the backend")]
    PostureConfigUnavailable,

    #[error("device posture gate denied network access")]
    PostureDenied,

    #[error("device binding gate blocked network access ({status}, code {code})")]
    DeviceBindingBlocked { code: i32, status: &'static str },
}

pub type Result<T> = std::result::Result<T, Error>;
