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
    AuthenticationRejected { code: u8, message: String },

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

    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),

    #[error("TUN operation failed: {0}")]
    Tun(String),

    #[error("external command failed: {program}: {message}")]
    CommandFailed { program: String, message: String },

    #[error("managed-provider error: {0}")]
    ManagedProvider(String),

    #[error("HTTP operation failed: {0}")]
    Http(String),

    #[error("OIDC authentication failed: {0}")]
    Oidc(String),

    #[error("controller operation failed: {0}")]
    Controller(String),
}

pub type Result<T> = std::result::Result<T, Error>;
