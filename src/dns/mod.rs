//! DNS policy, packet enforcement, physical relay, platform configuration,
//! and userspace name resolution.
//!
//! The module intentionally keeps controller wire formats out of the runtime.
//! Callers resolve [`DnsDefaults`] and layered [`DnsOverrides`] into one
//! immutable [`EffectiveDnsPolicy`] before starting a tunnel.

mod packet;
mod platform;
mod policy;
mod relay;
mod resolver;
mod runtime;

pub use packet::{DnsPacketAction, DnsPacketEngine, DnsRelayRequest};
pub use platform::{
    DnsPlatformTarget, PhysicalResolver, PlatformDnsLease, discover_physical_resolvers,
};
pub use policy::{
    DnsDefaults, DnsOverrides, DnsPolicyResolver, DnsServerMode, DomainRule, DomainRuleKind,
    EffectiveDnsPolicy, EncryptedDnsMode, ServerListDnsMode, SplitDnsMode,
};
pub use relay::{DnsRelay, RelayConfig};
pub use resolver::{ResolveVia, ResolverConfig};
#[cfg(feature = "forward")]
#[path = "transport.rs"]
mod transport_resolver;
pub use runtime::{DnsPacketDevice, DnsRuntime};
#[cfg(feature = "forward")]
pub use transport_resolver::{
    DnsLookup, default_port as default_dns_port, lookup as lookup_with_net,
};
