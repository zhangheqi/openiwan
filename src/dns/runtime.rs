use super::{
    DnsDefaults, DnsOverrides, DnsPacketAction, DnsPacketEngine, DnsPlatformTarget,
    DnsPolicyResolver, DnsRelay, DnsRelayRequest, EffectiveDnsPolicy, PhysicalResolver,
    PlatformDnsLease, RelayConfig, discover_physical_resolvers,
};
use crate::Result;
use crate::client::{PacketDevice, SessionInfo};
use std::io::{self, ErrorKind};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use tracing::{debug, warn};

#[derive(Debug)]
struct PolicyInputs {
    defaults: DnsDefaults,
    overrides: DnsOverrides,
}

#[derive(Debug)]
pub struct DnsRuntime {
    target: DnsPlatformTarget,
    inputs: RwLock<PolicyInputs>,
    policy: RwLock<Arc<EffectiveDnsPolicy>>,
    physical: RwLock<Arc<[PhysicalResolver]>>,
    relay: Arc<DnsRelay>,
    lease: Mutex<Option<PlatformDnsLease>>,
    active: AtomicBool,
    workers: Mutex<Vec<JoinHandle<()>>>,
    worker_count: Arc<AtomicUsize>,
    max_workers: usize,
}

impl DnsRuntime {
    pub fn new(
        target: DnsPlatformTarget,
        defaults: DnsDefaults,
        overrides: DnsOverrides,
        physical: Vec<PhysicalResolver>,
        relay_config: RelayConfig,
    ) -> Result<Self> {
        target.validate()?;
        overrides.validate()?;
        let policy = DnsPolicyResolver::resolve(&defaults, &overrides, &[])?;
        Ok(Self {
            target,
            inputs: RwLock::new(PolicyInputs {
                defaults,
                overrides,
            }),
            policy: RwLock::new(Arc::new(policy)),
            physical: RwLock::new(physical.clone().into()),
            relay: Arc::new(DnsRelay::new(relay_config, physical)),
            lease: Mutex::new(None),
            active: AtomicBool::new(false),
            workers: Mutex::new(Vec::new()),
            worker_count: Arc::new(AtomicUsize::new(0)),
            max_workers: relay_config.max_concurrent,
        })
    }

    pub fn policy(&self) -> Arc<EffectiveDnsPolicy> {
        Arc::clone(
            &self
                .policy
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    pub fn update_inputs(&self, defaults: DnsDefaults, overrides: DnsOverrides) -> Result<()> {
        overrides.validate()?;
        *self
            .inputs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = PolicyInputs {
            defaults,
            overrides,
        };
        Ok(())
    }

    pub fn update_policy(
        &self,
        defaults: DnsDefaults,
        overrides: DnsOverrides,
        session_dns: &[IpAddr],
    ) -> Result<()> {
        overrides.validate()?;
        let policy = DnsPolicyResolver::resolve(&defaults, &overrides, session_dns)?;
        self.activate_policy(policy)?;
        *self
            .inputs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = PolicyInputs {
            defaults,
            overrides,
        };
        Ok(())
    }

    pub fn activate(&self, session: &SessionInfo) -> Result<()> {
        match discover_physical_resolvers() {
            Ok(discovered) => {
                *self
                    .physical
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = discovered.into();
            }
            Err(error) => {
                warn!(%error, "could not refresh physical DNS resolvers; using prior snapshot");
            }
        }
        let policy = {
            let inputs = self
                .inputs
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            DnsPolicyResolver::resolve(&inputs.defaults, &inputs.overrides, &session.dns_servers)?
        };
        self.activate_policy(policy)
    }

    pub fn activate_policy(&self, policy: EffectiveDnsPolicy) -> Result<()> {
        let tunnel_servers = policy
            .servers
            .iter()
            .copied()
            .map(IpAddr::V4)
            .collect::<Vec<_>>();
        let physical_snapshot = Arc::clone(
            &self
                .physical
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let physical = physical_snapshot
            .iter()
            .filter(|resolver| !tunnel_servers.contains(&resolver.address.ip()))
            .cloned()
            .collect::<Vec<_>>();

        let mut lease = self
            .lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous_policy = self.policy();
        let previous_lease = lease.take();
        drop(previous_lease);
        let new_lease = match PlatformDnsLease::apply(&self.target, &policy.servers) {
            Ok(lease) => lease,
            Err(error) => {
                if let Ok(restored) =
                    PlatformDnsLease::apply(&self.target, &previous_policy.servers)
                {
                    *lease = Some(restored);
                }
                return Err(error);
            }
        };
        *self
            .policy
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(policy);
        self.relay.update_resolvers(physical);
        *lease = Some(new_lease);
        self.active.store(true, Ordering::Release);
        Ok(())
    }

    pub fn deactivate(&self) -> Result<()> {
        self.active.store(false, Ordering::Release);
        self.relay.reset_generation();
        let workers = std::mem::take(
            &mut *self
                .workers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for worker in workers {
            let _ = worker.join();
        }
        self.lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        Ok(())
    }

    fn process(&self, packet: &[u8]) -> DnsPacketAction {
        if !self.active.load(Ordering::Acquire) {
            return DnsPacketAction::Pass;
        }
        DnsPacketEngine::from_shared(self.policy()).process(packet)
    }

    fn spawn_relay<D>(&self, device: Arc<D>, request: DnsRelayRequest)
    where
        D: PacketDevice + ?Sized,
    {
        self.reap_workers();
        if !self.try_acquire_worker() {
            if let Some(response) = request.servfail_packet() {
                let _ = device.write_packet(&response);
            }
            return;
        }
        if !self.relay.has_resolvers() {
            self.worker_count.fetch_sub(1, Ordering::AcqRel);
            return;
        }
        let relay = Arc::clone(&self.relay);
        let generation = relay.generation();
        let worker_count = Arc::clone(&self.worker_count);
        let worker_request = request.clone();
        let worker_device = Arc::clone(&device);
        let worker = thread::Builder::new()
            .name("openiwan-dns-relay".into())
            .spawn(move || {
                let _counter = WorkerCounter(worker_count);
                match relay.relay(worker_request.dns_request(), generation) {
                    Ok(response) => {
                        if let Some(packet) = worker_request.response_packet(&response)
                            && let Err(error) = worker_device.write_packet(&packet)
                        {
                            warn!(%error, "failed to inject relayed DNS response");
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::Interrupted => {
                        debug!("discarding DNS reply from an obsolete generation");
                    }
                    Err(error) => {
                        warn!(%error, "physical DNS relay failed");
                        if let Some(packet) = worker_request.servfail_packet() {
                            let _ = worker_device.write_packet(&packet);
                        }
                    }
                }
            });
        match worker {
            Ok(worker) => self
                .workers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(worker),
            Err(error) => {
                self.worker_count.fetch_sub(1, Ordering::AcqRel);
                warn!(%error, "failed to spawn DNS relay worker");
                if let Some(response) = request.servfail_packet() {
                    let _ = device.write_packet(&response);
                }
            }
        }
    }

    fn try_acquire_worker(&self) -> bool {
        let mut current = self.worker_count.load(Ordering::Acquire);
        loop {
            if current >= self.max_workers {
                return false;
            }
            match self.worker_count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    fn reap_workers(&self) {
        let mut workers = self
            .workers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut index = 0;
        while index < workers.len() {
            if workers[index].is_finished() {
                let worker = workers.swap_remove(index);
                let _ = worker.join();
            } else {
                index += 1;
            }
        }
    }
}

impl Drop for DnsRuntime {
    fn drop(&mut self) {
        let _ = self.deactivate();
    }
}

struct WorkerCounter(Arc<AtomicUsize>);

impl Drop for WorkerCounter {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub struct DnsPacketDevice<D: PacketDevice + ?Sized> {
    inner: Arc<D>,
    runtime: Arc<DnsRuntime>,
}

impl<D: PacketDevice + ?Sized> std::fmt::Debug for DnsPacketDevice<D> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DnsPacketDevice")
            .field("name", &self.inner.name())
            .field("runtime", &self.runtime)
            .finish_non_exhaustive()
    }
}

impl<D: PacketDevice + ?Sized> DnsPacketDevice<D> {
    pub fn new(inner: Arc<D>, runtime: Arc<DnsRuntime>) -> Self {
        Self { inner, runtime }
    }

    pub fn runtime(&self) -> &Arc<DnsRuntime> {
        &self.runtime
    }

    pub fn inner(&self) -> &Arc<D> {
        &self.inner
    }
}

impl<D: PacketDevice + ?Sized> PacketDevice for DnsPacketDevice<D> {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn activate_session(&self, session: &SessionInfo) -> Result<()> {
        self.inner.activate_session(session)?;
        if let Err(error) = self.runtime.activate(session) {
            let _ = self.inner.deactivate_session();
            return Err(error);
        }
        Ok(())
    }

    fn deactivate_session(&self) -> Result<()> {
        let runtime = self.runtime.deactivate();
        let inner = self.inner.deactivate_session();
        runtime.and(inner)
    }

    fn read_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let length = self.inner.read_packet(buffer)?;
            match self.runtime.process(&buffer[..length]) {
                DnsPacketAction::Pass => return Ok(length),
                DnsPacketAction::Drop => {}
                DnsPacketAction::Inject(response) => {
                    write_complete(self.inner.as_ref(), &response)?;
                }
                DnsPacketAction::Relay(request) => {
                    if self.runtime.relay.has_resolvers() {
                        self.runtime.spawn_relay(Arc::clone(&self.inner), request);
                    } else {
                        // App-compatible fail-open behavior when the host has no
                        // usable physical resolver: send the original query
                        // through the tunnel.
                        return Ok(length);
                    }
                }
            }
        }
    }

    fn write_packet(&self, packet: &[u8]) -> io::Result<usize> {
        self.inner.write_packet(packet)
    }
}

fn write_complete<D: PacketDevice + ?Sized>(device: &D, packet: &[u8]) -> io::Result<()> {
    let written = device.write_packet(packet)?;
    if written == packet.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            ErrorKind::WriteZero,
            format!(
                "packet device accepted {written} of {} DNS response bytes",
                packet.len()
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{DnsServerMode, SplitDnsMode};
    use crate::protocol::EncryptionMethod;
    use std::net::{Ipv4Addr, SocketAddr};

    struct NullDevice;

    impl PacketDevice for NullDevice {
        fn name(&self) -> &'static str {
            "null0"
        }

        fn read_packet(&self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(ErrorKind::WouldBlock, "empty"))
        }

        fn write_packet(&self, packet: &[u8]) -> io::Result<usize> {
            Ok(packet.len())
        }
    }

    fn session(dns: Ipv4Addr) -> SessionInfo {
        SessionInfo {
            peer: SocketAddr::from(([192, 0, 2, 1], 6001)),
            session_id: 1,
            token: 2,
            encryption: EncryptionMethod::Xor,
            mtu: 1400,
            address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            gateway: None,
            dns_servers: vec![IpAddr::V4(dns)],
            segment_routing: false,
        }
    }

    #[test]
    fn session_activation_recomputes_openack_dns() {
        let runtime = DnsRuntime::new(
            DnsPlatformTarget::new("test0"),
            DnsDefaults::default(),
            DnsOverrides::default(),
            Vec::new(),
            RelayConfig::default(),
        )
        .unwrap();
        // Avoid invoking a real platform DNS backend in this unit test by
        // resolving a disabled policy, then inspect policy replacement.
        runtime
            .update_inputs(
                DnsDefaults::default(),
                DnsOverrides {
                    server_mode: Some(DnsServerMode::Disabled),
                    split_mode: Some(SplitDnsMode::Off),
                    ..DnsOverrides::default()
                },
            )
            .unwrap();
        runtime
            .activate(&session(Ipv4Addr::new(192, 0, 2, 53)))
            .unwrap();
        assert_eq!(runtime.policy().server_mode, DnsServerMode::Disabled);
        runtime.deactivate().unwrap();
    }

    #[test]
    fn wrapper_delegates_identity_and_writes() {
        let runtime = Arc::new(
            DnsRuntime::new(
                DnsPlatformTarget::new("test0"),
                DnsDefaults::default(),
                DnsOverrides::default(),
                Vec::new(),
                RelayConfig::default(),
            )
            .unwrap(),
        );
        let device = DnsPacketDevice::new(Arc::new(NullDevice), runtime);
        assert_eq!(device.name(), "null0");
        assert_eq!(device.write_packet(&[1, 2, 3]).unwrap(), 3);
    }
}
