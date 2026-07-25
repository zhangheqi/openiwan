use crate::client::{PacketDevice, SessionInfo};
use crate::{Error, Result};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::{Command, Output};
#[cfg(windows)]
use std::time::Duration;
use tun::AbstractDevice as _;

#[cfg(windows)]
mod wintun;

#[cfg(not(target_os = "macos"))]
const DEFAULT_TUN_NAME: &str = "openiwan0";
#[cfg(windows)]
const WINDOWS_READ_TIMEOUT: Duration = Duration::from_millis(100);

/// A native layer-three TUN device backed by the cross-platform `tun` crate.
pub struct TunDevice {
    name: String,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    device: tun::Device,
    #[cfg(windows)]
    reader: std::sync::Mutex<tun::DeviceReader>,
    #[cfg(windows)]
    writer: std::sync::Mutex<tun::DeviceWriter>,
    #[cfg(windows)]
    luid: u64,
    #[cfg(windows)]
    runtime: tokio::runtime::Runtime,
}

impl fmt::Debug for TunDevice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("TunDevice");
        debug.field("name", &self.name);
        #[cfg(windows)]
        debug.field("luid", &self.luid);
        debug.finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InterfaceSettings {
    name: Option<String>,
    address: IpAddr,
    netmask: IpAddr,
    mtu: u16,
}

impl TunDevice {
    /// Create and configure a native TUN interface for an authenticated session.
    ///
    /// When `requested_name` is `None`, Linux and Windows use `openiwan0`,
    /// while macOS asks the kernel to allocate the next available `utunN`.
    pub fn open(requested_name: Option<&str>, session: &SessionInfo) -> Result<Self> {
        let settings = interface_settings(requested_name, session)?;
        open_device(&settings)
    }

    #[cfg(windows)]
    const fn luid(&self) -> u64 {
        self.luid
    }
}

fn interface_settings(
    requested_name: Option<&str>,
    session: &SessionInfo,
) -> Result<InterfaceSettings> {
    let address = session.address.ok_or(Error::MissingTlv("IP/IP6"))?;
    let name = platform_tun_name(requested_name)?;
    let netmask = match address {
        IpAddr::V4(_) => {
            let mask = session.netmask.unwrap_or(Ipv4Addr::BROADCAST);
            netmask_prefix(mask)?;
            IpAddr::V4(mask)
        }
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(u128::MAX)),
    };
    Ok(InterfaceSettings {
        name,
        address,
        netmask,
        mtu: session.mtu,
    })
}

fn platform_tun_name(requested_name: Option<&str>) -> Result<Option<String>> {
    if requested_name.is_some_and(str::is_empty) {
        return Err(Error::InvalidConfig(
            "TUN interface name must not be empty".into(),
        ));
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(name) = requested_name {
            let suffix = name.strip_prefix("utun").ok_or_else(|| {
                Error::InvalidConfig("macOS TUN names must use the form utunN".into())
            })?;
            if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(Error::InvalidConfig(
                    "macOS TUN names must use the form utunN".into(),
                ));
            }
            return Ok(Some(name.to_owned()));
        }
        Ok(None)
    }

    #[cfg(not(target_os = "macos"))]
    {
        Ok(Some(requested_name.unwrap_or(DEFAULT_TUN_NAME).to_owned()))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_device(settings: &InterfaceSettings) -> Result<TunDevice> {
    let mut configuration = tun::Configuration::default();
    if let Some(name) = &settings.name {
        configuration.tun_name(name);
    }
    configuration.mtu(settings.mtu).layer(tun::Layer::L3);

    #[cfg(target_os = "linux")]
    {
        match settings.address {
            IpAddr::V4(_) => {
                configuration
                    .address(settings.address)
                    .netmask(settings.netmask)
                    .up();
            }
            // Preserve the known-good iproute2 path for IPv6 assignment.
            // Linux's legacy SIOCSIFADDR/SIOCSIFNETMASK ioctl layout is
            // IPv4-specific even though rust-tun accepts IpAddr here.
            IpAddr::V6(_) => {
                configuration.up();
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        configuration.platform_config(|platform| {
            platform.enable_routing(false);
        });
        match settings.address {
            IpAddr::V4(_) => {
                configuration
                    .address(settings.address)
                    .destination(settings.address)
                    .netmask(settings.netmask)
                    .up();
            }
            // rust-tun currently configures macOS IPv6 addresses through an
            // IPv4-only ioctl. Create the utun through rust-tun, then apply
            // the IPv6 address below with ifconfig to avoid that upstream
            // limitation.
            IpAddr::V6(_) => {
                configuration.up();
            }
        }
    }

    let device = tun::create(&configuration).map_err(tun_error)?;
    device.set_nonblock().map_err(Error::Io)?;
    let name = device.tun_name().map_err(tun_error)?;

    #[cfg(target_os = "linux")]
    if settings.address.is_ipv6() {
        run_command(
            "ip",
            &[
                "-6",
                "addr",
                "replace",
                &format!("{}/128", settings.address),
                "dev",
                &name,
            ],
        )?;
    }

    #[cfg(target_os = "macos")]
    if settings.address.is_ipv6() {
        run_command(
            "ifconfig",
            &[
                &name,
                "inet6",
                &format!("{}/128", settings.address),
                "mtu",
                &settings.mtu.to_string(),
                "up",
            ],
        )?;
    }

    Ok(TunDevice { name, device })
}

#[cfg(windows)]
fn open_device(settings: &InterfaceSettings) -> Result<TunDevice> {
    use tun::AbstractDeviceExt as _;

    let wintun_path = wintun::ensure_wintun()?;
    let mut configuration = tun::Configuration::default();
    if let Some(name) = &settings.name {
        configuration.tun_name(name);
    }
    configuration
        .address(settings.address)
        .netmask(settings.netmask)
        .mtu(settings.mtu)
        .layer(tun::Layer::L3)
        .up();
    configuration.platform_config(|platform| {
        platform.wintun_file(wintun_path.as_os_str());
        platform.wait_for_interfaces(
            settings.address.is_ipv4(),
            settings.address.is_ipv6(),
            Duration::from_secs(10),
        );
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .thread_name("openiwan-wintun")
        .build()
        .map_err(Error::Io)?;
    let device = {
        let _entered = runtime.enter();
        tun::create_as_async(&configuration).map_err(tun_error)?
    };
    let name = device.tun_name().map_err(tun_error)?;
    let luid = device.tun_luid();
    let (writer, reader) = device
        .split()
        .map_err(|error| Error::Tun(format!("split Wintun device: {error}")))?;

    Ok(TunDevice {
        name,
        reader: std::sync::Mutex::new(reader),
        writer: std::sync::Mutex::new(writer),
        luid,
        runtime,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn open_device(_settings: &InterfaceSettings) -> Result<TunDevice> {
    Err(Error::Unsupported(
        "native TUN creation is supported on Linux, macOS, and Windows",
    ))
}

fn tun_error(error: tun::Error) -> Error {
    Error::Tun(error.to_string())
}

impl PacketDevice for TunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn read_packet(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.device.recv(buffer)
    }

    #[cfg(windows)]
    fn read_packet(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        use std::io::Error as IoError;
        use tokio::io::AsyncReadExt as _;

        let mut reader = self
            .reader
            .lock()
            .map_err(|_| IoError::other("Wintun reader lock is poisoned"))?;
        map_windows_read_timeout(self.runtime.block_on(tokio::time::timeout(
            WINDOWS_READ_TIMEOUT,
            reader.read(buffer),
        )))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    fn read_packet(&self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "unsupported operating system",
        ))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn write_packet(&self, packet: &[u8]) -> std::io::Result<usize> {
        self.device.send(packet)
    }

    #[cfg(windows)]
    fn write_packet(&self, packet: &[u8]) -> std::io::Result<usize> {
        use std::io::Error as IoError;
        use tokio::io::AsyncWriteExt as _;

        let mut writer = self
            .writer
            .lock()
            .map_err(|_| IoError::other("Wintun writer lock is poisoned"))?;
        self.runtime.block_on(writer.write_all(packet))?;
        Ok(packet.len())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    fn write_packet(&self, _packet: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "unsupported operating system",
        ))
    }
}

#[cfg(windows)]
fn map_windows_read_timeout(
    result: std::result::Result<std::io::Result<usize>, tokio::time::error::Elapsed>,
) -> std::io::Result<usize> {
    result.unwrap_or_else(|_| {
        Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "Wintun receive poll timed out",
        ))
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Route {
    network: IpAddr,
    prefix: u8,
}

impl Route {
    fn parse(value: &str) -> Result<Self> {
        let (address, prefix) = value.split_once('/').ok_or_else(|| {
            Error::InvalidConfig(format!("route {value:?} must use CIDR notation"))
        })?;
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| Error::InvalidConfig(format!("invalid route address {address:?}")))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| Error::InvalidConfig(format!("invalid route prefix {prefix:?}")))?;
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        if prefix > maximum {
            return Err(Error::InvalidConfig(format!(
                "route prefix {prefix} exceeds {maximum}"
            )));
        }
        if prefix == 0 {
            return Err(Error::InvalidConfig(
                "default routes are not supported because the iWAN control endpoint \
                 must remain reachable outside the tunnel"
                    .into(),
            ));
        }
        Ok(Self {
            network: network_address(address, prefix),
            prefix,
        })
    }

    fn contains(&self, candidate: IpAddr) -> bool {
        match (self.network, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                network_address(IpAddr::V4(candidate), self.prefix) == IpAddr::V4(network)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                network_address(IpAddr::V6(candidate), self.prefix) == IpAddr::V6(network)
            }
            _ => false,
        }
    }
}

impl fmt::Display for Route {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix)
    }
}

fn network_address(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
        }
        IpAddr::V6(address) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
        }
    }
}

/// Removes routes installed for a TUN interface when dropped.
pub struct RouteGuard {
    device: String,
    routes: Vec<Route>,
    platform: PlatformRoutes,
}

impl fmt::Debug for RouteGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteGuard")
            .field("device", &self.device)
            .field("routes", &self.routes)
            .finish_non_exhaustive()
    }
}

impl RouteGuard {
    /// Install validated routes on `device`, rolling back partial failure.
    pub fn configure(device: &TunDevice, routes: &[String]) -> Result<Self> {
        let routes = routes
            .iter()
            .map(|route| Route::parse(route))
            .collect::<Result<Vec<_>>>()?;
        #[cfg(windows)]
        {
            let platform = configure_routes(device, &routes)?;
            Ok(Self {
                device: device.name.clone(),
                routes,
                platform,
            })
        }
        #[cfg(not(windows))]
        {
            configure_routes(device, &routes)?;
            Ok(Self {
                device: device.name.clone(),
                routes,
                platform: (),
            })
        }
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        cleanup_routes(&self.device, &self.routes, &mut self.platform);
    }
}

/// Resolve CIDR, IP-address, and domain route targets into validated CIDRs.
///
/// Domains are resolved once. Default routes and routes containing
/// `excluded_peer` are rejected so the iWAN control socket cannot be routed
/// into its own tunnel.
pub fn resolve_route_targets(
    cidrs: &[String],
    addresses: &[String],
    domains: &[String],
    excluded_peer: Option<IpAddr>,
) -> Result<Vec<String>> {
    let mut routes = Vec::new();
    for route in cidrs {
        push_route(&mut routes, Route::parse(route.trim())?, excluded_peer)?;
    }
    for address in addresses {
        let address = address
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| Error::InvalidConfig(format!("invalid route IP {address:?}")))?;
        let prefix = if address.is_ipv4() { 32 } else { 128 };
        push_route(
            &mut routes,
            Route {
                network: address,
                prefix,
            },
            excluded_peer,
        )?;
    }
    for domain in domains {
        let domain = domain.trim();
        if domain.is_empty() {
            return Err(Error::InvalidConfig(
                "route domain must not be empty".into(),
            ));
        }
        let resolved = (domain, 0)
            .to_socket_addrs()
            .map_err(|error| {
                Error::InvalidConfig(format!(
                    "failed to resolve route domain {domain:?}: {error}"
                ))
            })?
            .map(|address| address.ip())
            .collect::<Vec<_>>();
        if resolved.is_empty() {
            return Err(Error::InvalidConfig(format!(
                "route domain {domain:?} resolved to no addresses"
            )));
        }
        for address in resolved {
            let prefix = if address.is_ipv4() { 32 } else { 128 };
            push_route(
                &mut routes,
                Route {
                    network: address,
                    prefix,
                },
                excluded_peer,
            )?;
        }
    }
    Ok(routes.into_iter().map(|route| route.to_string()).collect())
}

fn push_route(routes: &mut Vec<Route>, route: Route, excluded_peer: Option<IpAddr>) -> Result<()> {
    if excluded_peer.is_some_and(|peer| route.contains(peer)) {
        return Err(Error::InvalidConfig(format!(
            "route {route} contains the active iWAN endpoint; choose a narrower route"
        )));
    }
    if !routes.contains(&route) {
        routes.push(route);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
type PlatformRoutes = ();

#[cfg(windows)]
type PlatformRoutes = windows_routes::WindowsRoutes;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
type PlatformRoutes = ();

#[cfg(target_os = "linux")]
fn configure_routes(device: &TunDevice, routes: &[Route]) -> Result<PlatformRoutes> {
    let mut installed = Vec::new();
    for route in routes {
        let route = route.to_string();
        if let Err(error) = run_command("ip", &["route", "replace", &route, "dev", device.name()]) {
            cleanup_linux_routes(device.name(), &installed);
            return Err(error);
        }
        installed.push(route);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn configure_routes(device: &TunDevice, routes: &[Route]) -> Result<PlatformRoutes> {
    let mut installed = Vec::new();
    for route in routes {
        let route = route.to_string();
        let family = if route.contains(':') {
            "-inet6"
        } else {
            "-net"
        };
        if let Err(error) = run_command(
            "route",
            &["-n", "add", family, &route, "-interface", device.name()],
        ) {
            cleanup_macos_routes(device.name(), &installed);
            return Err(error);
        }
        installed.push(route);
    }
    Ok(())
}

#[cfg(windows)]
fn configure_routes(device: &TunDevice, routes: &[Route]) -> Result<PlatformRoutes> {
    windows_routes::WindowsRoutes::configure(device.luid(), routes)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn configure_routes(_device: &TunDevice, _routes: &[Route]) -> Result<PlatformRoutes> {
    Err(Error::Unsupported(
        "route configuration is supported on Linux, macOS, and Windows",
    ))
}

#[cfg(target_os = "linux")]
fn cleanup_routes(device: &str, routes: &[Route], _platform: &mut PlatformRoutes) {
    let routes = routes.iter().map(ToString::to_string).collect::<Vec<_>>();
    cleanup_linux_routes(device, &routes);
    let _ = Command::new("ip")
        .args(["link", "set", "dev", device, "down"])
        .output();
}

#[cfg(target_os = "linux")]
fn cleanup_linux_routes(device: &str, routes: &[String]) {
    for route in routes.iter().rev() {
        let _ = Command::new("ip")
            .args(["route", "del", route, "dev", device])
            .output();
    }
}

#[cfg(target_os = "macos")]
fn cleanup_routes(device: &str, routes: &[Route], _platform: &mut PlatformRoutes) {
    let routes = routes.iter().map(ToString::to_string).collect::<Vec<_>>();
    cleanup_macos_routes(device, &routes);
    let _ = Command::new("ifconfig").args([device, "down"]).output();
}

#[cfg(target_os = "macos")]
fn cleanup_macos_routes(device: &str, routes: &[String]) {
    for route in routes.iter().rev() {
        let family = if route.contains(':') {
            "-inet6"
        } else {
            "-net"
        };
        let _ = Command::new("route")
            .args(["-n", "delete", family, route, "-interface", device])
            .output();
    }
}

#[cfg(windows)]
fn cleanup_routes(_device: &str, _routes: &[Route], platform: &mut PlatformRoutes) {
    platform.rollback();
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn cleanup_routes(_device: &str, _routes: &[Route], _platform: &mut PlatformRoutes) {}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_command(program: &str, arguments: &[&str]) -> Result<()> {
    let Output {
        status,
        stdout: _,
        stderr,
    } = Command::new(program).args(arguments).output()?;
    if !status.success() {
        return Err(Error::CommandFailed {
            program: program.into(),
            message: String::from_utf8_lossy(&stderr).trim().into(),
        });
    }
    Ok(())
}

fn netmask_prefix(mask: Ipv4Addr) -> Result<u8> {
    let bits = u32::from(mask);
    let prefix = bits.leading_ones() as u8;
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if bits != expected {
        return Err(Error::InvalidConfig(format!(
            "non-contiguous IPv4 netmask {mask}"
        )));
    }
    Ok(prefix)
}

#[cfg(any(windows, test))]
trait RouteBackend {
    type Row: Clone;

    fn desired(&self, route: &Route) -> std::io::Result<Self::Row>;
    fn get(&self, desired: &Self::Row) -> std::io::Result<Option<Self::Row>>;
    fn equivalent(&self, existing: &Self::Row, desired: &Self::Row) -> bool;
    fn create(&self, desired: &Self::Row) -> std::io::Result<()>;
    fn replace(&self, row: &Self::Row) -> std::io::Result<()>;
    fn delete(&self, row: &Self::Row) -> std::io::Result<()>;
}

#[cfg(any(windows, test))]
enum RouteChange<Row> {
    Created(Row),
    Replaced { previous: Row },
}

#[cfg(any(windows, test))]
fn apply_route_transaction<B: RouteBackend>(
    backend: &B,
    routes: &[Route],
) -> std::io::Result<Vec<RouteChange<B::Row>>> {
    let mut changes = Vec::new();
    for route in routes {
        let result = (|| {
            let desired = backend.desired(route)?;
            match backend.get(&desired)? {
                None => {
                    backend.create(&desired)?;
                    changes.push(RouteChange::Created(desired));
                }
                Some(existing) if backend.equivalent(&existing, &desired) => {}
                Some(previous) => {
                    backend.replace(&desired)?;
                    changes.push(RouteChange::Replaced { previous });
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            rollback_route_transaction(backend, &mut changes);
            return Err(error);
        }
    }
    Ok(changes)
}

#[cfg(any(windows, test))]
fn rollback_route_transaction<B: RouteBackend>(
    backend: &B,
    changes: &mut Vec<RouteChange<B::Row>>,
) {
    for change in changes.drain(..).rev() {
        match change {
            RouteChange::Created(row) => {
                let _ = backend.delete(&row);
            }
            RouteChange::Replaced { previous } => {
                let _ = backend.replace(&previous);
            }
        }
    }
}

#[cfg(windows)]
mod windows_routes {
    use super::{
        Error, Result, Route, RouteBackend, RouteChange, apply_route_transaction,
        rollback_route_transaction,
    };
    use std::io;
    use std::net::IpAddr;
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, DeleteIpForwardEntry2, GetIpForwardEntry2, InitializeIpForwardEntry,
        MIB_IPFORWARD_ROW2, SetIpForwardEntry2,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, MIB_IPPROTO_NETMGMT, NlroManual, SOCKADDR_INET,
    };

    pub(super) struct WindowsRoutes {
        backend: WindowsRouteBackend,
        changes: Vec<RouteChange<MIB_IPFORWARD_ROW2>>,
    }

    impl WindowsRoutes {
        pub(super) fn configure(luid: u64, routes: &[Route]) -> Result<Self> {
            let backend = WindowsRouteBackend { luid };
            let changes = apply_route_transaction(&backend, routes).map_err(|error| {
                Error::Tun(format!(
                    "configure Windows routes through Wintun: {error}; \
                     run openiwan from an elevated terminal"
                ))
            })?;
            Ok(Self { backend, changes })
        }

        pub(super) fn rollback(&mut self) {
            rollback_route_transaction(&self.backend, &mut self.changes);
        }
    }

    struct WindowsRouteBackend {
        luid: u64,
    }

    impl RouteBackend for WindowsRouteBackend {
        type Row = MIB_IPFORWARD_ROW2;

        fn desired(&self, route: &Route) -> io::Result<Self::Row> {
            let mut row = MIB_IPFORWARD_ROW2::default();
            // SAFETY: `row` is a writable MIB_IPFORWARD_ROW2 and the Windows
            // API only initializes that structure.
            unsafe { InitializeIpForwardEntry(&raw mut row) };
            row.InterfaceLuid = NET_LUID_LH { Value: self.luid };
            row.DestinationPrefix.Prefix = socket_address(route.network);
            row.DestinationPrefix.PrefixLength = route.prefix;
            row.NextHop = unspecified_address(route.network);
            row.SitePrefixLength = route.prefix;
            row.Metric = 0;
            row.Protocol = MIB_IPPROTO_NETMGMT;
            row.ValidLifetime = u32::MAX;
            row.PreferredLifetime = u32::MAX;
            row.Origin = NlroManual;
            Ok(row)
        }

        fn get(&self, desired: &Self::Row) -> io::Result<Option<Self::Row>> {
            let mut row = *desired;
            // SAFETY: `row` supplies the documented route key and remains
            // writable for the duration of GetIpForwardEntry2.
            match unsafe { GetIpForwardEntry2(&raw mut row) } {
                NO_ERROR => Ok(Some(row)),
                ERROR_NOT_FOUND | ERROR_FILE_NOT_FOUND => Ok(None),
                status => Err(os_error(status)),
            }
        }

        fn equivalent(&self, existing: &Self::Row, desired: &Self::Row) -> bool {
            existing.Metric == desired.Metric
                && existing.Protocol == desired.Protocol
                && existing.ValidLifetime == desired.ValidLifetime
                && existing.PreferredLifetime == desired.PreferredLifetime
                && existing.Origin == desired.Origin
        }

        fn create(&self, desired: &Self::Row) -> io::Result<()> {
            // SAFETY: `desired` is a fully initialized route row.
            status_result(unsafe { CreateIpForwardEntry2(desired) })
        }

        fn replace(&self, row: &Self::Row) -> io::Result<()> {
            // SAFETY: `row` is a route row returned by or prepared for the
            // IP Helper API.
            status_result(unsafe { SetIpForwardEntry2(row) })
        }

        fn delete(&self, row: &Self::Row) -> io::Result<()> {
            // SAFETY: `row` contains the documented route key.
            let status = unsafe { DeleteIpForwardEntry2(row) };
            if matches!(status, NO_ERROR | ERROR_NOT_FOUND | ERROR_FILE_NOT_FOUND) {
                Ok(())
            } else {
                Err(os_error(status))
            }
        }
    }

    fn socket_address(address: IpAddr) -> SOCKADDR_INET {
        let mut socket = SOCKADDR_INET::default();
        match address {
            IpAddr::V4(address) => {
                socket.Ipv4.sin_family = AF_INET;
                socket.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(address.octets());
            }
            IpAddr::V6(address) => {
                socket.Ipv6.sin6_family = AF_INET6;
                socket.Ipv6.sin6_addr.u.Byte = address.octets();
            }
        }
        socket
    }

    fn unspecified_address(address: IpAddr) -> SOCKADDR_INET {
        match address {
            IpAddr::V4(_) => socket_address(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            IpAddr::V6(_) => socket_address(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
        }
    }

    fn status_result(status: u32) -> io::Result<()> {
        if status == NO_ERROR {
            Ok(())
        } else {
            Err(os_error(status))
        }
    }

    fn os_error(status: u32) -> io::Error {
        io::Error::from_raw_os_error(status as i32)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn builds_ipv4_and_ipv6_rows_for_the_wintun_luid() {
            let backend = WindowsRouteBackend { luid: 42 };
            let ipv4 = backend
                .desired(&Route::parse("10.1.2.3/8").unwrap())
                .unwrap();
            // SAFETY: desired selected the IPv4 and Value union members.
            assert_eq!(unsafe { ipv4.InterfaceLuid.Value }, 42);
            assert_eq!(unsafe { ipv4.DestinationPrefix.Prefix.si_family }, AF_INET);
            assert_eq!(ipv4.DestinationPrefix.PrefixLength, 8);
            assert_eq!(
                unsafe { ipv4.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr },
                u32::from_ne_bytes([10, 0, 0, 0])
            );

            let ipv6 = backend
                .desired(&Route::parse("2001:db8:1::/32").unwrap())
                .unwrap();
            // SAFETY: desired selected the IPv6 union member.
            assert_eq!(unsafe { ipv6.DestinationPrefix.Prefix.si_family }, AF_INET6);
            assert_eq!(ipv6.DestinationPrefix.PrefixLength, 32);
            assert_eq!(
                unsafe { ipv6.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte },
                "2001:db8::".parse::<std::net::Ipv6Addr>().unwrap().octets()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    fn session(address: Option<IpAddr>, netmask: Option<Ipv4Addr>) -> SessionInfo {
        SessionInfo {
            peer: "192.0.2.1:6001".parse().unwrap(),
            session_id: 1,
            token: 2,
            encryption: crate::EncryptionMethod::Xor,
            mtu: 1400,
            address,
            gateway: None,
            netmask,
            dns_servers: Vec::new(),
            duplicate_packets: false,
            server_config: None,
        }
    }

    #[test]
    fn derives_ipv4_and_ipv6_interface_settings() {
        let v4 = interface_settings(
            None,
            &session(
                Some("10.0.0.8".parse().unwrap()),
                Some("255.255.252.0".parse().unwrap()),
            ),
        )
        .unwrap();
        assert_eq!(v4.netmask, "255.255.252.0".parse::<IpAddr>().unwrap());
        assert_eq!(v4.mtu, 1400);

        let v6 =
            interface_settings(None, &session(Some("2001:db8::8".parse().unwrap()), None)).unwrap();
        assert_eq!(v6.netmask, IpAddr::V6(Ipv6Addr::from(u128::MAX)));
        assert!(interface_settings(None, &session(None, None)).is_err());
    }

    #[test]
    fn chooses_the_platform_default_tun_name() {
        #[cfg(target_os = "macos")]
        {
            assert_eq!(platform_tun_name(None).unwrap(), None);
            assert_eq!(
                platform_tun_name(Some("utun7")).unwrap(),
                Some("utun7".into())
            );
            assert!(platform_tun_name(Some("openiwan0")).is_err());
        }
        #[cfg(not(target_os = "macos"))]
        {
            assert_eq!(
                platform_tun_name(None).unwrap(),
                Some(DEFAULT_TUN_NAME.into())
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_read_timeout_maps_to_would_block() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let result = runtime.block_on(tokio::time::timeout(Duration::from_millis(1), async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok::<usize, std::io::Error>(0)
        }));
        assert_eq!(
            map_windows_read_timeout(result).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn validates_and_canonicalizes_cidrs() {
        assert_eq!(
            Route::parse("10.2.3.4/8").unwrap().to_string(),
            "10.0.0.0/8"
        );
        assert_eq!(
            Route::parse("2001:db8:1::1/32").unwrap().to_string(),
            "2001:db8::/32"
        );
        assert!(Route::parse("10.0.0.0/33").is_err());
        assert!(Route::parse("10.0.0.0;id/8").is_err());
        assert!(Route::parse("0.0.0.0/0").is_err());
        assert!(Route::parse("::/0").is_err());
    }

    #[test]
    fn expands_and_deduplicates_route_targets() {
        assert_eq!(
            resolve_route_targets(
                &["10.1.2.3/8".into(), "10.0.0.0/8".into()],
                &["192.0.2.10".into(), "2001:db8::1".into()],
                &[],
                None,
            )
            .unwrap(),
            ["10.0.0.0/8", "192.0.2.10/32", "2001:db8::1/128"]
        );
        assert!(
            resolve_route_targets(
                &["192.0.2.0/24".into()],
                &[],
                &[],
                Some("192.0.2.10".parse().unwrap()),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_noncontiguous_netmask() {
        assert_eq!(
            netmask_prefix("255.255.252.0".parse().unwrap()).unwrap(),
            22
        );
        assert!(netmask_prefix("255.0.255.0".parse().unwrap()).is_err());
    }

    #[derive(Default)]
    struct MockBackend {
        rows: Mutex<HashMap<String, u8>>,
        fail_create: Mutex<HashSet<String>>,
        events: Mutex<Vec<String>>,
    }

    impl RouteBackend for MockBackend {
        type Row = (String, u8);

        fn desired(&self, route: &Route) -> std::io::Result<Self::Row> {
            Ok((route.to_string(), 0))
        }

        fn get(&self, desired: &Self::Row) -> std::io::Result<Option<Self::Row>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .get(&desired.0)
                .map(|metric| (desired.0.clone(), *metric)))
        }

        fn equivalent(&self, existing: &Self::Row, desired: &Self::Row) -> bool {
            existing == desired
        }

        fn create(&self, desired: &Self::Row) -> std::io::Result<()> {
            if self.fail_create.lock().unwrap().contains(&desired.0) {
                return Err(std::io::Error::other("injected create failure"));
            }
            self.events
                .lock()
                .unwrap()
                .push(format!("create {}", desired.0));
            self.rows
                .lock()
                .unwrap()
                .insert(desired.0.clone(), desired.1);
            Ok(())
        }

        fn replace(&self, row: &Self::Row) -> std::io::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(format!("replace {}", row.0));
            self.rows.lock().unwrap().insert(row.0.clone(), row.1);
            Ok(())
        }

        fn delete(&self, row: &Self::Row) -> std::io::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(format!("delete {}", row.0));
            self.rows.lock().unwrap().remove(&row.0);
            Ok(())
        }
    }

    #[test]
    fn route_transaction_rolls_back_in_reverse_order() {
        let backend = MockBackend::default();
        let routes = [
            Route::parse("10.0.0.0/8").unwrap(),
            Route::parse("192.0.2.0/24").unwrap(),
            Route::parse("2001:db8::/32").unwrap(),
        ];
        backend
            .fail_create
            .lock()
            .unwrap()
            .insert(routes[2].to_string());
        assert!(apply_route_transaction(&backend, &routes).is_err());
        assert!(backend.rows.lock().unwrap().is_empty());
        assert_eq!(
            *backend.events.lock().unwrap(),
            [
                "create 10.0.0.0/8",
                "create 192.0.2.0/24",
                "delete 192.0.2.0/24",
                "delete 10.0.0.0/8",
            ]
        );
    }

    #[test]
    fn route_transaction_restores_replaced_rows() {
        let backend = MockBackend::default();
        backend.rows.lock().unwrap().insert("10.0.0.0/8".into(), 42);
        let routes = [Route::parse("10.0.0.0/8").unwrap()];
        let mut changes = apply_route_transaction(&backend, &routes).unwrap();
        assert_eq!(backend.rows.lock().unwrap()["10.0.0.0/8"], 0);
        rollback_route_transaction(&backend, &mut changes);
        assert_eq!(backend.rows.lock().unwrap()["10.0.0.0/8"], 42);
    }
}
