use crate::client::{PacketDevice, SessionInfo};
use crate::{Error, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, ToSocketAddrs};
use std::os::fd::{AsRawFd, RawFd};
use std::process::{Command, Output};

#[cfg(target_os = "macos")]
use std::io::ErrorKind;
#[cfg(target_os = "macos")]
use std::os::fd::FromRawFd;

pub struct TunDevice {
    file: File,
    name: String,
}

impl std::fmt::Debug for TunDevice {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TunDevice")
            .field("name", &self.name)
            .field("fd", &self.file.as_raw_fd())
            .finish()
    }
}

impl TunDevice {
    #[cfg(target_os = "linux")]
    pub fn open(requested_name: &str) -> Result<Self> {
        use std::fs::OpenOptions;
        use std::os::unix::ffi::OsStrExt;

        const IFF_TUN: i16 = 0x0001;
        const IFF_NO_PI: i16 = 0x1000;
        const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

        #[repr(C)]
        struct IfReq {
            name: [libc::c_char; libc::IFNAMSIZ],
            data: [u8; 24],
        }

        if requested_name.len() >= libc::IFNAMSIZ {
            return Err(Error::InvalidConfig(format!(
                "TUN name must be shorter than {} bytes",
                libc::IFNAMSIZ
            )));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        let mut request = IfReq {
            name: [0; libc::IFNAMSIZ],
            data: [0; 24],
        };
        for (target, source) in request
            .name
            .iter_mut()
            .zip(std::ffi::OsStr::new(requested_name).as_bytes())
        {
            *target = *source as libc::c_char;
        }
        request.data[..2].copy_from_slice(&(IFF_TUN | IFF_NO_PI).to_ne_bytes());

        // SAFETY: `request` is a writable ifreq-sized structure and `file`
        // references /dev/net/tun for the lifetime of the ioctl call.
        let result = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut request) };
        if result < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        set_nonblocking(file.as_raw_fd())?;
        let name_end = request
            .name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(request.name.len());
        let name_bytes: Vec<u8> = request.name[..name_end]
            .iter()
            .map(|byte| byte.to_ne_bytes()[0])
            .collect();
        let name = String::from_utf8_lossy(&name_bytes).into_owned();
        Ok(Self { file, name })
    }

    #[cfg(target_os = "macos")]
    pub fn open(_requested_name: &str) -> Result<Self> {
        const SYSPROTO_CONTROL: libc::c_int = 2;
        const AF_SYS_CONTROL: u16 = 2;
        const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;
        const UTUN_OPT_IFNAME: libc::c_int = 2;
        const MAX_KCTL_NAME: usize = 96;

        #[repr(C)]
        struct ControlInfo {
            id: u32,
            name: [libc::c_char; MAX_KCTL_NAME],
        }

        #[repr(C)]
        struct SockAddrControl {
            length: u8,
            family: u8,
            sys_address: u16,
            id: u32,
            unit: u32,
            reserved: [u32; 5],
        }

        let control_name = b"com.apple.net.utun_control";
        let mut last_error = None;
        for unit in 1..=255_u32 {
            // SAFETY: arguments are fixed constants accepted by socket(2).
            let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
            if fd < 0 {
                return Err(Error::Io(std::io::Error::last_os_error()));
            }
            let mut info = ControlInfo {
                id: 0,
                name: [0; MAX_KCTL_NAME],
            };
            for (target, source) in info.name.iter_mut().zip(control_name) {
                *target = *source as libc::c_char;
            }
            // SAFETY: `info` has the exact ctl_info layout and remains writable
            // for the duration of ioctl(2).
            if unsafe { libc::ioctl(fd, CTLIOCGINFO, &mut info) } < 0 {
                let error = std::io::Error::last_os_error();
                // SAFETY: fd was created above and is not otherwise owned.
                unsafe { libc::close(fd) };
                return Err(Error::Io(error));
            }
            let address = SockAddrControl {
                length: std::mem::size_of::<SockAddrControl>() as u8,
                family: libc::AF_SYSTEM as u8,
                sys_address: AF_SYS_CONTROL,
                id: info.id,
                unit,
                reserved: [0; 5],
            };
            // SAFETY: `address` is a valid sockaddr_ctl and its size is passed
            // exactly to connect(2).
            let connected = unsafe {
                libc::connect(
                    fd,
                    (&raw const address).cast::<libc::sockaddr>(),
                    std::mem::size_of::<SockAddrControl>() as libc::socklen_t,
                )
            };
            if connected < 0 {
                last_error = Some(std::io::Error::last_os_error());
                // SAFETY: fd was created above and is not otherwise owned.
                unsafe { libc::close(fd) };
                continue;
            }

            let mut name = [0_u8; libc::IFNAMSIZ];
            let mut name_length = name.len() as libc::socklen_t;
            // SAFETY: the output buffer and socklen pointer are valid for this
            // getsockopt call.
            let result = unsafe {
                libc::getsockopt(
                    fd,
                    SYSPROTO_CONTROL,
                    UTUN_OPT_IFNAME,
                    name.as_mut_ptr().cast(),
                    &raw mut name_length,
                )
            };
            if result < 0 {
                let error = std::io::Error::last_os_error();
                // SAFETY: fd was created above and is not otherwise owned.
                unsafe { libc::close(fd) };
                return Err(Error::Io(error));
            }
            set_nonblocking(fd)?;
            let end = name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(name_length as usize);
            let name = String::from_utf8_lossy(&name[..end]).into_owned();
            // SAFETY: ownership of the connected fd is transferred to File.
            let file = unsafe { File::from_raw_fd(fd) };
            return Ok(Self { file, name });
        }
        Err(Error::Io(last_error.unwrap_or_else(|| {
            std::io::Error::new(ErrorKind::AddrNotAvailable, "no available utun unit")
        })))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub fn open(_requested_name: &str) -> Result<Self> {
        Err(Error::Unsupported(
            "native TUN creation is implemented only for Linux and macOS",
        ))
    }
}

impl PacketDevice for TunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    #[cfg(target_os = "linux")]
    fn read_packet(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let mut file = &self.file;
        file.read(buffer)
    }

    #[cfg(target_os = "macos")]
    fn read_packet(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let mut framed = vec![0_u8; buffer.len() + 4];
        let mut file = &self.file;
        let length = file.read(&mut framed)?;
        if length < 4 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "utun frame is shorter than its four-byte address-family prefix",
            ));
        }
        let packet_length = length - 4;
        buffer[..packet_length].copy_from_slice(&framed[4..length]);
        Ok(packet_length)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn read_packet(&self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            ErrorKind::Unsupported,
            "unsupported operating system",
        ))
    }

    #[cfg(target_os = "linux")]
    fn write_packet(&self, packet: &[u8]) -> std::io::Result<usize> {
        let mut file = &self.file;
        file.write_all(packet)?;
        Ok(packet.len())
    }

    #[cfg(target_os = "macos")]
    fn write_packet(&self, packet: &[u8]) -> std::io::Result<usize> {
        let family = match packet.first().map(|byte| byte >> 4) {
            Some(4) => libc::AF_INET as u32,
            Some(6) => libc::AF_INET6 as u32,
            _ => {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "utun write does not contain IPv4 or IPv6",
                ));
            }
        };
        let mut framed = Vec::with_capacity(packet.len() + 4);
        framed.extend_from_slice(&family.to_be_bytes());
        framed.extend_from_slice(packet);
        let mut file = &self.file;
        file.write_all(&framed)?;
        Ok(packet.len())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn write_packet(&self, _packet: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            ErrorKind::Unsupported,
            "unsupported operating system",
        ))
    }
}

pub struct RouteGuard {
    device: String,
    routes: Vec<String>,
}

impl std::fmt::Debug for RouteGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RouteGuard")
            .field("device", &self.device)
            .field("routes", &self.routes)
            .finish()
    }
}

impl RouteGuard {
    pub fn configure(device: &str, session: &SessionInfo, routes: &[String]) -> Result<Self> {
        let address = session.address.ok_or(Error::MissingTlv("IP/IP6"))?;
        for route in routes {
            validate_cidr(route)?;
        }
        let guard = Self {
            device: device.into(),
            routes: routes.to_vec(),
        };
        configure_interface(device, address, session, routes)?;
        Ok(guard)
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
        let route = route.trim();
        validate_cidr(route)?;
        push_route(&mut routes, route.to_owned(), excluded_peer)?;
    }
    for address in addresses {
        let address = address
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| Error::InvalidConfig(format!("invalid route IP {address:?}")))?;
        let route = match address {
            IpAddr::V4(_) => format!("{address}/32"),
            IpAddr::V6(_) => format!("{address}/128"),
        };
        push_route(&mut routes, route, excluded_peer)?;
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
            let route = match address {
                IpAddr::V4(_) => format!("{address}/32"),
                IpAddr::V6(_) => format!("{address}/128"),
            };
            push_route(&mut routes, route, excluded_peer)?;
        }
    }
    Ok(routes)
}

fn push_route(
    routes: &mut Vec<String>,
    route: String,
    excluded_peer: Option<IpAddr>,
) -> Result<()> {
    if let Some(peer) = excluded_peer {
        if cidr_contains(&route, peer)? {
            return Err(Error::InvalidConfig(format!(
                "route {route} contains the active iWAN endpoint; choose a narrower route"
            )));
        }
    }
    if !routes.iter().any(|existing| existing == &route) {
        routes.push(route);
    }
    Ok(())
}

fn cidr_contains(cidr: &str, candidate: IpAddr) -> Result<bool> {
    let (address, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| Error::InvalidConfig(format!("route {cidr:?} must use CIDR notation")))?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| Error::InvalidConfig(format!("invalid route address {address:?}")))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| Error::InvalidConfig(format!("invalid route prefix {prefix:?}")))?;
    Ok(match (address, candidate) {
        (IpAddr::V4(network), IpAddr::V4(candidate)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(network) & mask == u32::from(candidate) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(candidate)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(network) & mask == u128::from(candidate) & mask
        }
        _ => false,
    })
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        cleanup_interface(&self.device, &self.routes);
    }
}

#[cfg(target_os = "linux")]
fn configure_interface(
    device: &str,
    address: IpAddr,
    session: &SessionInfo,
    routes: &[String],
) -> Result<()> {
    let prefix = match (address, session.netmask) {
        (IpAddr::V4(_), Some(mask)) => netmask_prefix(mask)?,
        (IpAddr::V4(_), None) => 32,
        (IpAddr::V6(_), _) => 128,
    };
    run_command(
        "ip",
        &[
            "link",
            "set",
            "dev",
            device,
            "mtu",
            &session.mtu.to_string(),
        ],
    )?;
    run_command(
        "ip",
        &[
            "addr",
            "replace",
            &format!("{address}/{prefix}"),
            "dev",
            device,
        ],
    )?;
    run_command("ip", &["link", "set", "dev", device, "up"])?;
    for route in routes {
        run_command("ip", &["route", "replace", route, "dev", device])?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn configure_interface(
    device: &str,
    address: IpAddr,
    session: &SessionInfo,
    routes: &[String],
) -> Result<()> {
    match address {
        IpAddr::V4(address) => run_command(
            "ifconfig",
            &[
                device,
                &address.to_string(),
                &address.to_string(),
                "netmask",
                "255.255.255.255",
                "mtu",
                &session.mtu.to_string(),
                "up",
            ],
        )?,
        IpAddr::V6(address) => run_command(
            "ifconfig",
            &[
                device,
                "inet6",
                &format!("{address}/128"),
                "mtu",
                &session.mtu.to_string(),
                "up",
            ],
        )?,
    }
    for route in routes {
        let family = if route.contains(':') {
            "-inet6"
        } else {
            "-net"
        };
        run_command("route", &["-n", "add", family, route, "-interface", device])?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn configure_interface(
    _device: &str,
    _address: IpAddr,
    _session: &SessionInfo,
    _routes: &[String],
) -> Result<()> {
    Err(Error::Unsupported(
        "interface configuration is implemented only for Linux and macOS",
    ))
}

#[cfg(target_os = "linux")]
fn cleanup_interface(device: &str, routes: &[String]) {
    for route in routes.iter().rev() {
        let _ = Command::new("ip")
            .args(["route", "del", route, "dev", device])
            .output();
    }
    let _ = Command::new("ip")
        .args(["link", "set", "dev", device, "down"])
        .output();
}

#[cfg(target_os = "macos")]
fn cleanup_interface(device: &str, routes: &[String]) {
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
    let _ = Command::new("ifconfig").args([device, "down"]).output();
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn cleanup_interface(_device: &str, _routes: &[String]) {}

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

fn validate_cidr(value: &str) -> Result<()> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| Error::InvalidConfig(format!("route {value:?} must use CIDR notation")))?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| Error::InvalidConfig(format!("invalid route address {address:?}")))?;
    let prefix: u8 = prefix
        .parse()
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
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn netmask_prefix(mask: std::net::Ipv4Addr) -> Result<u8> {
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

fn set_nonblocking(fd: RawFd) -> Result<()> {
    // SAFETY: fcntl only observes the valid descriptor and returns its flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: fd remains valid and O_NONBLOCK is an accepted status flag.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_cidr_without_shell_interpretation() {
        assert!(validate_cidr("10.0.0.0/8").is_ok());
        assert!(validate_cidr("2001:db8::/32").is_ok());
        assert!(validate_cidr("10.0.0.0/33").is_err());
        assert!(validate_cidr("10.0.0.0;id/8").is_err());
        assert!(validate_cidr("0.0.0.0/0").is_err());
        assert!(validate_cidr("::/0").is_err());
    }

    #[test]
    fn expands_and_deduplicates_route_targets() {
        assert_eq!(
            resolve_route_targets(
                &["10.0.0.0/8".into(), "10.0.0.0/8".into()],
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
}
