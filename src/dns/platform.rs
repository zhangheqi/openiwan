use crate::{Error, Result};
use std::collections::HashSet;
use std::fmt;
#[cfg(target_os = "macos")]
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Stdio;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPlatformTarget {
    pub interface_name: String,
    /// Windows `NET_LUID`; ignored on other platforms.
    pub platform_id: Option<u64>,
}

impl DnsPlatformTarget {
    pub fn new(interface_name: impl Into<String>) -> Self {
        Self {
            interface_name: interface_name.into(),
            platform_id: None,
        }
    }

    pub fn with_platform_id(interface_name: impl Into<String>, platform_id: u64) -> Self {
        Self {
            interface_name: interface_name.into(),
            platform_id: Some(platform_id),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.interface_name.is_empty()
            || self.interface_name.len() > 128
            || !self
                .interface_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(Error::InvalidConfig(
                "DNS interface name contains unsupported characters".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalResolver {
    pub address: SocketAddr,
    pub interface_name: Option<String>,
    pub interface_index: Option<u32>,
}

impl PhysicalResolver {
    pub fn new(address: IpAddr) -> Self {
        Self {
            address: SocketAddr::new(address, 53),
            interface_name: None,
            interface_index: None,
        }
    }
}

enum PlatformLease {
    None,
    #[cfg(target_os = "linux")]
    Resolved {
        interface: String,
    },
    #[cfg(target_os = "linux")]
    Resolvconf {
        interface: String,
    },
    #[cfg(target_os = "macos")]
    Scutil {
        key: String,
    },
    #[cfg(windows)]
    Windows(WindowsDnsLease),
}

/// A link-scoped DNS configuration that restores its prior state on drop.
pub struct PlatformDnsLease {
    lease: PlatformLease,
}

impl fmt::Debug for PlatformDnsLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlatformDnsLease")
            .finish_non_exhaustive()
    }
}

impl PlatformDnsLease {
    pub fn apply(target: &DnsPlatformTarget, servers: &[Ipv4Addr]) -> Result<Self> {
        target.validate()?;
        if servers.is_empty() {
            return Ok(Self {
                lease: PlatformLease::None,
            });
        }

        #[cfg(target_os = "linux")]
        {
            if command_exists("resolvectl") {
                apply_resolved(&target.interface_name, servers)?;
                return Ok(Self {
                    lease: PlatformLease::Resolved {
                        interface: target.interface_name.clone(),
                    },
                });
            }
            if command_exists("resolvconf") {
                apply_resolvconf(&target.interface_name, servers)?;
                return Ok(Self {
                    lease: PlatformLease::Resolvconf {
                        interface: target.interface_name.clone(),
                    },
                });
            }
            Err(Error::CommandFailed {
                program: "resolvectl/resolvconf".into(),
                message: "no supported link-scoped Linux DNS backend is installed".into(),
            })
        }

        #[cfg(target_os = "macos")]
        {
            let key = format!(
                "State:/Network/Service/openiwan-{}/DNS",
                target.interface_name
            );
            let server_values = servers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            run_scutil(&format!(
                "d.init\nd.add ServerAddresses * {server_values}\n\
                 d.add SupplementalMatchDomains * \"\"\nset {key}\n"
            ))?;
            Ok(Self {
                lease: PlatformLease::Scutil { key },
            })
        }

        #[cfg(windows)]
        {
            let luid = target.platform_id.ok_or_else(|| {
                Error::Tun("Windows DNS configuration requires the Wintun NET_LUID".into())
            })?;
            Ok(Self {
                lease: PlatformLease::Windows(WindowsDnsLease::apply(luid, servers)?),
            })
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            let _ = target;
            Err(Error::Tun(
                "DNS configuration is supported on Linux, macOS, and Windows".into(),
            ))
        }
    }
}

impl Drop for PlatformDnsLease {
    fn drop(&mut self) {
        match &self.lease {
            PlatformLease::None => {}
            #[cfg(target_os = "linux")]
            PlatformLease::Resolved { interface } => {
                let _ = Command::new("resolvectl")
                    .args(["revert", interface])
                    .output();
            }
            #[cfg(target_os = "linux")]
            PlatformLease::Resolvconf { interface } => {
                let _ = Command::new("resolvconf").args(["-d", interface]).output();
            }
            #[cfg(target_os = "macos")]
            PlatformLease::Scutil { key } => {
                let _ = run_scutil(&format!("remove {key}\n"));
            }
            #[cfg(windows)]
            PlatformLease::Windows(lease) => lease.restore(),
        }
    }
}

/// Snapshot usable physical resolvers before the VPN mutates link DNS.
pub fn discover_physical_resolvers() -> Result<Vec<PhysicalResolver>> {
    #[cfg(target_os = "linux")]
    let addresses = {
        let mut addresses = resolved_resolvers();
        addresses.extend(parse_resolv_conf(&std::fs::read_to_string(
            "/etc/resolv.conf",
        )?));
        addresses
    };
    #[cfg(all(unix, not(target_os = "linux")))]
    let addresses = parse_resolv_conf(&std::fs::read_to_string("/etc/resolv.conf")?);
    #[cfg(target_os = "wasi")]
    let addresses = parse_resolv_conf(&std::fs::read_to_string("/etc/resolv.conf")?);
    #[cfg(windows)]
    let addresses = windows_resolvers()?;
    #[cfg(not(any(unix, windows, target_os = "wasi")))]
    let addresses = Vec::new();

    let mut seen = HashSet::new();
    Ok(addresses
        .into_iter()
        .filter(|address| {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && seen.insert(*address)
        })
        .map(|address| {
            let (interface_name, interface_index) = physical_interface(address);
            PhysicalResolver {
                address: SocketAddr::new(address, 53),
                interface_name,
                interface_index,
            }
        })
        .take(8)
        .collect())
}

#[cfg(target_os = "linux")]
fn resolved_resolvers() -> Vec<IpAddr> {
    Command::new("resolvectl")
        .arg("dns")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map_or_else(Vec::new, |output| {
            String::from_utf8_lossy(&output.stdout)
                .split_whitespace()
                .filter_map(|field| field.trim_end_matches(':').parse::<IpAddr>().ok())
                .collect()
        })
}

#[cfg(any(unix, target_os = "wasi"))]
fn parse_resolv_conf(contents: &str) -> Vec<IpAddr> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or_default();
            let mut fields = line.split_whitespace();
            (fields.next()? == "nameserver")
                .then(|| fields.next()?.parse::<IpAddr>().ok())
                .flatten()
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn physical_interface(address: IpAddr) -> (Option<String>, Option<u32>) {
    let output = Command::new("ip")
        .args(["route", "get", &address.to_string()])
        .output();
    let name = output
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut fields = text.split_whitespace();
            while let Some(field) = fields.next() {
                if field == "dev" {
                    return fields.next().map(ToOwned::to_owned);
                }
            }
            None
        });
    let index = name.as_deref().and_then(interface_index);
    (name, index)
}

#[cfg(target_os = "macos")]
fn physical_interface(address: IpAddr) -> (Option<String>, Option<u32>) {
    let output = Command::new("route")
        .args(["-n", "get", &address.to_string()])
        .output();
    let name = output
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .find_map(|line| line.trim().strip_prefix("interface:").map(str::trim))
                .map(ToOwned::to_owned)
        });
    let index = name.as_deref().and_then(interface_index);
    (name, index)
}

#[cfg(windows)]
fn physical_interface(address: IpAddr) -> (Option<String>, Option<u32>) {
    use windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterface;
    let IpAddr::V4(address) = address else {
        return (None, None);
    };
    let mut index = 0_u32;
    // GetBestInterface expects the IPv4 address in network byte order.
    let status = unsafe { GetBestInterface(u32::from_ne_bytes(address.octets()), &raw mut index) };
    (None, (status == 0).then_some(index))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn physical_interface(_address: IpAddr) -> (Option<String>, Option<u32>) {
    (None, None)
}

#[cfg(unix)]
fn interface_index(name: &str) -> Option<u32> {
    use std::ffi::CString;
    let name = CString::new(name).ok()?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

#[cfg(target_os = "linux")]
fn command_exists(program: &str) -> bool {
    Command::new(program)
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

#[cfg(target_os = "linux")]
fn apply_resolved(interface: &str, servers: &[Ipv4Addr]) -> Result<()> {
    let server_strings = servers.iter().map(ToString::to_string).collect::<Vec<_>>();
    let mut arguments = vec!["dns", interface];
    arguments.extend(server_strings.iter().map(String::as_str));
    run_command("resolvectl", &arguments)?;
    if let Err(error) = run_command("resolvectl", &["domain", interface, "~."]) {
        let _ = Command::new("resolvectl")
            .args(["revert", interface])
            .output();
        return Err(error);
    }
    if let Err(error) = run_command("resolvectl", &["default-route", interface, "yes"]) {
        let _ = Command::new("resolvectl")
            .args(["revert", interface])
            .output();
        return Err(error);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_resolvconf(interface: &str, servers: &[Ipv4Addr]) -> Result<()> {
    use std::fmt::Write as _;
    use std::io::Write as _;
    let mut child = Command::new("resolvconf")
        .args(["-a", interface])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = String::new();
    for server in servers {
        writeln!(&mut input, "nameserver {server}")
            .expect("writing a resolver address to a String cannot fail");
    }
    child
        .stdin
        .take()
        .ok_or_else(|| Error::Tun("failed to open resolvconf stdin".into()))?
        .write_all(input.as_bytes())?;
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        let _ = Command::new("resolvconf").args(["-d", interface]).output();
        Err(Error::CommandFailed {
            program: "resolvconf".into(),
            message: String::from_utf8_lossy(&output.stderr).trim().into(),
        })
    }
}

#[cfg(target_os = "linux")]
fn run_command(program: &str, arguments: &[&str]) -> Result<()> {
    let output = Command::new(program).args(arguments).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::CommandFailed {
            program: program.into(),
            message: String::from_utf8_lossy(&output.stderr).trim().into(),
        })
    }
}

#[cfg(target_os = "macos")]
fn run_scutil(script: &str) -> Result<()> {
    let mut child = Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| Error::Tun("failed to open scutil stdin".into()))?
        .write_all(script.as_bytes())?;
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::CommandFailed {
            program: "scutil".into(),
            message: String::from_utf8_lossy(&output.stderr).trim().into(),
        })
    }
}

#[cfg(windows)]
struct WindowsDnsLease {
    guid: windows_sys::core::GUID,
    previous: Option<String>,
}

#[cfg(windows)]
impl WindowsDnsLease {
    fn apply(luid_value: u64, servers: &[Ipv4Addr]) -> Result<Self> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            ConvertInterfaceLuidToGuid, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
            FreeInterfaceDnsSettings, GetInterfaceDnsSettings,
        };
        use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

        let luid = NET_LUID_LH { Value: luid_value };
        let mut guid = windows_sys::core::GUID::default();
        let status = unsafe { ConvertInterfaceLuidToGuid(&raw const luid, &raw mut guid) };
        if status != 0 {
            return Err(Error::Tun(format!(
                "ConvertInterfaceLuidToGuid failed with status {status}"
            )));
        }

        let mut current = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            ..DNS_INTERFACE_SETTINGS::default()
        };
        let status = unsafe { GetInterfaceDnsSettings(guid, &raw mut current) };
        let previous = if status == 0 {
            let value = wide_string(current.NameServer);
            unsafe { FreeInterfaceDnsSettings(&raw mut current) };
            value
        } else {
            None
        };
        let joined = servers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        set_windows_dns(guid, Some(&joined))?;
        Ok(Self { guid, previous })
    }

    fn restore(&self) {
        let _ = set_windows_dns(self.guid, self.previous.as_deref());
    }
}

#[cfg(windows)]
fn set_windows_dns(guid: windows_sys::core::GUID, servers: Option<&str>) -> Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER,
        SetInterfaceDnsSettings,
    };
    let mut wide = servers.map(std::ffi::OsStr::new).map(|value| {
        value
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>()
    });
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: u64::from(DNS_SETTING_NAMESERVER),
        NameServer: wide.as_mut().map_or(std::ptr::null_mut(), Vec::as_mut_ptr),
        ..DNS_INTERFACE_SETTINGS::default()
    };
    let status = unsafe { SetInterfaceDnsSettings(guid, &raw const settings) };
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Tun(format!(
            "SetInterfaceDnsSettings failed with status {status}"
        )))
    }
}

#[cfg(windows)]
fn wide_string(pointer: windows_sys::core::PWSTR) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let mut length = 0;
    unsafe {
        while *pointer.add(length) != 0 {
            length += 1;
        }
        Some(String::from_utf16_lossy(std::slice::from_raw_parts(
            pointer, length,
        )))
    }
}

#[cfg(windows)]
fn windows_resolvers() -> Result<Vec<IpAddr>> {
    use std::ffi::CStr;
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FIXED_INFO_W2KSP1, GetNetworkParams, IP_ADDR_STRING,
    };

    let mut length = 0_u32;
    let status = unsafe { GetNetworkParams(std::ptr::null_mut(), &raw mut length) };
    if status != ERROR_BUFFER_OVERFLOW || length == 0 {
        return Err(Error::Tun(format!(
            "GetNetworkParams sizing failed with status {status}"
        )));
    }
    let element_count = (length as usize).div_ceil(std::mem::size_of::<FIXED_INFO_W2KSP1>());
    let mut storage = Vec::with_capacity(element_count);
    storage.resize_with(
        element_count,
        std::mem::MaybeUninit::<FIXED_INFO_W2KSP1>::uninit,
    );
    let fixed = storage.as_mut_ptr().cast::<FIXED_INFO_W2KSP1>();
    let status = unsafe { GetNetworkParams(fixed, &raw mut length) };
    if status != 0 {
        return Err(Error::Tun(format!(
            "GetNetworkParams failed with status {status}"
        )));
    }

    let mut output = Vec::new();
    let mut current: *const IP_ADDR_STRING = unsafe { &raw const (*fixed).DnsServerList };
    while !current.is_null() {
        let bytes = unsafe { &(*current).IpAddress.String };
        let pointer = bytes.as_ptr().cast::<std::ffi::c_char>();
        let value = unsafe { CStr::from_ptr(pointer) }.to_string_lossy();
        if let Ok(address) = value.parse::<IpAddr>() {
            output.push(address);
        }
        current = unsafe { (*current).Next };
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_platform_target_names() {
        assert!(DnsPlatformTarget::new("utun42").validate().is_ok());
        assert!(DnsPlatformTarget::new("Ethernet_2").validate().is_ok());
        assert!(DnsPlatformTarget::new("").validate().is_err());
        assert!(
            DnsPlatformTarget::new("utun0\nremove State:/Network")
                .validate()
                .is_err()
        );
    }

    #[cfg(any(unix, target_os = "wasi"))]
    #[test]
    fn parses_nameservers_without_search_or_comments() {
        assert_eq!(
            parse_resolv_conf(
                "search example.test\nnameserver 192.0.2.53 # primary\nnameserver ::1\n"
            ),
            [
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
                "::1".parse().unwrap()
            ]
        );
    }
}
