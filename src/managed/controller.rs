use super::http::{HttpRequest, HttpTransport};
use super::password;
use super::security;
use crate::dns::{DnsDefaults, DnsServerMode, DomainRule, ServerListDnsMode, SplitDnsMode};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr as _;
use url::Url;
use zeroize::Zeroize;

pub const LOOKUP_PATH: &str = "/lookup";
pub const AUTH_PATH: &str = "/auth";
pub const API_LOGIN_PATH: &str = "/api/login";
pub const APP_LOGIN_PATH: &str = "/api/get-app-login";
pub const CONFIG_PATH: &str = "/config";
pub const LOGOS_PATH: &str = "/logos";
pub const HEALTH_PATH: &str = "/health";
pub const POSTURE_EVALUATE_PATH: &str = "/posture/evaluate";
pub const POSTURE_RELOAD_PATH: &str = "/posture/reload";
pub const KEEPALIVE_RELOAD_PATH: &str = "/keepalive/reload";
pub const UPDATE_CHECK_PATH: &str = "/update/check";

#[derive(Debug, Serialize)]
struct ConfigRequest<'a> {
    domain: &'a str,
    #[serde(rename = "type")]
    client_type: &'a str,
    oem_name: &'static str,
    app_version: &'static str,
    device_id: &'a str,
    #[serde(rename = "userName", skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    posture_version: Option<i64>,
}

pub(crate) struct ConfigParameters<'a> {
    pub domain: &'a str,
    pub client_type: &'a str,
    pub controller_app_id: &'a str,
    pub access_token: Option<&'a str>,
    pub username: Option<&'a str>,
    pub device_id: &'a str,
    pub posture_version: Option<i64>,
}

/// Dynamically decoded `/config` response.
///
/// Callers can inspect the raw object for deployment-specific members while
/// using typed accessors for the protocol-defined configuration.
#[derive(Clone)]
pub struct ControllerConfiguration {
    raw: Value,
    credential_app_id: Option<String>,
    credential_domain: Option<String>,
}

impl std::fmt::Debug for ControllerConfiguration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControllerConfiguration")
            .field("has_posture", &self.posture().is_some())
            .field("has_keepalive", &self.keepalive().is_some())
            .field(
                "has_device_binding",
                &self.device_binding_status_raw().is_some(),
            )
            .field(
                "server_count",
                &self.iwan_servers().map_or(0, |servers| servers.len()),
            )
            .field(
                "sr_group_count",
                &self.sr_groups().map_or(0, |groups| groups.len()),
            )
            .finish_non_exhaustive()
    }
}

impl ControllerConfiguration {
    pub(crate) const fn from_raw(raw: Value) -> Self {
        Self {
            raw,
            credential_app_id: None,
            credential_domain: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_controller_raw(raw: Value, app_id: &str, domain: &str) -> Self {
        Self {
            raw,
            credential_app_id: Some(app_id.to_owned()),
            credential_domain: Some(domain.to_owned()),
        }
    }

    pub const fn raw(&self) -> &Value {
        &self.raw
    }

    pub fn into_raw(self) -> Value {
        self.raw
    }

    pub fn posture(&self) -> Option<&Value> {
        nonempty_object_member(&self.raw, "posture")
    }

    pub fn keepalive(&self) -> Option<&Value> {
        nonempty_object_member(&self.raw, "keepalive")
    }

    pub fn device_binding_status_raw(&self) -> Option<&Value> {
        self.raw.get("device_binding_status")
    }

    pub fn device_binding_status(&self) -> Option<DeviceBindingStatus> {
        let value = self.device_binding_status_raw()?;
        let value = value
            .as_object()
            .and_then(|object| object.get("code").or_else(|| object.get("status")))
            .unwrap_or(value);
        if let Some(code) = value.as_i64().and_then(|code| i32::try_from(code).ok()) {
            return DeviceBindingStatus::from_code(code);
        }
        let value = value.as_str()?.trim();
        if let Ok(code) = value.parse::<i32>() {
            return DeviceBindingStatus::from_code(code);
        }
        DeviceBindingStatus::from_name(value)
    }

    pub fn enforce_device_binding(&self) -> Result<()> {
        let Some(status) = self.device_binding_status() else {
            return Ok(());
        };
        Err(Error::DeviceBindingBlocked {
            code: status.code(),
            status: status.as_str(),
        })
    }

    pub fn ip_filter_raw(&self) -> Option<&Value> {
        self.raw.get("ipfilter")
    }

    /// Decode the IP-filter cache format.
    ///
    /// The version belongs to the outer object while rules may be nested in
    /// an `ipfilter` member. Empty and non-string rules are ignored.
    pub fn ip_filter(&self) -> Result<Option<IpFilterConfiguration>> {
        let Some(raw) = self.ip_filter_raw() else {
            return Ok(None);
        };
        let outer = raw
            .as_object()
            .ok_or_else(|| Error::Controller("ipfilter must be an object".into()))?;
        let version = outer
            .get("version")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Error::Controller("ipfilter has no version".into()))?
            .to_owned();
        let rules = outer
            .get("ipfilter")
            .and_then(Value::as_object)
            .unwrap_or(outer);
        Ok(Some(IpFilterConfiguration {
            version,
            updated: rules
                .get("updated")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            inclusive: nonempty_string_array(rules.get("inclusive")),
            exclusive: nonempty_string_array(rules.get("exclusive")),
        }))
    }

    pub fn branding(&self) -> Option<&Value> {
        self.raw.get("branding")
    }

    pub fn routing_policy(&self) -> Option<&Value> {
        self.raw.get("routing")
    }

    pub fn routing(&self) -> Result<Option<RoutingConfiguration>> {
        let Some(value) = self.routing_policy() else {
            return Ok(None);
        };
        let object = value
            .as_object()
            .ok_or_else(|| Error::Controller("routing policy must be an object".into()))?;
        let mode = match object
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("all")
            .to_ascii_lowercase()
            .as_str()
        {
            "ipfilter" => RoutingMode::IpFilter,
            "custom" => RoutingMode::Custom,
            _ => RoutingMode::All,
        };
        let custom_routes = object
            .get("custom_routes")
            .and_then(Value::as_str)
            .map(|routes| {
                routes
                    .split(',')
                    .map(str::trim)
                    .filter(|route| !route.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Ok(Some(RoutingConfiguration {
            mode,
            custom_routes,
            mtu_mode: string_member(object, "mtu_mode", "server"),
            custom_mtu: object
                .get("custom_mtu")
                .and_then(Value::as_i64)
                .and_then(|value| i32::try_from(value).ok())
                .unwrap_or(0),
        }))
    }

    /// Routes installed in `custom` mode.
    ///
    /// Other modes need platform VPN exclusion semantics and are therefore
    /// represented by [`Self::routing`] instead of being silently flattened
    /// into an incorrect route list.
    pub fn custom_routes(&self) -> Result<Vec<String>> {
        Ok(self
            .routing()?
            .filter(|routing| routing.mode == RoutingMode::Custom)
            .map_or_else(Vec::new, |routing| routing.custom_routes))
    }

    /// Decode every controller DNS source into one strongly typed policy.
    ///
    /// Malformed remote list entries are ignored with diagnostics. Structural
    /// errors and invalid scalar modes fail the configuration instead of
    /// leaking stringly typed values into the data plane.
    pub fn dns_defaults(&self, controller_service: bool) -> Result<DnsDefaults> {
        let mut defaults = DnsDefaults {
            controller_service,
            ..DnsDefaults::default()
        };

        if let Some(object) = self.raw.get("dns").and_then(Value::as_object) {
            defaults.server_mode = ServerListDnsMode::from_server_value(
                object.get("mode").and_then(Value::as_str).unwrap_or("auto"),
            );
            defaults.server_dns = parse_ipv4_list(object.get("servers"), "server-list DNS");
        }

        if let Some(raw) = self.raw.get("domainfilter") {
            let object = raw
                .as_object()
                .ok_or_else(|| Error::Controller("domainfilter must be an object".into()))?;
            let domain_filter_mode = object.get("mode").and_then(Value::as_str).unwrap_or("");
            defaults.managed_domain_filter =
                domain_filter_mode.eq_ignore_ascii_case("domain_filter");
            if !domain_filter_mode.is_empty()
                && !defaults.managed_domain_filter
                && !domain_filter_mode.eq_ignore_ascii_case("tunnel_all")
            {
                tracing::warn!(
                    %domain_filter_mode,
                    "invalid controller domain-filter mode; failing open to tunnel-all"
                );
            }
            defaults.managed_inclusive =
                parse_domain_rules(object.get("inclusive"), "inclusive domain-filter");
            defaults.managed_exclusive =
                parse_domain_rules(object.get("exclusive"), "exclusive domain-filter");
            defaults.block_encrypted_dns = object
                .get("drop_secure_dns")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            defaults.secure_dns_hosts =
                parse_dns_hosts(object.get("secure_dns_hosts"), "secure DNS");
        }

        if let Some(raw) = self.routing_policy() {
            let object = raw
                .as_object()
                .ok_or_else(|| Error::Controller("routing policy must be an object".into()))?;
            defaults.local_mode = DnsServerMode::from_str(
                object
                    .get("dns_mode")
                    .and_then(Value::as_str)
                    .unwrap_or("server"),
            )?;
            defaults.local_dns = ["custom_dns1", "custom_dns2"]
                .into_iter()
                .filter_map(|key| {
                    let value = object.get(key)?.as_str()?.trim();
                    if value.is_empty() {
                        return None;
                    }
                    if let Ok(address) = value.parse::<Ipv4Addr>() {
                        Some(address)
                    } else {
                        tracing::warn!(%value, "ignoring invalid controller custom DNS");
                        None
                    }
                })
                .collect();
            defaults.split_mode = if object
                .get("split_dns_enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                object
                    .get("split_dns_mode")
                    .and_then(Value::as_str)
                    .filter(|mode| !mode.is_empty())
                    .map_or(Ok(SplitDnsMode::Managed), SplitDnsMode::from_str)?
            } else {
                SplitDnsMode::Off
            };
            if defaults.split_mode == SplitDnsMode::Managed && !defaults.managed_domain_filter {
                defaults.split_mode = SplitDnsMode::TunnelAll;
            }
            defaults.custom_domains =
                parse_domain_rules(object.get("split_dns_custom_domains"), "custom split-DNS");
            if let Some(value) = object
                .get("block_encrypted_dns_override")
                .and_then(Value::as_bool)
            {
                defaults.block_encrypted_dns = value;
            }
            defaults.secure_dns_hosts.extend(parse_dns_hosts(
                object.get("block_encrypted_dns_hosts"),
                "encrypted-DNS override",
            ));
        }
        Ok(defaults)
    }

    pub fn iwan_servers(&self) -> Result<Vec<ServerInfo>> {
        let serverlist_present = self
            .raw
            .get("serverlist")
            .is_some_and(|value| !value.is_null());
        let sites_present = self.raw.get("sites").is_some_and(|value| !value.is_null());
        if serverlist_present && sites_present {
            return Err(Error::Controller(
                "mixed iWAN and SR config payload is invalid".into(),
            ));
        }
        let Some(serverlist) = self.raw.get("serverlist") else {
            return Ok(Vec::new());
        };
        let values = match serverlist {
            // Lookup-backed server lists are normalized to an array internally.
            Value::Array(values) => values,
            Value::Object(serverlist) => serverlist
                .get("serverlist")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    Error::Controller("serverlist config has no serverlist array".into())
                })?,
            _ => {
                return Err(Error::Controller(
                    "controller serverlist has an unexpected JSON type".into(),
                ));
            }
        };
        let servers: Vec<_> = values.iter().filter_map(ServerInfo::parse).collect();
        if values.is_empty() || servers.is_empty() {
            return Err(Error::Controller(
                "no valid servers found in configuration".into(),
            ));
        }
        Ok(servers)
    }

    pub fn server_credentials(&self) -> Result<HashMap<String, ServerCredentials>> {
        // The controller response embeds generated credentials in each server
        // entry. Keep them separate from public server metadata.
        let servers = match self.raw.get("serverlist") {
            Some(Value::Array(servers)) => Some(servers),
            Some(Value::Object(serverlist)) => {
                serverlist.get("serverlist").and_then(Value::as_array)
            }
            _ => None,
        };
        let (Some(app_id), Some(complete_domain)) = (
            self.credential_app_id.as_deref(),
            self.credential_domain.as_deref(),
        ) else {
            if servers.is_some_and(|servers| {
                servers.iter().any(|value| {
                    value
                        .as_object()
                        .is_some_and(|object| object.contains_key("passWord"))
                })
            }) {
                return Err(Error::Controller(
                    "controller server credentials have no lookup decryption context".into(),
                ));
            }
            return Ok(HashMap::new());
        };
        servers
            .into_iter()
            .flatten()
            .filter_map(|value| {
                let object = value.as_object()?;
                let server_id = json_opt_i32(object.get("id"), -1);
                let username = json_opt_string(object.get("userName"), "");
                let encrypted_password = json_opt_string(object.get("passWord"), "");
                if server_id == -1 || username.is_empty() || encrypted_password.is_empty() {
                    return None;
                }
                Some(
                    password::decrypt_saas_password(
                        app_id,
                        complete_domain,
                        &username,
                        &encrypted_password,
                    )
                    .and_then(|password| {
                        if password.is_empty() {
                            Err(Error::Crypto(
                                "controller password decryption returned an empty value",
                            ))
                        } else {
                            Ok(password)
                        }
                    })
                    .map(|password| {
                        (
                            server_id.to_string(),
                            ServerCredentials { username, password },
                        )
                    }),
                )
            })
            .collect()
    }

    pub fn sr_groups(&self) -> Result<Vec<SrGroup>> {
        let Some(sites) = self.raw.get("sites") else {
            return Ok(Vec::new());
        };
        let sites = sites
            .as_array()
            .ok_or_else(|| Error::Controller("sites must be an array".into()))?;
        let mut groups = sites
            .iter()
            .map(|site| {
                serde_json::from_value(site.clone())
                    .map_err(|error| Error::Controller(format!("invalid SR group: {error}")))
            })
            .collect::<Result<Vec<SrGroup>>>()?;
        let (Some(app_id), Some(complete_domain)) = (
            self.credential_app_id.as_deref(),
            self.credential_domain.as_deref(),
        ) else {
            if groups.iter().any(|group| {
                group
                    .entries
                    .iter()
                    .any(|entry| !entry.ingress.password.is_empty())
            }) {
                return Err(Error::Controller(
                    "SR ingress credentials have no lookup decryption context".into(),
                ));
            }
            return Ok(groups);
        };
        for group in &mut groups {
            for entry in &mut group.entries {
                if entry.ingress.password.is_empty() {
                    continue;
                }
                let decrypted = password::decrypt_saas_password(
                    app_id,
                    complete_domain,
                    &entry.ingress.username,
                    &entry.ingress.password,
                )?;
                if decrypted.is_empty() {
                    return Err(Error::Crypto(
                        "SR ingress password decryption returned an empty value",
                    ));
                }
                entry.ingress.password.zeroize();
                entry.ingress.password = decrypted;
            }
        }
        Ok(groups)
    }
}

fn nonempty_object_member<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let member = value.get(name)?;
    member
        .as_object()
        .is_some_and(|object| !object.is_empty())
        .then_some(member)
}

fn nonempty_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn string_member(object: &serde_json::Map<String, Value>, name: &str, default: &str) -> String {
    object
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or(default)
        .to_owned()
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| {
            let value = match value {
                Value::String(value) => value.trim().to_owned(),
                Value::Null => return None,
                value => value.to_string().trim().to_owned(),
            };
            (!value.is_empty()).then_some(value)
        })
        .collect()
}

fn parse_ipv4_list(value: Option<&Value>, label: &str) -> Vec<Ipv4Addr> {
    string_list(value)
        .into_iter()
        .filter_map(|value| {
            if let Ok(address) = value.parse::<Ipv4Addr>() {
                Some(address)
            } else {
                tracing::warn!(%value, %label, "ignoring invalid controller DNS server");
                None
            }
        })
        .collect()
}

fn parse_domain_rules(value: Option<&Value>, label: &str) -> Vec<DomainRule> {
    string_list(value)
        .into_iter()
        .filter_map(|value| match DomainRule::parse(&value) {
            Ok(rule) => Some(rule),
            Err(error) => {
                tracing::warn!(%value, %label, %error, "ignoring invalid controller DNS rule");
                None
            }
        })
        .collect()
}

fn parse_dns_hosts(value: Option<&Value>, label: &str) -> Vec<String> {
    string_list(value)
        .into_iter()
        .filter_map(|value| match DomainRule::parse(&format!("^{value}")) {
            Ok(rule) => Some(rule.domain().to_owned()),
            Err(error) => {
                tracing::warn!(%value, %label, %error, "ignoring invalid controller DNS host");
                None
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceBindingStatus {
    Pending,
    Rejected,
    Revoked,
    LimitExceeded,
    CheckFailed,
}

impl DeviceBindingStatus {
    pub const fn code(self) -> i32 {
        match self {
            Self::Pending => 8000,
            Self::Rejected => 8001,
            Self::Revoked => 8002,
            Self::LimitExceeded => 8003,
            Self::CheckFailed => -1,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Rejected => "rejected",
            Self::Revoked => "revoked",
            Self::LimitExceeded => "limitExceeded",
            Self::CheckFailed => "checkFailed",
        }
    }

    const fn from_code(code: i32) -> Option<Self> {
        match code {
            8000 => Some(Self::Pending),
            8001 => Some(Self::Rejected),
            8002 => Some(Self::Revoked),
            8003 => Some(Self::LimitExceeded),
            -1 => Some(Self::CheckFailed),
            _ => None,
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "pending" => Some(Self::Pending),
            "rejected" => Some(Self::Rejected),
            "revoked" => Some(Self::Revoked),
            "limitexceeded" | "limit_exceeded" => Some(Self::LimitExceeded),
            "checkfailed" | "check_failed" => Some(Self::CheckFailed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpFilterConfiguration {
    pub version: String,
    pub updated: bool,
    pub inclusive: Vec<String>,
    pub exclusive: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingMode {
    All,
    IpFilter,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingConfiguration {
    pub mode: RoutingMode,
    pub custom_routes: Vec<String>,
    pub mtu_mode: String,
    pub custom_mtu: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    pub id: String,
    pub name: String,
    pub name_en: String,
    pub server_name: String,
    pub server_port: i32,
    pub is_auto: bool,
    pub ip: Option<String>,
}

impl ServerInfo {
    fn parse(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        let id = json_opt_i32(object.get("id"), -1);
        if id == -1 {
            return None;
        }
        let name = json_opt_string(object.get("name"), "");
        let server_name = json_opt_string(object.get("serverName"), "");
        if name.is_empty() || server_name.is_empty() {
            return None;
        }
        Some(Self {
            id: id.to_string(),
            name,
            name_en: json_opt_string(object.get("name_en"), ""),
            server_name,
            server_port: json_opt_i32(object.get("serverPort"), 8000),
            is_auto: json_opt_bool(object.get("isauto"), false),
            ip: object
                .get("ip")
                .map(|value| json_opt_string(Some(value), ""))
                .filter(|value| !value.is_empty()),
        })
    }

    pub fn endpoint(&self) -> String {
        // `serverName` is the ingress host. The optional `ip` remains
        // controller metadata and does not replace it.
        let host = &self.server_name;
        if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{}", self.server_port)
        } else {
            format!("{host}:{}", self.server_port)
        }
    }
}

fn json_opt_i32(value: Option<&Value>, default: i32) -> i32 {
    let Some(value) = value else {
        return default;
    };
    if let Some(value) = value.as_i64() {
        return i32::try_from(value).unwrap_or(default);
    }
    if let Some(value) = value.as_f64().filter(|value| value.is_finite()) {
        return value as i32;
    }
    value
        .as_str()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite())
        .map_or(default, |value| value as i32)
}

fn json_opt_string(value: Option<&Value>, default: &str) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        _ => default.to_owned(),
    }
}

fn json_opt_bool(value: Option<&Value>, default: bool) -> bool {
    match value {
        Some(Value::Bool(value)) => *value,
        Some(Value::String(value)) if value.eq_ignore_ascii_case("true") => true,
        Some(Value::String(value)) if value.eq_ignore_ascii_case("false") => false,
        _ => default,
    }
}

#[derive(Clone)]
pub struct ServerCredentials {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for ServerCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServerCredentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ServerCredentials {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

pub(crate) fn fetch<T: HttpTransport>(
    config_url: &str,
    transport: &T,
    parameters: ConfigParameters<'_>,
) -> Result<ControllerConfiguration> {
    if parameters.device_id.is_empty() {
        return Err(Error::Managed("device id must not be empty".into()));
    }
    let body = serde_json::to_vec(&ConfigRequest {
        domain: parameters.domain,
        client_type: parameters.client_type,
        oem_name: "panabit",
        app_version: "2.3.0",
        device_id: parameters.device_id,
        username: parameters.username.filter(|value| !value.is_empty()),
        posture_version: parameters.posture_version,
    })
    .map_err(|error| Error::Controller(format!("serialize config request: {error}")))?;
    if parameters.controller_app_id.is_empty() {
        return Err(Error::Controller(
            "config request requires the controller app_id".into(),
        ));
    }
    let url = exact_https_endpoint("config", config_url)?;
    let mut headers = vec![
        ("Content-Type".into(), "application/json".into()),
        ("X-Mobile-Api-Version".into(), "4".into()),
    ];
    headers.extend(security::controller_api_headers(
        "POST",
        &url,
        &body,
        parameters.controller_app_id,
    )?);
    if let Some(access_token) = parameters.access_token {
        headers.push(("Authorization".into(), format!("Bearer {access_token}")));
    }
    let response = transport.execute(HttpRequest {
        method: "POST",
        url,
        headers,
        body,
        timeout: None,
    })?;
    match response.status {
        200 => {
            let raw: Value = serde_json::from_slice(&response.body)
                .map_err(|error| Error::Controller(format!("invalid config response: {error}")))?;
            if !raw.is_object() {
                return Err(Error::Controller(
                    "config response must be a JSON object".into(),
                ));
            }
            Ok(ControllerConfiguration {
                raw,
                credential_app_id: Some(parameters.controller_app_id.to_owned()),
                credential_domain: Some(parameters.domain.to_owned()),
            })
        }
        401 => Err(Error::ControllerUnauthorized),
        status => Err(controller_rejection(status, &response.body)),
    }
}

fn controller_rejection(status: u16, body: &[u8]) -> Error {
    let value = serde_json::from_slice::<Value>(body).unwrap_or(Value::Null);
    let error = value.get("error");
    let code_value = error
        .and_then(|error| error.get("code"))
        .or_else(|| error.filter(|error| error.is_string() || error.is_number()))
        .or_else(|| value.get("code"));
    let code = match code_value {
        Some(Value::String(code)) => code.clone(),
        Some(Value::Number(code)) => code.to_string(),
        _ => "unknown".into(),
    };
    let message = error
        .and_then(|error| {
            error
                .get("message")
                .or_else(|| error.get("detail"))
                .and_then(Value::as_str)
        })
        .or_else(|| value.get("message").and_then(Value::as_str))
        .or_else(|| value.get("detail").and_then(Value::as_str))
        .unwrap_or("controller rejected the request")
        .to_owned();
    Error::ControllerRejected {
        status,
        code,
        message,
    }
}

fn exact_https_endpoint(name: &str, endpoint: &str) -> Result<String> {
    let url = Url::parse(endpoint)
        .map_err(|error| Error::Controller(format!("invalid {name} URL: {error}")))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Controller(format!(
            "{name} URL must be HTTPS without credentials or a fragment"
        )));
    }
    Ok(endpoint.to_owned())
}

/// Nine-field segment-routing entry returned by the controller.
#[derive(Clone, Deserialize)]
pub struct SrEntry {
    pub id: i32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub keepalive: Option<bool>,
    #[serde(default)]
    pub encrypt_algo: String,
    #[serde(default)]
    pub encrypt_key: String,
    #[serde(default = "unknown_status")]
    pub status: String,
    pub ip: String,
    pub ingress: SrIngress,
    pub path: SrPath,
    /// Runtime-only identifier assigned during SR validation.
    #[serde(skip)]
    pub local_sr_id: Option<u32>,
}

impl std::fmt::Debug for SrEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SrEntry")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("keepalive", &self.keepalive)
            .field("encrypt_algo", &self.encrypt_algo)
            .field("encrypt_key", &"[REDACTED]")
            .field("status", &self.status)
            .field("ip", &self.ip)
            .field("ingress", &self.ingress)
            .field("path", &self.path)
            .field("local_sr_id", &self.local_sr_id)
            .finish()
    }
}

impl Drop for SrEntry {
    fn drop(&mut self) {
        self.encrypt_key.zeroize();
    }
}

fn unknown_status() -> String {
    "UNKNOWN".into()
}

#[derive(Clone, Deserialize)]
pub struct SrIngress {
    #[serde(rename = "serverName")]
    pub server_name: String,
    #[serde(rename = "serverPort")]
    pub server_port: i32,
    #[serde(rename = "userName")]
    pub username: String,
    #[serde(rename = "passWord")]
    pub password: String,
    #[serde(default)]
    pub mtu: i32,
}

impl std::fmt::Debug for SrIngress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SrIngress")
            .field("server_name", &self.server_name)
            .field("server_port", &self.server_port)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("mtu", &self.mtu)
            .finish()
    }
}

impl Drop for SrIngress {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SrPath {
    pub links: Vec<i32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SrGroup {
    pub id: i32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub name_en: String,
    #[serde(default)]
    pub primary_index: i32,
    #[serde(rename = "sr", default)]
    pub entries: Vec<SrEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::http::HttpResponse;
    use std::sync::Mutex;

    struct MockTransport {
        request: Mutex<Option<HttpRequest>>,
    }

    impl HttpTransport for MockTransport {
        fn execute(&self, request: HttpRequest) -> Result<HttpResponse> {
            *self.request.lock().unwrap() = Some(request);
            Ok(HttpResponse {
                status: 200,
                body: br#"{"deployment_specific":{"kept":true}}"#.to_vec(),
            })
        }
    }

    #[test]
    fn config_request_matches_protocol_contract() {
        let transport = MockTransport {
            request: Mutex::new(None),
        };
        let configuration = fetch(
            "https://controller.example.test/base/config?tenant=example",
            &transport,
            ConfigParameters {
                domain: "example",
                client_type: "macos",
                controller_app_id: "panabit-controller",
                access_token: Some("access"),
                username: Some("alice"),
                device_id: "device-1",
                posture_version: None,
            },
        )
        .unwrap();
        assert_eq!(configuration.raw()["deployment_specific"]["kept"], true);
        let request = transport.request.lock().unwrap().take().unwrap();
        assert_eq!(
            request.url,
            "https://controller.example.test/base/config?tenant=example"
        );
        assert_eq!(
            request
                .headers
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            [
                "Content-Type",
                "X-Mobile-Api-Version",
                "X-Auth-AppId",
                "X-Auth-Timestamp",
                "X-Auth-Nonce",
                "X-Auth-Sign",
                "Authorization",
            ]
        );
        assert_eq!(
            request
                .headers
                .iter()
                .find(|(name, _)| name == "X-Auth-AppId")
                .map(|(_, value)| value.as_str()),
            Some("panabit-controller")
        );
        assert_eq!(
            request
                .headers
                .iter()
                .find(|(name, _)| name == "Authorization")
                .map(|(_, value)| value.as_str()),
            Some("Bearer access")
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&request.body).unwrap(),
            serde_json::json!({
                "domain": "example",
                "type": "macos",
                "oem_name": "panabit",
                "app_version": "2.3.0",
                "device_id": "device-1",
                "userName": "alice"
            })
        );
    }

    #[test]
    fn decodes_controller_business_error_shape() {
        let error = controller_rejection(
            400,
            br#"{"error":"business_error","message":"invalid client type"}"#,
        );
        assert!(matches!(
            error,
            Error::ControllerRejected {
                status: 400,
                ref code,
                ref message,
            } if code == "business_error" && message == "invalid client type"
        ));
    }

    #[test]
    fn decodes_sr_entry_shape() {
        let entry: SrEntry = serde_json::from_value(serde_json::json!({
            "id": 1,
            "name": "line",
            "keepalive": true,
            "encrypt_algo": "aes128",
            "encrypt_key": "0123456789abcdef",
            "status": "up",
            "ip": "192.0.2.10",
            "ingress": {
                "serverName": "192.0.2.20",
                "serverPort": 6001,
                "userName": "alice",
                "passWord": "secret",
                "mtu": 1400
            },
            "path": {"links": [1, 2, 3]}
        }))
        .unwrap();
        assert_eq!(entry.ingress.server_port, 6001);
        assert_eq!(entry.keepalive, Some(true));
        assert_eq!(entry.path.links, [1, 2, 3]);
        assert_eq!(entry.local_sr_id, None);
        assert!(!format!("{entry:?}").contains("secret"));
    }

    #[test]
    fn sr_entry_defaults_match_wire_schema() {
        let entry: SrEntry = serde_json::from_value(serde_json::json!({
            "id": 1,
            "ip": "192.0.2.10",
            "ingress": {
                "serverName": "host",
                "serverPort": 6001,
                "userName": "user",
                "passWord": "password"
            },
            "path": {"links": [1]}
        }))
        .unwrap();
        assert_eq!(entry.name, "");
        assert_eq!(entry.keepalive, None);
        assert_eq!(entry.encrypt_algo, "");
        assert_eq!(entry.status, "UNKNOWN");
        assert_eq!(entry.ingress.mtu, 0);
    }

    #[test]
    fn parses_serverlist_and_credentials() {
        let encrypted_password = crate::managed::password::encrypt_for_test(
            "controller-example",
            "example.test",
            "entry-user",
            b"entry-password",
        );
        let configuration = ControllerConfiguration {
            raw: serde_json::json!({
                "serverlist": {
                    "version": "1",
                    "serverlist": [{
                        "id": 7,
                        "name": "Line",
                        "name_en": "Line",
                        "serverName": "edge.example",
                        "serverPort": 6001,
                        "isauto": true,
                        "ip": "192.0.2.7",
                        "userName": "entry-user",
                        "passWord": encrypted_password
                    }]
                },
                "dns": {"mode": "manual", "servers": ["10.0.0.53"]}
            }),
            credential_app_id: Some("controller-example".into()),
            credential_domain: Some("example.test".into()),
        };
        let servers = configuration.iwan_servers().unwrap();
        assert_eq!(servers[0].endpoint(), "edge.example:6001");
        assert_eq!(servers[0].ip.as_deref(), Some("192.0.2.7"));
        let credentials = configuration.server_credentials().unwrap();
        assert_eq!(credentials["7"].username, "entry-user");
        assert_eq!(credentials["7"].password, "entry-password");
        assert_eq!(
            configuration.dns_defaults(true).unwrap().server_dns,
            [Ipv4Addr::new(10, 0, 0, 53)]
        );
    }

    #[test]
    fn generated_credentials_require_lookup_decryption_context() {
        let configuration = ControllerConfiguration::from_raw(serde_json::json!({
            "serverlist": [{
                "id": 7,
                "serverName": "edge.example",
                "serverPort": 6001,
                "userName": "entry-user",
                "passWord": "ciphertext"
            }]
        }));
        let error = configuration.server_credentials().unwrap_err();
        assert!(error.to_string().contains("no lookup decryption context"));
    }

    #[test]
    fn generated_credentials_never_fall_back_to_ciphertext() {
        let configuration = ControllerConfiguration {
            raw: serde_json::json!({
                "serverlist": [{
                    "id": 7,
                    "serverName": "edge.example",
                    "serverPort": 6001,
                    "userName": "entry-user",
                    "passWord": "not-standard-base64!"
                }]
            }),
            credential_app_id: Some("controller-example".into()),
            credential_domain: Some("example.test".into()),
        };
        assert!(configuration.server_credentials().is_err());
    }

    #[test]
    fn exact_config_endpoint_is_preserved() {
        assert_eq!(
            exact_https_endpoint(
                "config",
                "https://controller.example.test/prefix/config?tenant=example"
            )
            .unwrap(),
            "https://controller.example.test/prefix/config?tenant=example"
        );
    }

    #[test]
    fn preserves_explicit_zero_server_port_from_controller_parser() {
        let configuration = ControllerConfiguration::from_raw(serde_json::json!({
            "serverlist": [{
                "id": 7,
                "name": "Line",
                "serverName": "edge.example",
                "serverPort": 0
            }]
        }));
        let servers = configuration.iwan_servers().unwrap();
        assert_eq!(servers[0].server_port, 0);
        assert_eq!(servers[0].endpoint(), "edge.example:0");
    }

    #[test]
    fn server_parser_accepts_negative_ids_except_minus_one() {
        let configuration = ControllerConfiguration::from_raw(serde_json::json!({
            "serverlist": [
                {
                    "id": -2,
                    "name": "negative",
                    "serverName": "edge.example",
                    "serverPort": -7
                },
                {
                    "id": -1,
                    "name": "sentinel",
                    "serverName": "ignored.example"
                }
            ]
        }));
        let servers = configuration.iwan_servers().unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].id, "-2");
        assert_eq!(servers[0].server_port, -7);
    }

    #[test]
    fn device_binding_codes_block_login_and_connect() {
        for (raw, expected) in [
            (serde_json::json!(8000), DeviceBindingStatus::Pending),
            (
                serde_json::json!({"code": 8001}),
                DeviceBindingStatus::Rejected,
            ),
            (
                serde_json::json!({"status": "revoked"}),
                DeviceBindingStatus::Revoked,
            ),
            (
                serde_json::json!("limitExceeded"),
                DeviceBindingStatus::LimitExceeded,
            ),
            (serde_json::json!(-1), DeviceBindingStatus::CheckFailed),
        ] {
            let configuration = ControllerConfiguration::from_raw(serde_json::json!({
                "device_binding_status": raw
            }));
            assert_eq!(configuration.device_binding_status(), Some(expected));
            assert!(matches!(
                configuration.enforce_device_binding(),
                Err(Error::DeviceBindingBlocked { .. })
            ));
        }
    }

    #[test]
    fn absent_or_unknown_device_binding_status_is_allowed() {
        ControllerConfiguration::from_raw(serde_json::json!({}))
            .enforce_device_binding()
            .unwrap();
        ControllerConfiguration::from_raw(serde_json::json!({
            "device_binding_status": "approved"
        }))
        .enforce_device_binding()
        .unwrap();
    }

    #[test]
    fn parses_routing_modes_and_custom_routes() {
        let configuration = ControllerConfiguration::from_raw(serde_json::json!({
            "routing": {
                "mode": "custom",
                "custom_routes": "10.0.0.0/8, 192.0.2.0/24"
            }
        }));
        assert_eq!(
            configuration.routing().unwrap().unwrap().custom_routes,
            ["10.0.0.0/8", "192.0.2.0/24"]
        );
        assert_eq!(
            configuration.custom_routes().unwrap(),
            ["10.0.0.0/8", "192.0.2.0/24"]
        );

        let configuration = ControllerConfiguration::from_raw(serde_json::json!({
            "routing": {
                "mode": "ipfilter",
                "custom_routes": "",
                "dns_mode": "custom",
                "custom_dns1": "10.0.0.53",
                "custom_dns2": "10.0.0.54",
                "mtu_mode": "custom",
                "custom_mtu": 1300,
                "split_dns_enabled": true,
                "split_dns_mode": "custom",
                "split_dns_custom_domains": ["example.test"],
                "block_encrypted_dns_override": true,
                "block_encrypted_dns_hosts": ["dns.google"]
            }
        }));
        let routing = configuration.routing().unwrap().unwrap();
        assert_eq!(routing.mode, RoutingMode::IpFilter);
        assert_eq!(routing.custom_mtu, 1300);
        let dns = configuration.dns_defaults(true).unwrap();
        assert_eq!(dns.local_mode, DnsServerMode::Custom);
        assert_eq!(
            dns.local_dns,
            [Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 54)]
        );
        assert_eq!(dns.split_mode, SplitDnsMode::Custom);
        assert_eq!(dns.custom_domains, ["example.test".parse().unwrap()]);
        assert!(dns.block_encrypted_dns);
        assert!(configuration.custom_routes().unwrap().is_empty());
    }

    #[test]
    fn parses_nested_ipfilter_and_ignores_non_string_rules() {
        let configuration = ControllerConfiguration::from_raw(serde_json::json!({
            "ipfilter": {
                "version": "v7",
                "ipfilter": {
                    "updated": false,
                    "inclusive": ["10.0.0.0/8", "", 42],
                    "exclusive": ["10.1.0.0/16"]
                }
            }
        }));
        assert_eq!(
            configuration.ip_filter().unwrap(),
            Some(IpFilterConfiguration {
                version: "v7".into(),
                updated: false,
                inclusive: vec!["10.0.0.0/8".into()],
                exclusive: vec!["10.1.0.0/16".into()]
            })
        );
    }

    #[test]
    fn parses_domain_filter_shape() {
        let configuration = ControllerConfiguration::from_raw(serde_json::json!({
            "domainfilter": {
                "version": "v3",
                "mode": "domain_filter",
                "inclusive": ["corp.example"],
                "exclusive": ["public.example"],
                "drop_secure_dns": true,
                "secure_dns_hosts": ["dns.google"]
            }
        }));
        let dns = configuration.dns_defaults(true).unwrap();
        assert!(dns.managed_domain_filter);
        assert_eq!(dns.managed_inclusive, ["corp.example".parse().unwrap()]);
        assert_eq!(dns.managed_exclusive, ["public.example".parse().unwrap()]);
        assert!(dns.block_encrypted_dns);
        assert_eq!(dns.secure_dns_hosts, ["dns.google"]);
    }

    #[test]
    fn preserves_numeric_device_binding_rejection_codes() {
        let error = controller_rejection(
            403,
            br#"{"error":{"code":8002,"message":"binding revoked"}}"#,
        );
        assert!(matches!(
            error,
            Error::ControllerRejected {
                status: 403,
                ref code,
                ref message
            } if code == "8002" && message == "binding revoked"
        ));
    }

    #[test]
    fn rejects_mixed_iwan_and_sr_payload() {
        let configuration = ControllerConfiguration {
            raw: serde_json::json!({"serverlist": [], "sites": []}),
            credential_app_id: None,
            credential_domain: None,
        };
        assert!(configuration.iwan_servers().is_err());
    }

    #[test]
    fn parses_sr_group_shape() {
        let encrypted_password = crate::managed::password::encrypt_for_test(
            "controller-example",
            "example.test",
            "u",
            b"p",
        );
        let configuration = ControllerConfiguration {
            raw: serde_json::json!({
                "sites": [{
                    "id": 5,
                    "name": "site",
                    "name_en": "site",
                    "primary_index": 0,
                    "sr": [{
                        "id": 1,
                        "ip": "192.0.2.1",
                        "ingress": {
                            "serverName": "edge.example",
                            "serverPort": 6001,
                            "userName": "u",
                            "passWord": encrypted_password
                        },
                        "path": {"links": [1]}
                    }]
                }]
            }),
            credential_app_id: Some("controller-example".into()),
            credential_domain: Some("example.test".into()),
        };
        let groups = configuration.sr_groups().unwrap();
        assert_eq!(groups[0].entries[0].ingress.username, "u");
        assert_eq!(groups[0].entries[0].ingress.password, "p");
    }
}
