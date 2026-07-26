use super::http::{HttpRequest, HttpTransport};
use super::provider::ProviderConfig;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
    service_type: &'a str,
    oem_name: &'static str,
    app_version: &'static str,
    device_id: &'a str,
    #[serde(rename = "userName", skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    posture_version: Option<&'a str>,
}

/// Dynamically decoded `/config` response.
///
/// The Android/Flutter artifacts do not retain one authoritative aggregate
/// response schema, so callers must interpret deployment-specific members.
#[derive(Debug, Clone)]
pub struct ControllerConfiguration {
    raw: Value,
}

impl ControllerConfiguration {
    pub const fn raw(&self) -> &Value {
        &self.raw
    }

    pub fn into_raw(self) -> Value {
        self.raw
    }
}

pub(crate) fn fetch<T: HttpTransport>(
    provider: &ProviderConfig,
    transport: &T,
    access_token: Option<&str>,
    username: Option<&str>,
    device_id: &str,
    posture_version: Option<&str>,
) -> Result<ControllerConfiguration> {
    if device_id.is_empty() {
        return Err(Error::ManagedProvider("device id must not be empty".into()));
    }
    let body = serde_json::to_vec(&ConfigRequest {
        domain: &provider.controller.domain,
        service_type: &provider.controller.service_type,
        oem_name: "panabit",
        app_version: "2.3.0",
        device_id,
        username: username.filter(|value| !value.is_empty()),
        posture_version,
    })
    .map_err(|error| Error::Controller(format!("serialize config request: {error}")))?;
    let mut headers = vec![
        ("Content-Type".into(), "application/json".into()),
        ("X-Mobile-Api-Version".into(), "4".into()),
    ];
    if let Some(access_token) = access_token {
        headers.push(("Authorization".into(), format!("Bearer {access_token}")));
    }
    let response = transport.execute(HttpRequest {
        method: "POST",
        url: endpoint(&provider.controller.base_url, CONFIG_PATH)?,
        headers,
        body,
    })?;
    match response.status {
        200 => {
            let raw = serde_json::from_slice(&response.body)
                .map_err(|error| Error::Controller(format!("invalid config response: {error}")))?;
            Ok(ControllerConfiguration { raw })
        }
        401 => Err(Error::ControllerUnauthorized),
        status => Err(Error::Controller(format!("config returned HTTP {status}"))),
    }
}

fn endpoint(base_url: &str, path: &str) -> Result<String> {
    let base = Url::parse(base_url)
        .map_err(|error| Error::Controller(format!("invalid controller URL: {error}")))?;
    base.join(path)
        .map(String::from)
        .map_err(|error| Error::Controller(format!("invalid controller path: {error}")))
}

/// Confirmed nine-field Android `SREntry` serializer.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::http::HttpResponse;
    use crate::managed::provider::{ControllerConfig, OidcConfig};
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

    fn provider() -> ProviderConfig {
        ProviderConfig {
            oidc: Some(OidcConfig {
                issuer: "https://auth.example.test".into(),
                client_id: "client".into(),
                redirect_uri: "app://callback".into(),
                scopes: vec!["openid".into()],
                username_claim: "sub".into(),
                organization: "example".into(),
                provider: "oidc".into(),
            }),
            controller: ControllerConfig {
                base_url: "https://controller.example.test/base/".into(),
                domain: "example".into(),
                service_type: "device".into(),
            },
        }
    }

    #[test]
    fn config_request_matches_confirmed_aot_contract() {
        let transport = MockTransport {
            request: Mutex::new(None),
        };
        let configuration = fetch(
            &provider(),
            &transport,
            Some("access"),
            Some("alice"),
            "device-1",
            None,
        )
        .unwrap();
        assert_eq!(configuration.raw()["deployment_specific"]["kept"], true);
        let request = transport.request.lock().unwrap().take().unwrap();
        assert_eq!(request.url, "https://controller.example.test/config");
        assert_eq!(
            request.headers,
            [
                ("Content-Type".into(), "application/json".into()),
                ("X-Mobile-Api-Version".into(), "4".into()),
                ("Authorization".into(), "Bearer access".into()),
            ]
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&request.body).unwrap(),
            serde_json::json!({
                "domain": "example",
                "type": "device",
                "oem_name": "panabit",
                "app_version": "2.3.0",
                "device_id": "device-1",
                "userName": "alice"
            })
        );
    }

    #[test]
    fn decodes_confirmed_sr_entry_shape() {
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
        assert!(!format!("{entry:?}").contains("secret"));
    }

    #[test]
    fn sr_entry_defaults_match_android_serializer() {
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
}
