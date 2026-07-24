use super::http::{HttpRequest, HttpTransport};
use super::oidc::OidcIdentity;
use super::provider::ProviderConfig;
use super::store::{ManagedServer, ManagedState, STATE_VERSION};
use crate::{Error, Result};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Serialize)]
struct DeviceRequest<'a> {
    domain: &'a str,
    #[serde(rename = "type")]
    device_type: &'a str,
    oem_name: &'a str,
    device_id: &'a str,
    #[serde(rename = "userName")]
    username: &'a str,
    serverlist_version: &'static str,
    ipfilter_version: &'static str,
    branding_version: &'static str,
}

#[derive(Deserialize)]
struct ConfigResponse {
    serverlist: ServerList,
}

#[derive(Deserialize)]
struct ServerList {
    serverlist: Vec<WireServer>,
}

#[derive(Deserialize)]
struct WireServer {
    name: String,
    #[serde(rename = "serverName")]
    host: String,
    #[serde(rename = "serverPort", deserialize_with = "deserialize_port")]
    port: u16,
    #[serde(rename = "userName")]
    username: String,
    #[serde(rename = "passWord")]
    encrypted_password: String,
}

pub(crate) fn fetch<T: HttpTransport>(
    provider: &ProviderConfig,
    transport: &T,
    identity: &OidcIdentity,
    device_id: &str,
) -> Result<ManagedState> {
    let request = DeviceRequest {
        domain: &provider.controller.domain,
        device_type: &provider.controller.device_type,
        oem_name: &provider.controller.oem_name,
        device_id,
        username: &identity.username,
        serverlist_version: "0",
        ipfilter_version: "0",
        branding_version: "0",
    };
    let auth_response = signed_post(
        provider,
        transport,
        &provider.controller.auth_path,
        &request,
        &identity.access_token,
    )?;
    require_ok("auth", auth_response.status)?;

    let keepalive = DeviceRequest {
        device_type: "keepalive",
        ..request.clone()
    };
    let keepalive_response = signed_post(
        provider,
        transport,
        &provider.controller.keepalive_path,
        &keepalive,
        &identity.access_token,
    )?;
    if keepalive_response.status != 200 {
        tracing::warn!(
            status = keepalive_response.status,
            "controller keepalive returned a non-success status"
        );
    }

    let response = signed_post(
        provider,
        transport,
        &provider.controller.config_path,
        &request,
        &identity.access_token,
    )?;
    require_ok("config", response.status)?;
    let response: ConfigResponse = serde_json::from_slice(&response.body)
        .map_err(|error| Error::Controller(format!("invalid config response: {error}")))?;
    let mut servers = Vec::with_capacity(response.serverlist.serverlist.len());
    for server in response.serverlist.serverlist {
        if server.name.trim().is_empty()
            || server.host.trim().is_empty()
            || server.port == 0
            || server.username.trim().is_empty()
            || server.encrypted_password.is_empty()
        {
            return Err(Error::Controller(
                "controller returned an incomplete line".into(),
            ));
        }
        servers.push(ManagedServer {
            name: server.name,
            host: server.host,
            port: server.port,
            username: server.username,
            encrypted_password: server.encrypted_password,
        });
    }
    if servers.is_empty() {
        return Err(Error::Controller(
            "controller returned no available lines".into(),
        ));
    }
    let fetched_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Controller("system clock is before the Unix epoch".into()))?
        .as_secs();
    Ok(ManagedState {
        version: STATE_VERSION,
        provider_id: provider.id.clone(),
        domain: provider.controller.domain.clone(),
        device_id: device_id.into(),
        fetched_at_unix,
        servers,
    })
}

fn signed_post<T: HttpTransport, B: Serialize>(
    provider: &ProviderConfig,
    transport: &T,
    path: &str,
    body: &B,
    access_token: &str,
) -> Result<super::http::HttpResponse> {
    let body = serde_json::to_vec(body)
        .map_err(|error| Error::Controller(format!("serialize request: {error}")))?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Controller("system clock is before the Unix epoch".into()))?
        .as_secs()
        .to_string();
    let nonce = random_nonce();
    let body_hash = hex_lower(&Sha256::digest(&body));
    let canonical = format!("POST\n{path}\n\n{body_hash}\n{timestamp}\n{nonce}");
    let mut mac = HmacSha256::new_from_slice(provider.controller.app_secret.as_bytes())
        .map_err(|_| Error::Crypto("invalid controller HMAC key"))?;
    mac.update(canonical.as_bytes());
    let signature = hex_lower(&mac.finalize().into_bytes());
    let base = Url::parse(&provider.controller.base_url)
        .map_err(|error| Error::Controller(format!("invalid controller URL: {error}")))?;
    let url = base
        .join(path)
        .map_err(|error| Error::Controller(format!("invalid controller path: {error}")))?;

    transport.execute(HttpRequest {
        method: "POST",
        url: url.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), format!("Bearer {access_token}")),
            ("X-Auth-AppId".into(), provider.controller.app_id.clone()),
            ("X-Auth-Timestamp".into(), timestamp),
            ("X-Auth-Nonce".into(), nonce),
            ("X-Auth-Sign".into(), signature),
        ],
        body,
    })
}

fn require_ok(operation: &str, status: u16) -> Result<()> {
    if status == 200 {
        Ok(())
    } else {
        Err(Error::Controller(format!(
            "{operation} returned HTTP {status}"
        )))
    }
}

fn random_nonce() -> String {
    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02X}");
    }
    output
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn deserialize_port<'de, D>(deserializer: D) -> std::result::Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Number(number) => number
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
            .ok_or_else(|| serde::de::Error::custom("invalid server port")),
        serde_json::Value::String(port) => port
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| serde::de::Error::custom("invalid server port")),
        _ => Err(serde::de::Error::custom("invalid server port")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::http::{HttpResponse, HttpTransport};
    use crate::managed::provider::{
        ControllerConfig, OidcConfig, PROVIDER_VERSION, TokenRequestFormat,
    };
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    #[derive(Default)]
    struct MockTransport {
        requests: Mutex<Vec<HttpRequest>>,
        responses: Mutex<VecDeque<HttpResponse>>,
    }

    impl HttpTransport for MockTransport {
        fn execute(&self, request: HttpRequest) -> Result<HttpResponse> {
            self.requests.lock().unwrap().push(request);
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| Error::Http("missing mock response".into()))
        }
    }

    fn provider() -> ProviderConfig {
        ProviderConfig {
            version: PROVIDER_VERSION,
            id: "example".into(),
            display_name: "Example".into(),
            dns_servers: Vec::new(),
            require_auth_verify_echo: false,
            xor_key_bytes: 16,
            oidc: OidcConfig {
                issuer: "https://auth.example.test".into(),
                client_id: "client".into(),
                redirect_uri: "com.example://callback".into(),
                scopes: vec!["openid".into()],
                username_claims: vec!["sub".into()],
                token_request_format: TokenRequestFormat::Json,
            },
            controller: ControllerConfig {
                base_url: "https://controller.example.test".into(),
                domain: "iwan.example".into(),
                app_id: "controller-example".into(),
                app_secret: "app-secret".into(),
                auth_path: "/m/auth".into(),
                keepalive_path: "/m/keepalive".into(),
                config_path: "/m/config".into(),
                device_type: "android".into(),
                oem_name: "panabit".into(),
            },
        }
    }

    #[test]
    fn fetches_typed_lines_with_signed_requests() {
        let transport = MockTransport::default();
        let mut responses = transport.responses.lock().unwrap();
        responses.push_back(HttpResponse {
            status: 200,
            body: b"{}".to_vec(),
        });
        responses.push_back(HttpResponse {
            status: 204,
            body: Vec::new(),
        });
        responses.push_back(HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "serverlist": {
                    "serverlist": [{
                        "name": "Education",
                        "serverName": "192.0.2.10",
                        "serverPort": "6001",
                        "userName": "line-user",
                        "passWord": "encrypted"
                    }]
                }
            }))
            .unwrap(),
        });
        drop(responses);

        let provider = provider();
        let identity = OidcIdentity {
            access_token: Zeroizing::new("access-token".into()),
            username: "alice".into(),
        };
        let state = fetch(&provider, &transport, &identity, "0011223344556677").unwrap();
        assert_eq!(state.provider_id, "example");
        assert_eq!(state.servers[0].port, 6001);

        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        for request in requests.iter() {
            assert!(
                request
                    .headers
                    .iter()
                    .any(|(name, value)| name == "Authorization" && value == "Bearer access-token")
            );
            assert!(
                request
                    .headers
                    .iter()
                    .any(|(name, value)| name == "X-Auth-Sign" && value.len() == 64)
            );
            let timestamp = header(request, "X-Auth-Timestamp");
            let nonce = header(request, "X-Auth-Nonce");
            let body_hash = hex_lower(&Sha256::digest(&request.body));
            let path = Url::parse(&request.url).unwrap().path().to_owned();
            let canonical = format!("POST\n{path}\n\n{body_hash}\n{timestamp}\n{nonce}");
            let mut mac = HmacSha256::new_from_slice(b"app-secret").unwrap();
            mac.update(canonical.as_bytes());
            assert_eq!(
                header(request, "X-Auth-Sign"),
                hex_lower(&mac.finalize().into_bytes())
            );
        }
        assert!(String::from_utf8_lossy(&requests[1].body).contains("\"type\":\"keepalive\""));
    }

    fn header<'a>(request: &'a HttpRequest, name: &str) -> &'a str {
        request
            .headers
            .iter()
            .find_map(|(candidate, value)| (candidate == name).then_some(value.as_str()))
            .unwrap()
    }
}
