use super::http::{HttpRequest, HttpResponse, HttpTransport};
use crate::{Error, Result};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct KeepaliveCredentials {
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
    pub app_id: String,
    pub app_secret: Zeroizing<String>,
    pub device_id: String,
}

impl std::fmt::Debug for KeepaliveCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeepaliveCredentials")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("app_id", &self.app_id)
            .field("app_secret", &"[REDACTED]")
            .field("device_id", &self.device_id)
            .finish()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeepaliveRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oem_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serverlist_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_metrics: Option<PathMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_metrics_ts: Option<PathMetricsTs>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathMetrics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iwan: Option<IwanMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sr: Option<SrMetrics>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IwanMetrics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<IwanActive>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servers: Option<Vec<IwanServerMetric>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct IwanActive {
    pub server_id: i32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct IwanServerMetric {
    pub server_id: i32,
    pub latency_ms: i32,
    #[serde(default)]
    pub latency_us: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SrMetrics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<SrActive>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sites: Option<Vec<SrSiteMetric>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SrActive {
    pub group_id: i32,
    pub sr_id: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrSiteMetric {
    pub id: i32,
    pub sr: Vec<SrPathMetric>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrPathMetric {
    pub id: i32,
    pub latency_ms: i32,
    #[serde(default)]
    pub latency_us: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_path: Option<SrFullPathMetric>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SrFullPathMetric {
    pub rtt_ms: i32,
    #[serde(default)]
    pub rtt_us: i32,
    pub loss_pct: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathMetricsTs {
    pub sample_ts_ms: Vec<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iwan: Option<IwanMetricsTs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sr: Option<SrMetricsTs>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IwanMetricsTs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<IwanActive>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servers: Option<Vec<IwanServerMetricTs>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IwanServerMetricTs {
    pub server_id: i32,
    pub latency_us: Vec<Option<i32>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SrMetricsTs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<SrActive>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sites: Option<Vec<SrSiteMetricTs>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrSiteMetricTs {
    pub id: i32,
    pub sr: Vec<SrPathMetricTs>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrPathMetricTs {
    pub id: i32,
    pub latency_us: Vec<Option<i32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_path: Option<SrFullPathMetricTs>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrFullPathMetricTs {
    pub rtt_us: Vec<Option<i32>>,
    pub loss_pct: Vec<Option<i32>>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct KeepaliveResponse {
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub posture_ack: Option<PostureAck>,
    #[serde(default)]
    pub posture: Option<PostureUpdate>,
    #[serde(default)]
    pub device_binding: Option<DeviceBinding>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PostureAck {
    pub status: String,
    pub user_notice: UserNotice,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserNotice {
    pub reason_codes: Vec<Value>,
    pub title: String,
    pub message: String,
    pub title_en: String,
    pub message_en: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PostureUpdate {
    pub version: String,
    pub updated: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceBinding {
    pub action: String,
    #[serde(default)]
    pub reason: Option<String>,
}

use serde_json::Value;

pub fn send<T: HttpTransport>(
    transport: &T,
    endpoint: &str,
    credentials: &KeepaliveCredentials,
    request: &KeepaliveRequest,
) -> Result<KeepaliveResponse> {
    let body = serde_json::to_vec(request)
        .map_err(|error| Error::Controller(format!("serialize keepalive request: {error}")))?;
    let mut last_error = None;
    for _ in 0..2 {
        let response = match execute_once(transport, endpoint, credentials, &body) {
            Ok(response) => response,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        match response.status {
            200 => match serde_json::from_slice(&response.body) {
                Ok(response) => return Ok(response),
                Err(error) => {
                    last_error = Some(Error::Controller(format!(
                        "invalid keepalive response: {error}"
                    )));
                }
            },
            401 => return Err(Error::ControllerUnauthorized),
            status => {
                last_error = Some(Error::Controller(format!(
                    "keepalive returned HTTP {status}"
                )));
            }
        }
    }
    Err(last_error.expect("two keepalive attempts always produce an error"))
}

fn execute_once<T: HttpTransport>(
    transport: &T,
    endpoint: &str,
    credentials: &KeepaliveCredentials,
    body: &[u8],
) -> Result<HttpResponse> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Controller("system clock is before the Unix epoch".into()))?
        .as_secs()
        .to_string();
    let nonce = random_nonce();
    let signature = sign_request(
        endpoint,
        body,
        &timestamp,
        &nonce,
        credentials.app_secret.as_bytes(),
    )?;
    transport.execute(HttpRequest {
        method: "POST",
        url: endpoint.to_owned(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("X-Mobile-Api-Version".into(), "3".into()),
            (
                "Authorization".into(),
                format!("Bearer {}", credentials.access_token.as_str()),
            ),
            ("X-Auth-AppId".into(), credentials.app_id.clone()),
            ("X-Auth-Timestamp".into(), timestamp),
            ("X-Auth-Nonce".into(), nonce),
            ("X-Auth-Sign".into(), signature),
        ],
        body: body.to_vec(),
    })
}

fn random_nonce() -> String {
    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex_lower(&bytes)
}

pub fn sign_request(
    endpoint: &str,
    exact_body: &[u8],
    timestamp: &str,
    nonce: &str,
    app_secret: &[u8],
) -> Result<String> {
    let canonical = canonical_request(endpoint, exact_body, timestamp, nonce)?;
    let mut mac = HmacSha256::new_from_slice(app_secret)
        .map_err(|_| Error::Crypto("invalid keepalive HMAC key"))?;
    mac.update(canonical.as_bytes());
    Ok(hex_lower(&mac.finalize().into_bytes()))
}

pub fn canonical_request(
    endpoint: &str,
    exact_body: &[u8],
    timestamp: &str,
    nonce: &str,
) -> Result<String> {
    let url = Url::parse(endpoint)
        .map_err(|error| Error::Controller(format!("invalid keepalive URL: {error}")))?;
    let path = decode_component(url.path(), false);
    let path = if path.is_empty() { "/" } else { &path };
    let mut query = BTreeMap::new();
    if let Some(raw_query) = url.query() {
        for pair in raw_query.split('&') {
            let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
            let name = decode_component(raw_name, true);
            let value = decode_component(raw_value, true);
            query.entry(name).or_insert(value);
        }
    }
    let canonical_query = query
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    Ok(format!(
        "POST\n{path}\n{canonical_query}\n{}\n{timestamp}\n{nonce}",
        hex_lower(&Sha256::digest(exact_body))
    ))
}

fn decode_component(value: &str, plus_as_space: bool) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut offset = 0;
    while offset < bytes.len() {
        match bytes[offset] {
            b'+' if plus_as_space => {
                decoded.push(b' ');
                offset += 1;
            }
            b'%' => {
                if offset + 2 >= bytes.len() {
                    return value.to_owned();
                }
                let Some(high) = hex_value(bytes[offset + 1]) else {
                    return value.to_owned();
                };
                let Some(low) = hex_value(bytes[offset + 2]) else {
                    return value.to_owned();
                };
                decoded.push((high << 4) | low);
                offset += 3;
            }
            byte => {
                decoded.push(byte);
                offset += 1;
            }
        }
    }
    String::from_utf8(decoded).unwrap_or_else(|_| value.to_owned())
}

const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::http::HttpResponse;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn matches_recovered_hmac_vector() {
        let endpoint = "https://controller.example/keepalive?b=two&a=one%20x&a=ignored&plus=a+b";
        let canonical = canonical_request(
            endpoint,
            br#"{"x":1}"#,
            "1700000000",
            "000102030405060708090a0b0c0d0e0f",
        )
        .unwrap();
        assert_eq!(
            canonical,
            "POST\n/keepalive\na=one x&b=two&plus=a b\n\
             5041bf1f713df204784353e82f6a4a535931cb64f1f4b4a5aeaffcb720918b22\n\
             1700000000\n000102030405060708090a0b0c0d0e0f"
        );
        assert_eq!(
            sign_request(
                endpoint,
                br#"{"x":1}"#,
                "1700000000",
                "000102030405060708090a0b0c0d0e0f",
                b"test-secret",
            )
            .unwrap(),
            "33c627d0d8fdfe78b4e57d2ca1113628647d9c1e71d8b6c03f2e958733f1aa79"
        );
    }

    #[test]
    fn path_metric_timestamp_requires_sample_array() {
        assert!(serde_json::from_str::<PathMetricsTs>(r#"{"iwan":{}}"#).is_err());
    }

    struct RetryTransport {
        calls: AtomicUsize,
        requests: Mutex<Vec<HttpRequest>>,
    }

    impl HttpTransport for RetryTransport {
        fn execute(&self, request: HttpRequest) -> Result<HttpResponse> {
            self.requests.lock().unwrap().push(request);
            if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
                Err(Error::Http("first transport failure".into()))
            } else {
                Ok(HttpResponse {
                    status: 200,
                    body: b"{}".to_vec(),
                })
            }
        }
    }

    #[test]
    fn retries_one_transport_failure_with_fresh_auth_headers() {
        let transport = RetryTransport {
            calls: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
        };
        let credentials = KeepaliveCredentials {
            access_token: Zeroizing::new("access".into()),
            refresh_token: Zeroizing::new("refresh".into()),
            app_id: "app".into(),
            app_secret: Zeroizing::new("secret".into()),
            device_id: "device".into(),
        };
        let request = KeepaliveRequest {
            domain: Some("example".into()),
            service_type: Some("device".into()),
            oem_name: Some("panabit".into()),
            device_id: Some("device".into()),
            ..KeepaliveRequest::default()
        };
        send(
            &transport,
            "https://controller.example/keepalive",
            &credentials,
            &request,
        )
        .unwrap();
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].body, requests[1].body);
        assert!(
            requests[0]
                .headers
                .iter()
                .any(|header| header == &("X-Mobile-Api-Version".into(), "3".into()))
        );
        let nonce = header_value(&requests[0], "X-Auth-Nonce").as_bytes();
        assert_eq!(nonce.len(), 32);
        assert!(
            nonce
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        );
        assert_ne!(
            header_value(&requests[0], "X-Auth-Nonce"),
            header_value(&requests[1], "X-Auth-Nonce")
        );
        assert_ne!(
            header_value(&requests[0], "X-Auth-Sign"),
            header_value(&requests[1], "X-Auth-Sign")
        );
    }

    struct StatusTransport {
        calls: AtomicUsize,
        statuses: Mutex<VecDeque<u16>>,
    }

    impl HttpTransport for StatusTransport {
        fn execute(&self, _request: HttpRequest) -> Result<HttpResponse> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(HttpResponse {
                status: self.statuses.lock().unwrap().pop_front().unwrap(),
                body: b"{}".to_vec(),
            })
        }
    }

    #[test]
    fn retries_one_non_success_status() {
        let transport = StatusTransport {
            calls: AtomicUsize::new(0),
            statuses: Mutex::new(VecDeque::from([500, 200])),
        };
        send(
            &transport,
            "https://controller.example/keepalive",
            &test_credentials(),
            &KeepaliveRequest::default(),
        )
        .unwrap();
        assert_eq!(transport.calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn does_not_retry_unauthorized() {
        let transport = StatusTransport {
            calls: AtomicUsize::new(0),
            statuses: Mutex::new(VecDeque::from([401, 200])),
        };
        let error = send(
            &transport,
            "https://controller.example/keepalive",
            &test_credentials(),
            &KeepaliveRequest::default(),
        )
        .unwrap_err();
        assert!(matches!(error, Error::ControllerUnauthorized));
        assert_eq!(transport.calls.load(Ordering::Relaxed), 1);
    }

    fn header_value<'a>(request: &'a HttpRequest, name: &str) -> &'a str {
        request
            .headers
            .iter()
            .find(|(header_name, _)| header_name == name)
            .unwrap()
            .1
            .as_str()
    }

    fn test_credentials() -> KeepaliveCredentials {
        KeepaliveCredentials {
            access_token: Zeroizing::new("access".into()),
            refresh_token: Zeroizing::new("refresh".into()),
            app_id: "app".into(),
            app_secret: Zeroizing::new("secret".into()),
            device_id: "device".into(),
        }
    }
}
