use super::http::{HttpRequest, HttpTransport};
use super::security;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

pub const LOOKUP_PRIMARY: &str = "https://lookup.gsase.com/lookup";
pub const LOOKUP_FALLBACK: &str = "https://lookupbak.hypersase.com/lookup";
pub const LOOKUP_CACHE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
pub const LOOKUP_ATTEMPTS_PER_SERVER: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupSource {
    Network,
    Cache,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceType {
    ServerList,
    Saas,
    Controller,
}

impl ServiceType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServerList => "serverlist",
            Self::Saas => "saas",
            Self::Controller => "controller",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "serverlist" => Ok(Self::ServerList),
            "saas" => Ok(Self::Saas),
            "controller" => Ok(Self::Controller),
            _ => Err(Error::Managed(format!(
                "unsupported lookup service type {value:?}"
            ))),
        }
    }
}

#[derive(Clone)]
pub struct LookupResult {
    pub complete_domain: String,
    pub original_domain: String,
    pub is_fuzzy_match: bool,
    pub service_type: ServiceType,
    pub server_list_url: Option<String>,
    pub saas_info: Option<Value>,
    pub controller_info: Option<Value>,
    pub source: LookupSource,
    pub(crate) raw: Value,
}

impl std::fmt::Debug for LookupResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LookupResult")
            .field("complete_domain", &self.complete_domain)
            .field("original_domain", &self.original_domain)
            .field("is_fuzzy_match", &self.is_fuzzy_match)
            .field("service_type", &self.service_type)
            .field("server_list_url", &self.server_list_url)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl LookupResult {
    pub const fn raw(&self) -> &Value {
        &self.raw
    }

    pub fn active_domain(&self) -> &str {
        if self.is_fuzzy_match && !self.complete_domain.is_empty() {
            &self.complete_domain
        } else {
            &self.original_domain
        }
    }

    pub fn auth_url(&self) -> Option<&str> {
        self.controller_endpoint("auth")
    }

    pub fn config_url(&self) -> Option<&str> {
        self.controller_endpoint("config")
    }

    pub fn resolved_server_list_url(&self) -> Option<&str> {
        self.controller_endpoint("serverlist")
            .or(self.server_list_url.as_deref())
    }

    pub fn controller_app_id(&self) -> Option<&str> {
        self.controller_info
            .as_ref()
            .and_then(|info| object_string(info, &["app_id"]))
    }

    fn controller_endpoint(&self, name: &str) -> Option<&str> {
        self.controller_info
            .as_ref()?
            .get("url")?
            .as_object()?
            .get(name)?
            .as_str()
            .filter(|value| !value.is_empty())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    #[serde(rename = "cachedAt")]
    cached_at_ms: u64,
    response: Value,
}

#[derive(Debug, Clone)]
pub struct LookupCache {
    directory: PathBuf,
}

impl LookupCache {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn read(&self, domain: &str, now: SystemTime) -> Result<Option<Value>> {
        let path = self.path(domain);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let entry: CacheEntry = serde_json::from_slice(&bytes).map_err(|error| {
            Error::Managed(format!("invalid lookup cache {}: {error}", path.display()))
        })?;
        let now_ms = epoch_millis(now)?;
        if now_ms.saturating_sub(entry.cached_at_ms) > LOOKUP_CACHE_TTL.as_millis() as u64 {
            return Ok(None);
        }
        Ok(Some(entry.response))
    }

    fn write(&self, domain: &str, response: &Value, now: SystemTime) -> Result<()> {
        fs::create_dir_all(&self.directory)?;
        let path = self.path(domain);
        let temporary = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec(&CacheEntry {
            cached_at_ms: epoch_millis(now)?,
            response: response.clone(),
        })
        .map_err(|error| Error::Managed(format!("serialize lookup cache: {error}")))?;
        fs::write(&temporary, bytes)?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    fn path(&self, domain: &str) -> PathBuf {
        self.directory.join(format!("lookup_cache_{domain}.json"))
    }
}

pub struct LookupClient<T> {
    transport: T,
    cache: Option<LookupCache>,
    endpoints: Vec<String>,
}

impl<T: HttpTransport> LookupClient<T> {
    pub fn with_transport(transport: T) -> Self {
        Self {
            transport,
            cache: None,
            endpoints: vec![LOOKUP_PRIMARY.into(), LOOKUP_FALLBACK.into()],
        }
    }

    pub fn with_cache(mut self, directory: impl Into<PathBuf>) -> Self {
        self.cache = Some(LookupCache::new(directory));
        self
    }

    pub(crate) const fn transport(&self) -> &T {
        &self.transport
    }

    #[cfg(test)]
    fn with_endpoints(mut self, endpoints: Vec<String>) -> Self {
        self.endpoints = endpoints;
        self
    }

    pub fn lookup(&self, domain: &str, device_id: &str) -> Result<LookupResult> {
        self.lookup_at(domain, device_id, SystemTime::now())
    }

    fn lookup_at(&self, domain: &str, device_id: &str, now: SystemTime) -> Result<LookupResult> {
        validate_domain(domain)?;
        if device_id.trim().is_empty() {
            return Err(Error::Managed("device id must not be empty".into()));
        }

        let live = self.lookup_live(domain, device_id);
        match live {
            Ok((raw, result)) => {
                if let Some(cache) = &self.cache {
                    // Cache failures do not invalidate a successful lookup.
                    let _ = cache.write(domain, &raw, now);
                    if result.active_domain() != domain {
                        let _ = cache.write(result.active_domain(), &raw, now);
                    }
                }
                Ok(result)
            }
            Err(live_error) => {
                if let Some(cache) = &self.cache
                    && let Ok(Some(raw)) = cache.read(domain, now)
                    && let Ok(result) = parse_response(domain, raw, LookupSource::Cache)
                {
                    return Ok(result);
                }
                Err(live_error)
            }
        }
    }

    fn lookup_live(&self, domain: &str, device_id: &str) -> Result<(Value, LookupResult)> {
        let body = serde_json::to_vec(&serde_json::json!({
            "domain": domain,
            "serviceType": "fgb",
            "device_id": device_id,
            "oem_name": "panabit",
            "app_version": "2.3.0"
        }))
        .map_err(|error| Error::Managed(format!("serialize lookup request: {error}")))?;
        let mut last_error = None;
        for endpoint in &self.endpoints {
            validate_lookup_endpoint(endpoint)?;
            for _ in 0..LOOKUP_ATTEMPTS_PER_SERVER {
                let mut headers = vec![
                    ("Content-Type".into(), "application/json".into()),
                    ("X-Mobile-Api-Version".into(), "4".into()),
                ];
                headers.extend(security::mobile_api_headers("POST", endpoint, &body)?);
                match self.transport.execute(HttpRequest {
                    method: "POST",
                    url: endpoint.clone(),
                    headers,
                    body: body.clone(),
                    timeout: None,
                }) {
                    Ok(response) if response.status == 200 => {
                        let parsed = serde_json::from_slice(&response.body)
                            .map_err(|error| {
                                Error::Managed(format!("invalid lookup response: {error}"))
                            })
                            .and_then(response_data)
                            .and_then(|raw| {
                                parse_response(domain, raw.clone(), LookupSource::Network)
                                    .map(|result| (raw, result))
                            });
                        match parsed {
                            Ok(result) => return Ok(result),
                            Err(error) => last_error = Some(error),
                        }
                    }
                    Ok(response) => {
                        last_error = Some(Error::Managed(format!(
                            "lookup returned HTTP {}",
                            response.status
                        )));
                    }
                    Err(error) => last_error = Some(error),
                }
            }
        }
        Err(last_error.unwrap_or_else(|| Error::Managed("all lookup servers failed".into())))
    }
}

pub fn validate_domain(domain: &str) -> Result<()> {
    if domain.is_empty() {
        return Err(Error::Managed("client domain cannot be empty".into()));
    }
    if domain.chars().count() > 128 {
        return Err(Error::Managed(
            "client domain must not exceed 128 characters".into(),
        ));
    }
    if !domain.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'@' | b'#' | b'$' | b'_')
    }) {
        return Err(Error::Managed(
            "client domain contains unsupported characters".into(),
        ));
    }
    Ok(())
}

fn response_data(value: Value) -> Result<Value> {
    let Some(object) = value.as_object() else {
        return Err(Error::Managed(
            "lookup response must be a JSON object".into(),
        ));
    };
    if let Some(success) = object.get("success").and_then(Value::as_bool) {
        if !success {
            let error = object.get("error").unwrap_or(&Value::Null);
            return Err(Error::Managed(format!("lookup rejected request: {error}")));
        }
        return object
            .get("data")
            .cloned()
            .ok_or_else(|| Error::Managed("successful lookup response has no data".into()));
    }
    Ok(value)
}

fn parse_response(domain: &str, raw: Value, source: LookupSource) -> Result<LookupResult> {
    let object = raw
        .as_object()
        .ok_or_else(|| Error::Managed("lookup data must be a JSON object".into()))?;
    let service_type = required_string(object, &["type"])?;
    let service_type = ServiceType::parse(service_type)?;
    let is_fuzzy_match = object
        .get("isFuzzyMatch")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let complete_domain = optional_string(object, &["completeDomain"])
        .unwrap_or(domain)
        .to_owned();
    if is_fuzzy_match {
        validate_domain(&complete_domain)?;
    }
    // The entered domain remains authoritative unless the lookup explicitly
    // marks completeDomain as the canonical replacement.
    let original_domain = domain.to_owned();
    let server_list_url = optional_string(object, &["serverlistaddress"]).map(ToOwned::to_owned);
    if matches!(service_type, ServiceType::ServerList | ServiceType::Saas)
        && server_list_url.is_none()
    {
        return Err(Error::Managed(
            "lookup response is missing serverlist URL".into(),
        ));
    }
    Ok(LookupResult {
        complete_domain,
        original_domain,
        is_fuzzy_match,
        service_type,
        server_list_url,
        saas_info: object.get("saas_info").cloned(),
        controller_info: object.get("controller_info").cloned(),
        source,
        raw,
    })
}

fn required_string<'a>(object: &'a Map<String, Value>, names: &[&str]) -> Result<&'a str> {
    optional_string(object, names)
        .ok_or_else(|| Error::Managed(format!("lookup response is missing {}", names.join("/"))))
}

fn optional_string<'a>(object: &'a Map<String, Value>, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(Value::as_str))
        .filter(|value| !value.is_empty())
}

fn object_string<'a>(value: &'a Value, names: &[&str]) -> Option<&'a str> {
    optional_string(value.as_object()?, names)
}

fn validate_lookup_endpoint(value: &str) -> Result<()> {
    let url = Url::parse(value)
        .map_err(|error| Error::Managed(format!("invalid lookup URL: {error}")))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/lookup"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Managed(
            "lookup URL must be an HTTPS /lookup endpoint".into(),
        ));
    }
    Ok(())
}

fn epoch_millis(time: SystemTime) -> Result<u64> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Managed("system time predates Unix epoch".into()))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| Error::Managed("system time is out of range".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::HttpResponse;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct MockTransport {
        responses: Mutex<VecDeque<Result<HttpResponse>>>,
        requests: Mutex<Vec<HttpRequest>>,
    }

    impl HttpTransport for MockTransport {
        fn execute(&self, request: HttpRequest) -> Result<HttpResponse> {
            self.requests.lock().unwrap().push(request);
            self.responses.lock().unwrap().pop_front().unwrap()
        }
    }

    fn response(status: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn domain_validation_matches_contract() {
        validate_domain("iwan.ustc").unwrap();
        validate_domain("a-b_c@d#$").unwrap();
        assert!(validate_domain("").is_err());
        assert!(validate_domain("bad/domain").is_err());
        assert!(validate_domain(&"a".repeat(129)).is_err());
    }

    #[test]
    fn retries_primary_then_uses_fallback_and_canonical_domain() {
        let transport = MockTransport {
            responses: Mutex::new(VecDeque::from([
                Err(Error::Http("offline".into())),
                Err(Error::Http("offline".into())),
                Ok(response(
                    200,
                    r#"{"success":true,"data":{"type":"controller","completeDomain":"iwan.ustc.edu.cn","originalDomain":"iwan.ustc","isFuzzyMatch":true,"controller_info":{"app_id":"controller-example","url":{"auth":"https://controller.example/m/auth","config":"https://controller.example/m/config"}}}}"#,
                )),
            ])),
            requests: Mutex::new(Vec::new()),
        };
        let client = LookupClient::with_transport(transport)
            .with_endpoints(vec![LOOKUP_PRIMARY.into(), LOOKUP_FALLBACK.into()]);
        let result = client.lookup("iwan.ustc", "device").unwrap();
        assert_eq!(result.active_domain(), "iwan.ustc.edu.cn");
        assert_eq!(result.service_type, ServiceType::Controller);
        let requests = client.transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        for request in requests.iter() {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(body["serviceType"], "fgb");
            assert!(body.get("type").is_none());
            for name in [
                "X-Auth-AppId",
                "X-Auth-Timestamp",
                "X-Auth-Nonce",
                "X-Auth-Sign",
            ] {
                assert!(request.headers.iter().any(|(header, _)| header == name));
            }
        }
        assert_ne!(
            header_value(&requests[0], "X-Auth-Nonce"),
            header_value(&requests[1], "X-Auth-Nonce")
        );
    }

    #[test]
    fn falls_back_to_unexpired_cache() {
        let directory =
            std::env::temp_dir().join(format!("openiwan-lookup-test-{}", std::process::id()));
        let cache = LookupCache::new(&directory);
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let raw = serde_json::json!({
            "type": "serverlist",
            "serverlistaddress": "https://config.example/list",
            "originalDomain": "example"
        });
        cache.write("example", &raw, now).unwrap();
        let transport = MockTransport {
            responses: Mutex::new(VecDeque::from([
                Err(Error::Http("offline".into())),
                Err(Error::Http("offline".into())),
                Err(Error::Http("offline".into())),
                Err(Error::Http("offline".into())),
            ])),
            requests: Mutex::new(Vec::new()),
        };
        let client = LookupClient::with_transport(transport)
            .with_cache(&directory)
            .with_endpoints(vec![LOOKUP_PRIMARY.into(), LOOKUP_FALLBACK.into()]);
        let result = client
            .lookup_at("example", "device", now + Duration::from_secs(60))
            .unwrap();
        assert_eq!(result.source, LookupSource::Cache);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn malformed_live_lookup_falls_back_to_unexpired_cache() {
        let directory = std::env::temp_dir().join(format!(
            "openiwan-invalid-live-lookup-test-{}",
            std::process::id()
        ));
        let cache = LookupCache::new(&directory);
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let cached = serde_json::json!({
            "type": "serverlist",
            "serverlistaddress": "https://config.example/list",
            "originalDomain": "example"
        });
        cache.write("example", &cached, now).unwrap();
        let transport = MockTransport {
            responses: Mutex::new(VecDeque::from([
                Ok(response(
                    200,
                    r#"{"success":true,"data":{"type":"unsupported"}}"#,
                )),
                Ok(response(
                    200,
                    r#"{"success":true,"data":{"type":"unsupported"}}"#,
                )),
            ])),
            requests: Mutex::new(Vec::new()),
        };
        let result = LookupClient::with_transport(transport)
            .with_cache(&directory)
            .with_endpoints(vec![LOOKUP_PRIMARY.into()])
            .lookup_at("example", "device", now + Duration::from_secs(60))
            .unwrap();
        assert_eq!(result.source, LookupSource::Cache);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn invalid_cache_does_not_mask_the_live_lookup_error() {
        let directory = std::env::temp_dir().join(format!(
            "openiwan-invalid-cache-lookup-test-{}",
            std::process::id()
        ));
        let cache = LookupCache::new(&directory);
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        cache
            .write("example", &serde_json::json!({"type": "unsupported"}), now)
            .unwrap();
        let transport = MockTransport {
            responses: Mutex::new(VecDeque::from([
                Err(Error::Http("offline".into())),
                Err(Error::Http("offline".into())),
            ])),
            requests: Mutex::new(Vec::new()),
        };
        let error = LookupClient::with_transport(transport)
            .with_cache(&directory)
            .with_endpoints(vec![LOOKUP_PRIMARY.into()])
            .lookup_at("example", "device", now + Duration::from_secs(60))
            .unwrap_err();
        assert!(matches!(error, Error::Http(ref message) if message == "offline"));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn successful_wrapper_requires_data() {
        assert!(response_data(serde_json::json!({"success": true})).is_err());
    }

    #[test]
    fn non_fuzzy_lookup_keeps_the_entered_domain() {
        let result = parse_response(
            "entered.example",
            serde_json::json!({
                "type": "serverlist",
                "serverlistaddress": "https://config.example/list",
                "originalDomain": "server-controlled.example",
                "completeDomain": "also-server-controlled.example",
                "isFuzzyMatch": false
            }),
            LookupSource::Network,
        )
        .unwrap();
        assert_eq!(result.active_domain(), "entered.example");
        assert_eq!(result.original_domain, "entered.example");
    }

    #[test]
    fn parses_macos_controller_url_map() {
        let result = parse_response(
            "iwan.ustc",
            serde_json::json!({
                "type": "controller",
                "domain": "iwan.ustc",
                "serverlistaddress": "https://controller.example/m/config",
                "controller_info": {
                    "url": {
                        "serverlist": "https://controller.example/m/serverlist",
                        "ipfilter": "https://controller.example/m/ipfilter",
                        "config": "https://controller.example/m/config",
                        "auth": "https://controller.example/m/auth"
                    },
                    "app_id": "controller-example"
                }
            }),
            LookupSource::Network,
        )
        .unwrap();

        assert_eq!(result.auth_url(), Some("https://controller.example/m/auth"));
        assert_eq!(
            result.config_url(),
            Some("https://controller.example/m/config")
        );
        assert_eq!(
            result.resolved_server_list_url(),
            Some("https://controller.example/m/serverlist")
        );
        assert_eq!(result.controller_app_id(), Some("controller-example"));
    }

    #[test]
    fn response_requires_type_member() {
        assert!(
            parse_response(
                "iwan.ustc",
                serde_json::json!({"domain": "iwan.ustc"}),
                LookupSource::Network,
            )
            .is_err()
        );
    }

    #[test]
    fn fuzzy_canonical_domain_must_pass_domain_validation() {
        let error = parse_response(
            "entered.example",
            serde_json::json!({
                "type": "controller",
                "completeDomain": "../escape",
                "isFuzzyMatch": true
            }),
            LookupSource::Network,
        )
        .unwrap_err();
        assert!(matches!(error, Error::Managed(_)));
    }

    #[test]
    fn cache_paths_do_not_alias_allowed_domain_characters() {
        let cache = LookupCache::new("/tmp/openiwan-lookup-cache-path-test");
        assert_ne!(cache.path("a@b"), cache.path("a#b"));
        assert_ne!(cache.path("a#b"), cache.path("a$b"));
    }

    fn header_value<'a>(request: &'a HttpRequest, name: &str) -> &'a str {
        request
            .headers
            .iter()
            .find(|(header, _)| header == name)
            .unwrap()
            .1
            .as_str()
    }
}
