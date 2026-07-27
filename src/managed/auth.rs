use super::http::{HttpRequest, HttpTransport};
use super::lookup::{LookupResult, ServiceType};
use super::security;
use crate::{Error, Result};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use url::Url;

pub const AUTH_REQUEST_ATTEMPTS: usize = 3;
const OEM_NAME: &str = "panabit";

#[derive(Serialize)]
struct AuthRequest<'a> {
    domain: &'a str,
    #[serde(rename = "type")]
    client_type: &'a str,
    oem_name: &'static str,
    device_id: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Credential,
    Oidc,
}

#[derive(Debug, Clone)]
pub struct ControllerOidcConfig {
    pub authorization_url: String,
    pub token_url: String,
    pub userinfo_endpoint: Option<String>,
    pub discovery_url: Option<String>,
    pub client_id: String,
    pub kc_idp_hint: Option<String>,
    pub provider_hint: Option<String>,
    pub issuer: Option<String>,
    pub parameters: Map<String, Value>,
    pub metadata: Map<String, Value>,
}

#[derive(Debug, Clone)]
pub struct ControllerAuth {
    pub version: Option<String>,
    pub method: AuthMethod,
    pub oidc: Option<ControllerOidcConfig>,
    pub keepalive: Option<Value>,
    raw: Value,
}

impl ControllerAuth {
    pub const fn raw(&self) -> &Value {
        &self.raw
    }
}

impl ControllerOidcConfig {
    pub(crate) fn provider_config(
        &self,
        redirect_uri: impl Into<String>,
    ) -> super::oidc::OidcConfig {
        let mut additional_authorization_parameters: BTreeMap<String, String> = self
            .parameters
            .iter()
            .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_owned())))
            .collect();
        if let Some(hint) = &self.kc_idp_hint {
            additional_authorization_parameters
                .entry("kc_idp_hint".into())
                .or_insert_with(|| hint.clone());
        }
        let organization = additional_authorization_parameters
            .remove("organization")
            .unwrap_or_default();
        let scopes = additional_authorization_parameters
            .remove("scope")
            .map(|scope| {
                scope
                    .split_ascii_whitespace()
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .filter(|scopes| !scopes.is_empty())
            .unwrap_or_else(|| vec!["openid".into(), "profile".into(), "email".into()]);
        let provider = self
            .provider_hint
            .clone()
            .or_else(|| additional_authorization_parameters.remove("provider_hint"))
            .or_else(|| additional_authorization_parameters.remove("provider"))
            .unwrap_or_default();
        super::oidc::OidcConfig {
            authorization_endpoint: self.authorization_url.clone(),
            token_endpoint: self.token_url.clone(),
            client_id: self.client_id.clone(),
            redirect_uri: redirect_uri.into(),
            scopes,
            organization,
            provider,
            additional_authorization_parameters,
        }
    }
}

pub(crate) fn fetch<T: HttpTransport>(
    lookup: &LookupResult,
    device_id: &str,
    transport: &T,
) -> Result<ControllerAuth> {
    if lookup.service_type != ServiceType::Controller {
        return Ok(ControllerAuth {
            version: None,
            method: AuthMethod::Credential,
            oidc: None,
            keepalive: None,
            raw: Value::Null,
        });
    }
    if device_id.is_empty() {
        return Err(Error::Controller(
            "auth request device_id must not be empty".into(),
        ));
    }
    let endpoint = auth_endpoint(lookup)?;
    let app_id = lookup
        .controller_app_id()
        .ok_or_else(|| Error::Controller("controller lookup has no app_id".into()))?;
    let body = serde_json::to_vec(&AuthRequest {
        domain: lookup.active_domain(),
        client_type: client_platform(),
        oem_name: OEM_NAME,
        device_id,
    })
    .map_err(|error| Error::Controller(format!("serialize auth request: {error}")))?;
    let mut last_error = None;
    for _ in 0..AUTH_REQUEST_ATTEMPTS {
        let mut headers = vec![
            ("Content-Type".into(), "application/json".into()),
            ("X-Mobile-Api-Version".into(), "4".into()),
        ];
        headers.extend(security::controller_api_headers(
            "POST", &endpoint, &body, app_id,
        )?);
        match transport.execute(HttpRequest {
            method: "POST",
            url: endpoint.clone(),
            headers,
            body: body.clone(),
            timeout: None,
        }) {
            Ok(response) if response.status == 200 => {
                let parsed = serde_json::from_slice(&response.body)
                    .map_err(|error| Error::Controller(format!("invalid auth response: {error}")))
                    .and_then(parse_response);
                match parsed {
                    Ok(auth) => return Ok(auth),
                    Err(error) => last_error = Some(error),
                }
            }
            Ok(response) => {
                last_error = Some(match response.status {
                    401 => Error::ControllerUnauthorized,
                    status => Error::Controller(format!("auth returned HTTP {status}")),
                });
                if matches!(response.status, 400..=499) {
                    break;
                }
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| Error::Controller("auth request failed".into())))
}

/// Fall back to credential mode when `/auth` cannot be obtained or decoded.
/// A successfully decoded explicit OIDC response is never downgraded.
pub(crate) fn fetch_or_credential<T: HttpTransport>(
    lookup: &LookupResult,
    device_id: &str,
    transport: &T,
) -> ControllerAuth {
    fetch(lookup, device_id, transport).unwrap_or_else(|error| {
        tracing::debug!(
            error = %error,
            domain = lookup.active_domain(),
            "controller auth unavailable; falling back to credential mode"
        );
        ControllerAuth {
            version: None,
            method: AuthMethod::Credential,
            oidc: None,
            keepalive: None,
            raw: Value::Null,
        }
    })
}

fn auth_endpoint(lookup: &LookupResult) -> Result<String> {
    let endpoint = lookup
        .auth_url()
        .ok_or_else(|| Error::Controller("controller lookup has no auth URL".into()))?;
    let url = Url::parse(endpoint)
        .map_err(|error| Error::Controller(format!("invalid auth URL: {error}")))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Controller("auth URL must use HTTPS".into()));
    }
    Ok(endpoint.to_owned())
}

#[cfg(target_os = "android")]
pub(crate) const fn client_platform() -> &'static str {
    "android"
}

#[cfg(target_os = "ios")]
pub(crate) const fn client_platform() -> &'static str {
    "ios"
}

#[cfg(target_os = "macos")]
pub(crate) const fn client_platform() -> &'static str {
    "macos"
}

#[cfg(target_os = "windows")]
pub(crate) const fn client_platform() -> &'static str {
    "windows"
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    target_os = "macos",
    target_os = "windows"
)))]
pub(crate) const fn client_platform() -> &'static str {
    // The controller API has no distinct desktop-Unix profile.
    "android"
}

fn parse_response(value: Value) -> Result<ControllerAuth> {
    let root = value
        .as_object()
        .ok_or_else(|| Error::Controller("auth response must be an object".into()))?;
    let object = root
        .get("auth")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::Controller("auth response has no auth object".into()))?;
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Controller("auth response has no method".into()))?;
    let method = match method.to_ascii_lowercase().as_str() {
        "credential" => AuthMethod::Credential,
        "oidc" => AuthMethod::Oidc,
        _ => {
            return Err(Error::Controller(format!("invalid auth method {method:?}")));
        }
    };
    let oidc = match method {
        AuthMethod::Credential => None,
        AuthMethod::Oidc => Some(parse_oidc(
            object
                .get("oidc")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    Error::Controller("method=oidc response has no oidc object".into())
                })?,
        )?),
    };
    Ok(ControllerAuth {
        version: root
            .get("version")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        method,
        oidc,
        keepalive: root.get("keepalive").cloned(),
        raw: value,
    })
}

fn parse_oidc(object: &Map<String, Value>) -> Result<ControllerOidcConfig> {
    let authorization_url = required_nonempty(object, "authorization_endpoint")?.to_owned();
    let token_url = required_nonempty(object, "token_endpoint")?.to_owned();
    let client_id = required_nonempty(object, "client_id")?.to_owned();
    validate_https("authorization_endpoint", &authorization_url)?;
    validate_https("token_endpoint", &token_url)?;
    let parameters = optional_object(object, "parameters");
    let metadata = optional_object(object, "metadata");
    let userinfo_endpoint = optional_nonempty(object, "userinfo_endpoint").map(ToOwned::to_owned);
    if let Some(url) = &userinfo_endpoint {
        validate_https("userinfo_endpoint", url)?;
    }
    let discovery_url = optional_nonempty(object, "discoveryUrl").map(ToOwned::to_owned);
    if let Some(url) = &discovery_url {
        validate_https("discoveryUrl", url)?;
    }
    Ok(ControllerOidcConfig {
        authorization_url,
        token_url,
        userinfo_endpoint,
        discovery_url,
        client_id,
        kc_idp_hint: optional_nonempty(object, "kc_idp_hint").map(ToOwned::to_owned),
        provider_hint: optional_nonempty(object, "provider_hint").map(ToOwned::to_owned),
        issuer: optional_nonempty(object, "issuer").map(ToOwned::to_owned),
        parameters,
        metadata,
    })
}

fn required_nonempty<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    optional_nonempty(object, name)
        .ok_or_else(|| Error::Controller(format!("OIDC config is missing {name}")))
}

fn optional_nonempty<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn optional_object(object: &Map<String, Value>, name: &str) -> Map<String, Value> {
    object
        .get(name)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

fn validate_https(name: &str, value: &str) -> Result<()> {
    let url =
        Url::parse(value).map_err(|error| Error::Controller(format!("invalid {name}: {error}")))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Controller(format!(
            "{name} must be an HTTPS URL without credentials or a fragment"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::http::HttpResponse;
    use crate::managed::{LookupSource, ServiceType};
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

    fn lookup() -> LookupResult {
        LookupResult {
            complete_domain: "canonical.example".into(),
            original_domain: "example".into(),
            is_fuzzy_match: true,
            service_type: ServiceType::Controller,
            server_list_url: None,
            saas_info: None,
            controller_info: Some(serde_json::json!({
                "app_id": "controller-example",
                "url": {
                    "auth": "https://controller.example/m/auth"
                }
            })),
            source: LookupSource::Network,
            raw: Value::Null,
        }
    }

    #[test]
    fn parses_oidc_auth_and_uses_canonical_domain() {
        let transport = MockTransport {
            responses: Mutex::new(VecDeque::from([Ok(HttpResponse {
                status: 200,
                body: br#"{"version":"1","auth":{"method":"oidc","oidc":{"authorization_endpoint":"https://id.example/auth","token_endpoint":"https://id.example/token","client_id":"mobile","parameters":{"organization":"example","provider_hint":"enterprise","prompt":"login","scope":"openid profile email offline_access"},"metadata":{"issuer":"id"}}},"keepalive":{"endpoint":"/m/keepalive","interval":300}}"#.to_vec(),
            })])),
            requests: Mutex::new(Vec::new()),
        };
        let auth = fetch(&lookup(), "device-id", &transport).unwrap();
        assert_eq!(auth.method, AuthMethod::Oidc);
        let oidc = auth.oidc.unwrap();
        assert_eq!(oidc.client_id, "mobile");
        let provider = oidc.provider_config("com.panabit.mobile://oauth2redirect");
        assert_eq!(
            provider.scopes,
            ["openid", "profile", "email", "offline_access"]
        );
        assert_eq!(provider.organization, "example");
        assert_eq!(provider.provider, "enterprise");
        assert_eq!(
            provider.additional_authorization_parameters.get("prompt"),
            Some(&"login".to_owned())
        );
        assert!(
            !provider
                .additional_authorization_parameters
                .contains_key("scope")
        );
        assert_eq!(
            transport.requests.lock().unwrap()[0].url,
            "https://controller.example/m/auth"
        );
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests[0].method, "POST");
        let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["domain"], "canonical.example");
        assert_eq!(body["type"], client_platform());
        assert_eq!(body["oem_name"], "panabit");
        assert_eq!(body["device_id"], "device-id");
        assert!(body.get("app_version").is_none());
        for name in [
            "X-Auth-AppId",
            "X-Auth-Timestamp",
            "X-Auth-Nonce",
            "X-Auth-Sign",
        ] {
            assert!(requests[0].headers.iter().any(|(header, _)| header == name));
        }
    }

    #[test]
    fn uses_nested_macos_auth_endpoint() {
        let mut lookup = lookup();
        lookup.complete_domain = "iwan.ustc".into();
        lookup.original_domain = "iwan.ustc".into();
        lookup.is_fuzzy_match = false;
        lookup.controller_info = Some(serde_json::json!({
            "app_id": "controller-example",
            "url": {
                "auth": "https://controller.example/m/auth"
            }
        }));
        let transport = MockTransport {
            responses: Mutex::new(VecDeque::from([Ok(HttpResponse {
                status: 200,
                body: br#"{"auth":{"method":"oidc","oidc":{"authorization_endpoint":"https://id.example/auth","token_endpoint":"https://id.example/token","client_id":"mobile"}}}"#.to_vec(),
            })])),
            requests: Mutex::new(Vec::new()),
        };

        assert_eq!(
            fetch(&lookup, "device-id", &transport).unwrap().method,
            AuthMethod::Oidc
        );
        assert_eq!(
            transport.requests.lock().unwrap()[0].url,
            "https://controller.example/m/auth"
        );
    }

    #[test]
    fn invalid_auth_falls_back_only_through_explicit_ui_semantics() {
        let transport = MockTransport {
            responses: Mutex::new(VecDeque::from([
                Ok(HttpResponse {
                    status: 200,
                    body: br#"{"auth":{"method":"unknown"}}"#.to_vec(),
                }),
                Ok(HttpResponse {
                    status: 200,
                    body: br#"{"auth":{"method":"unknown"}}"#.to_vec(),
                }),
                Ok(HttpResponse {
                    status: 200,
                    body: br#"{"auth":{"method":"unknown"}}"#.to_vec(),
                }),
            ])),
            requests: Mutex::new(Vec::new()),
        };
        assert_eq!(
            fetch_or_credential(&lookup(), "device-id", &transport).method,
            AuthMethod::Credential
        );
    }

    #[test]
    fn rejects_unknown_auth_method() {
        let error = parse_response(serde_json::json!({
            "auth": {
                "method": "unsupported"
            }
        }))
        .unwrap_err();
        assert!(error.to_string().contains("invalid auth method"));
    }

    #[test]
    fn auth_uses_the_lookup_endpoint_without_appending_the_domain() {
        let mut lookup = lookup();
        lookup.complete_domain = "canonical.example".into();
        lookup.controller_info = Some(serde_json::json!({
            "app_id": "controller-example",
            "url": {
                "auth": "https://controller.example/m/auth?tenant=canonical"
            }
        }));
        assert_eq!(
            auth_endpoint(&lookup).unwrap(),
            "https://controller.example/m/auth?tenant=canonical"
        );
    }
}
