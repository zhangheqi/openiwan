use super::http::{HttpRequest, HttpTransport};
use crate::{Error, Result};
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use url::Url;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub(crate) struct OidcConfig {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub organization: String,
    pub provider: String,
    pub additional_authorization_parameters: BTreeMap<String, String>,
}

impl OidcConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", self.redirect_uri.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(Error::Oidc(format!("{name} must not be empty")));
            }
        }
        if !self.scopes.iter().any(|scope| scope == "openid") {
            return Err(Error::Oidc("OIDC scopes must include openid".into()));
        }
        for (name, value) in [
            (
                "authorization endpoint",
                self.authorization_endpoint.as_str(),
            ),
            ("token endpoint", self.token_endpoint.as_str()),
        ] {
            let _ = parse_https_url(name, value)?;
        }
        let redirect = Url::parse(&self.redirect_uri)
            .map_err(|error| Error::Oidc(format!("invalid redirect URI: {error}")))?;
        if redirect.scheme().is_empty()
            || redirect.query().is_some()
            || redirect.fragment().is_some()
        {
            return Err(Error::Oidc(
                "redirect URI must have a scheme and no query or fragment".into(),
            ));
        }
        Ok(())
    }
}

pub struct PendingAuthorization {
    authorization_url: Url,
    token_endpoint: String,
    state: Zeroizing<String>,
    nonce: Zeroizing<String>,
    code_verifier: Zeroizing<String>,
}

impl std::fmt::Debug for PendingAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingAuthorization")
            .field("authorization_url", &"[REDACTED]")
            .field("state", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("code_verifier", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl PendingAuthorization {
    pub fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }
}

pub struct OidcIdentity {
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
    pub user_id: String,
    pub username: String,
    pub expires_at: i64,
}

impl std::fmt::Debug for OidcIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OidcIdentity")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("user_id", &self.user_id)
            .field("username", &self.username)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Deserialize)]
#[allow(clippy::struct_field_names)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    id_token: String,
    #[serde(default)]
    expires_in: Option<i64>,
}

pub fn begin(oidc: &OidcConfig) -> Result<PendingAuthorization> {
    let code_verifier = random_urlsafe(64);
    let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(code_verifier.as_bytes()));
    let state = random_urlsafe(32);
    let nonce = random_urlsafe(32);
    let mut authorization_url =
        parse_https_url("authorization endpoint", &oidc.authorization_endpoint)?;
    authorization_url
        .query_pairs_mut()
        .append_pair("client_id", &oidc.client_id)
        .append_pair("redirect_uri", &oidc.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", &oidc.scopes.join(" "))
        .append_pair("code_challenge", &code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &state)
        .append_pair("nonce", &nonce);
    if !oidc.organization.is_empty() {
        authorization_url
            .query_pairs_mut()
            .append_pair("organization", &oidc.organization);
    }
    if !oidc.provider.is_empty() {
        authorization_url
            .query_pairs_mut()
            .append_pair("provider", &oidc.provider);
    }
    for (name, value) in &oidc.additional_authorization_parameters {
        authorization_url.query_pairs_mut().append_pair(name, value);
    }

    Ok(PendingAuthorization {
        authorization_url,
        token_endpoint: oidc.token_endpoint.clone(),
        state: Zeroizing::new(state),
        nonce: Zeroizing::new(nonce),
        code_verifier: Zeroizing::new(code_verifier),
    })
}

pub(crate) fn complete<T: HttpTransport>(
    oidc: &OidcConfig,
    transport: &T,
    pending: &PendingAuthorization,
    redirect_url: &str,
) -> Result<OidcIdentity> {
    let redirect = Url::parse(redirect_url)
        .map_err(|error| Error::Oidc(format!("invalid callback URL: {error}")))?;
    validate_redirect_uri(&oidc.redirect_uri, &redirect)?;
    let query: std::collections::HashMap<String, String> =
        redirect.query_pairs().into_owned().collect();
    if let Some(error) = query.get("error") {
        let description = query
            .get("error_description")
            .map_or("", |value| value.as_str());
        return Err(Error::Oidc(format!(
            "authorization server returned {error}: {description}"
        )));
    }
    let returned_state = query
        .get("state")
        .ok_or_else(|| Error::Oidc("callback URL has no state".into()))?;
    if returned_state.as_bytes() != pending.state.as_bytes() {
        return Err(Error::Oidc("callback state mismatch".into()));
    }
    let code = Zeroizing::new(
        query
            .get("code")
            .cloned()
            .ok_or_else(|| Error::Oidc("callback URL has no authorization code".into()))?,
    );

    let (content_type, body) = token_request_body(oidc, &code, &pending.code_verifier);
    let response = transport.execute(HttpRequest {
        method: "POST",
        url: pending.token_endpoint.clone(),
        headers: vec![("Content-Type".into(), content_type.into())],
        body,
        timeout: None,
    })?;
    if response.status != 200 {
        return Err(Error::Oidc(format!(
            "token endpoint returned HTTP {}",
            response.status
        )));
    }
    let response_body = Zeroizing::new(response.body);
    let token: TokenResponse = serde_json::from_slice(&response_body)
        .map_err(|error| Error::Oidc(format!("invalid token response: {error}")))?;
    if token.access_token.is_empty() || token.id_token.is_empty() {
        return Err(Error::Oidc(
            "token response is missing access_token or id_token".into(),
        ));
    }
    let access_token = Zeroizing::new(token.access_token);
    let refresh_token = Zeroizing::new(token.refresh_token);
    let id_token = Zeroizing::new(token.id_token);
    let claims = parse_id_token(&id_token, &pending.nonce)?;
    let username = extract_username(&claims)?;
    let user_id = claims
        .get("sub")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::Oidc("ID token has no subject".into()))?
        .to_owned();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let expires_at = token
        .expires_in
        .filter(|seconds| *seconds > 0)
        .and_then(|seconds| now.checked_add(seconds))
        .or_else(|| {
            parse_jwt_payload(&access_token)
                .ok()
                .and_then(|claims| claims.get("exp").and_then(Value::as_i64))
        })
        .or_else(|| claims.get("exp").and_then(Value::as_i64))
        .ok_or_else(|| Error::Oidc("token response has no expiry".into()))?;
    Ok(OidcIdentity {
        access_token,
        refresh_token,
        user_id,
        username,
        expires_at,
    })
}

fn validate_redirect_uri(expected: &str, actual: &Url) -> Result<()> {
    let expected = Url::parse(expected)
        .map_err(|error| Error::Oidc(format!("invalid configured redirect URI: {error}")))?;
    if expected.scheme() != actual.scheme()
        || expected.username() != actual.username()
        || expected.password() != actual.password()
        || expected.host_str() != actual.host_str()
        || expected.port() != actual.port()
        || expected.path() != actual.path()
        || actual.fragment().is_some()
    {
        return Err(Error::Oidc(
            "callback URL does not match the configured redirect URI".into(),
        ));
    }
    Ok(())
}

fn token_request_body(
    oidc: &OidcConfig,
    code: &str,
    code_verifier: &str,
) -> (&'static str, Vec<u8>) {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &oidc.client_id)
        .append_pair("code", code)
        .append_pair("code_verifier", code_verifier)
        .append_pair("redirect_uri", &oidc.redirect_uri)
        .append_pair("grant_type", "authorization_code")
        .finish()
        .into_bytes();
    ("application/x-www-form-urlencoded", body)
}

fn parse_id_token(token: &str, expected_nonce: &str) -> Result<Value> {
    let claims = parse_jwt_payload(token)?;
    let nonce = claims
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Oidc("ID token has no nonce".into()))?;
    if nonce.as_bytes() != expected_nonce.as_bytes() {
        return Err(Error::Oidc("ID token nonce mismatch".into()));
    }
    Ok(claims)
}

fn parse_jwt_payload(token: &str) -> Result<Value> {
    let mut segments = token.split('.');
    let _header = segments
        .next()
        .filter(|segment| !segment.is_empty())
        .ok_or_else(|| Error::Oidc("ID token has no header".into()))?;
    let payload = segments
        .next()
        .filter(|segment| !segment.is_empty())
        .ok_or_else(|| Error::Oidc("ID token has no payload".into()))?;
    let _signature = segments
        .next()
        .ok_or_else(|| Error::Oidc("ID token has no signature segment".into()))?;
    if segments.next().is_some() {
        return Err(Error::Oidc("ID token has too many segments".into()));
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload))
        .map_err(|error| Error::Oidc(format!("invalid ID token payload encoding: {error}")))?;
    let claims: Value = serde_json::from_slice(&payload)
        .map_err(|error| Error::Oidc(format!("invalid ID token payload: {error}")))?;
    if !claims.is_object() {
        return Err(Error::Oidc("JWT payload must be an object".into()));
    }
    Ok(claims)
}

fn extract_username(claims: &Value) -> Result<String> {
    for claim in ["preferred_username", "email", "sub"] {
        if let Some(value) = claims.get(claim).and_then(Value::as_str)
            && !value.trim().is_empty()
        {
            return Ok(value.to_owned());
        }
    }
    Err(Error::Oidc(
        "ID token does not contain a recovered username claim".into(),
    ))
}

fn parse_https_url(name: &str, value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|error| Error::Oidc(format!("invalid {name}: {error}")))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Oidc(format!(
            "{name} must be an HTTPS URL without credentials or a fragment"
        )));
    }
    Ok(url)
}

fn random_urlsafe(length: usize) -> String {
    let mut bytes = vec![0_u8; length];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::http::{HttpResponse, HttpTransport};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MockTransport {
        responses: Mutex<VecDeque<HttpResponse>>,
        requests: Mutex<Vec<HttpRequest>>,
    }

    impl MockTransport {
        fn push_json(&self, value: Value) {
            self.responses.lock().unwrap().push_back(HttpResponse {
                status: 200,
                body: serde_json::to_vec(&value).unwrap(),
            });
        }
    }

    impl HttpTransport for MockTransport {
        fn execute(&self, request: HttpRequest) -> Result<HttpResponse> {
            self.requests.lock().unwrap().push(request);
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| Error::Http("mock response queue is empty".into()))
        }
    }

    fn oidc() -> OidcConfig {
        OidcConfig {
            authorization_endpoint: "https://auth.example.test/authorize".into(),
            token_endpoint: "https://auth.example.test/token".into(),
            client_id: "client-id".into(),
            redirect_uri: "com.example.app://oauth2redirect".into(),
            scopes: vec!["openid".into(), "profile".into()],
            organization: "example".into(),
            provider: "oidc".into(),
            additional_authorization_parameters: BTreeMap::default(),
        }
    }

    fn id_token(claims: &Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(claims).unwrap());
        format!("{header}.{payload}.signature")
    }

    #[test]
    fn redirect_requires_exact_origin_path_and_state() {
        let actual = Url::parse("com.example.app://oauth2redirect?code=x&state=y").unwrap();
        validate_redirect_uri("com.example.app://oauth2redirect", &actual).unwrap();
        assert!(validate_redirect_uri("com.example.app://other", &actual).is_err());
        assert!(
            validate_redirect_uri(
                "com.example.app://oauth2redirect",
                &Url::parse("com.attacker.app://oauth2redirect?code=x&state=y").unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn performs_recovered_pkce_oidc_exchange() {
        let oidc = oidc();
        let transport = MockTransport::default();
        let pending = begin(&oidc).unwrap();
        let query: std::collections::HashMap<_, _> = pending
            .authorization_url()
            .query_pairs()
            .into_owned()
            .collect();
        assert_eq!(query.get("code_challenge_method").unwrap(), "S256");
        assert_eq!(query.get("nonce").unwrap(), pending.nonce.as_str());
        assert_eq!(query.get("state").unwrap(), pending.state.as_str());
        assert_eq!(query.get("organization").unwrap(), "example");
        assert_eq!(query.get("provider").unwrap(), "oidc");

        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let claims = serde_json::json!({
            "exp": now + 3600,
            "nonce": pending.nonce.as_str(),
            "sub": "user-1",
            "preferred_username": "alice"
        });
        transport.push_json(serde_json::json!({
            "access_token": "access-token-value",
            "refresh_token": "refresh-token-value",
            "id_token": id_token(&claims)
        }));

        let redirect = format!(
            "com.example.app://oauth2redirect?code=authorization-code&state={}",
            pending.state.as_str()
        );
        let identity = complete(&oidc, &transport, &pending, &redirect).unwrap();
        assert_eq!(identity.username, "alice");
        assert_eq!(identity.user_id, "user-1");
        assert_eq!(identity.access_token.as_str(), "access-token-value");

        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].url, "https://auth.example.test/token");
        assert_eq!(
            requests[0].headers,
            vec![(
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into()
            )]
        );
        assert!(String::from_utf8_lossy(&requests[0].body).contains("code_verifier="));
    }

    #[test]
    fn username_claims_match_recovered_precedence() {
        assert_eq!(
            extract_username(&serde_json::json!({
                "preferred_username": "preferred",
                "email": "person@example.test",
                "sub": "subject"
            }))
            .unwrap(),
            "preferred"
        );
        assert_eq!(
            extract_username(&serde_json::json!({
                "email": "person@example.test",
                "sub": "subject"
            }))
            .unwrap(),
            "person@example.test"
        );
        assert!(extract_username(&serde_json::json!({"name": "speculative"})).is_err());
    }

    #[test]
    fn rejects_callback_state_before_token_exchange() {
        let oidc = oidc();
        let transport = MockTransport::default();
        let pending = begin(&oidc).unwrap();
        let error = complete(
            &oidc,
            &transport,
            &pending,
            "com.example.app://oauth2redirect?code=x&state=wrong",
        )
        .unwrap_err();
        assert!(matches!(error, Error::Oidc(_)));
        assert!(transport.requests.lock().unwrap().is_empty());
    }
}
