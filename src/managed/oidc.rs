use super::http::{HttpRequest, HttpTransport};
use super::provider::OidcConfig;
use crate::{Error, Result};
use base64::Engine;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use rand::RngCore;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    id_token_signing_alg_values_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
}

pub struct PendingAuthorization {
    authorization_url: Url,
    discovery: DiscoveryDocument,
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
    pub username: String,
}

impl std::fmt::Debug for OidcIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OidcIdentity")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("username", &self.username)
            .finish()
    }
}

#[derive(Deserialize)]
#[allow(clippy::struct_field_names)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    id_token: String,
}

pub fn begin<T: HttpTransport>(oidc: &OidcConfig, transport: &T) -> Result<PendingAuthorization> {
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        oidc.issuer.trim_end_matches('/')
    );
    let response = transport.execute(HttpRequest {
        method: "GET",
        url: discovery_url,
        headers: Vec::new(),
        body: Vec::new(),
    })?;
    if response.status != 200 {
        return Err(Error::Oidc(format!(
            "discovery returned HTTP {}",
            response.status
        )));
    }
    let discovery: DiscoveryDocument = serde_json::from_slice(&response.body)
        .map_err(|error| Error::Oidc(format!("invalid discovery document: {error}")))?;
    validate_discovery(oidc, &discovery)?;

    let code_verifier = random_urlsafe(64);
    let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(code_verifier.as_bytes()));
    let state = random_urlsafe(32);
    let nonce = random_urlsafe(32);
    let mut authorization_url =
        parse_https_url("authorization endpoint", &discovery.authorization_endpoint)?;
    authorization_url
        .query_pairs_mut()
        .append_pair("client_id", &oidc.client_id)
        .append_pair("redirect_uri", &oidc.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", &oidc.scopes.join(" "))
        .append_pair("code_challenge", &code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("organization", &oidc.organization)
        .append_pair("provider", &oidc.provider);

    Ok(PendingAuthorization {
        authorization_url,
        discovery,
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
        url: pending.discovery.token_endpoint.clone(),
        headers: vec![("Content-Type".into(), content_type.into())],
        body,
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
    if token.access_token.is_empty() || token.refresh_token.is_empty() || token.id_token.is_empty()
    {
        return Err(Error::Oidc(
            "token response is missing access_token, refresh_token, or id_token".into(),
        ));
    }
    let access_token = Zeroizing::new(token.access_token);
    let refresh_token = Zeroizing::new(token.refresh_token);
    let id_token = Zeroizing::new(token.id_token);
    let claims = validate_id_token(oidc, transport, pending, &id_token)?;
    let username = extract_username(oidc, &claims)?;
    Ok(OidcIdentity {
        access_token,
        refresh_token,
        username,
    })
}

fn validate_discovery(oidc: &OidcConfig, discovery: &DiscoveryDocument) -> Result<()> {
    if discovery.issuer.trim_end_matches('/') != oidc.issuer.trim_end_matches('/') {
        return Err(Error::Oidc(
            "discovery issuer does not match the provider configuration".into(),
        ));
    }
    for (name, value) in [
        (
            "authorization endpoint",
            discovery.authorization_endpoint.as_str(),
        ),
        ("token endpoint", discovery.token_endpoint.as_str()),
        ("JWKS endpoint", discovery.jwks_uri.as_str()),
    ] {
        let _ = parse_https_url(name, value)?;
    }
    if !discovery
        .code_challenge_methods_supported
        .iter()
        .any(|method| method == "S256")
    {
        return Err(Error::Oidc(
            "authorization server does not advertise PKCE S256".into(),
        ));
    }
    if discovery.id_token_signing_alg_values_supported.is_empty() {
        return Err(Error::Oidc(
            "authorization server advertises no ID token signing algorithms".into(),
        ));
    }
    Ok(())
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

fn validate_id_token<T: HttpTransport>(
    oidc: &OidcConfig,
    transport: &T,
    pending: &PendingAuthorization,
    token: &str,
) -> Result<Value> {
    let header = decode_header(token)
        .map_err(|error| Error::Oidc(format!("invalid ID token header: {error}")))?;
    if !matches!(
        header.alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
    ) {
        return Err(Error::Oidc(
            "ID token must use an approved asymmetric signature algorithm".into(),
        ));
    }
    let algorithm_name = format!("{:?}", header.alg);
    if !pending
        .discovery
        .id_token_signing_alg_values_supported
        .iter()
        .any(|supported| supported == &algorithm_name)
    {
        return Err(Error::Oidc(format!(
            "ID token algorithm {algorithm_name} is not advertised by the issuer"
        )));
    }

    let response = transport.execute(HttpRequest {
        method: "GET",
        url: pending.discovery.jwks_uri.clone(),
        headers: Vec::new(),
        body: Vec::new(),
    })?;
    if response.status != 200 {
        return Err(Error::Oidc(format!(
            "JWKS endpoint returned HTTP {}",
            response.status
        )));
    }
    let jwks: JwkSet = serde_json::from_slice(&response.body)
        .map_err(|error| Error::Oidc(format!("invalid JWKS response: {error}")))?;
    let jwk = select_jwk(&jwks, header.kid.as_deref())?;
    let key = DecodingKey::from_jwk(jwk)
        .map_err(|error| Error::Oidc(format!("unsupported JWK: {error}")))?;
    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[oidc.client_id.as_str()]);
    validation.set_issuer(&[pending.discovery.issuer.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    let token_data = decode::<Value>(token, &key, &validation)
        .map_err(|error| Error::Oidc(format!("ID token validation failed: {error}")))?;
    let claims = token_data.claims;
    let nonce = claims
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Oidc("ID token has no nonce".into()))?;
    if nonce.as_bytes() != pending.nonce.as_bytes() {
        return Err(Error::Oidc("ID token nonce mismatch".into()));
    }
    Ok(claims)
}

fn select_jwk<'a>(set: &'a JwkSet, key_id: Option<&str>) -> Result<&'a Jwk> {
    match key_id {
        Some(key_id) => set
            .find(key_id)
            .ok_or_else(|| Error::Oidc(format!("JWKS has no key with id {key_id:?}"))),
        None if set.keys.len() == 1 => Ok(&set.keys[0]),
        None => Err(Error::Oidc(
            "ID token has no key id and JWKS contains multiple keys".into(),
        )),
    }
}

fn extract_username(oidc: &OidcConfig, claims: &Value) -> Result<String> {
    if let Some(value) = claims.get(&oidc.username_claim).and_then(Value::as_str)
        && !value.trim().is_empty()
    {
        return Ok(value.to_owned());
    }
    Err(Error::Oidc(format!(
        "ID token does not contain username claim {:?}",
        oidc.username_claim
    )))
}

fn parse_https_url(name: &str, value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|error| Error::Oidc(format!("invalid {name}: {error}")))?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(Error::Oidc(format!("{name} must use HTTPS")));
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
    use crate::managed::provider::OidcConfig;
    use jsonwebtoken::{EncodingKey, Header, encode};
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
            issuer: "https://auth.example.test".into(),
            client_id: "client-id".into(),
            redirect_uri: "com.example.app://oauth2redirect".into(),
            scopes: vec!["openid".into(), "profile".into()],
            username_claim: "name".into(),
            organization: "example".into(),
            provider: "oidc".into(),
        }
    }

    fn discovery() -> Value {
        serde_json::json!({
            "issuer": "https://auth.example.test",
            "authorization_endpoint": "https://auth.example.test/authorize",
            "token_endpoint": "https://auth.example.test/token",
            "jwks_uri": "https://auth.example.test/jwks",
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"]
        })
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
    fn validates_full_pkce_oidc_exchange() {
        let oidc = oidc();
        let transport = MockTransport::default();
        transport.push_json(discovery());
        let pending = begin(&oidc, &transport).unwrap();
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

        let now = jsonwebtoken::get_current_timestamp();
        let claims = serde_json::json!({
            "iss": "https://auth.example.test",
            "aud": "client-id",
            "exp": now + 3600,
            "iat": now,
            "nonce": pending.nonce.as_str(),
            "name": "alice"
        });
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("rsa01".into());
        let private_key = include_bytes!("../../tests/fixtures/test_rsa_private.pem");
        let id_token = encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(private_key).unwrap(),
        )
        .unwrap();
        transport.push_json(serde_json::json!({
            "access_token": "access-token-value",
            "refresh_token": "refresh-token-value",
            "id_token": id_token
        }));
        transport.push_json(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "n": "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ",
                "e": "AQAB",
                "kid": "rsa01",
                "alg": "RS256",
                "use": "sig"
            }]
        }));

        let redirect = format!(
            "com.example.app://oauth2redirect?code=authorization-code&state={}",
            pending.state.as_str()
        );
        let identity = complete(&oidc, &transport, &pending, &redirect).unwrap();
        assert_eq!(identity.username, "alice");
        assert_eq!(identity.access_token.as_str(), "access-token-value");

        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1].method, "POST");
        assert_eq!(requests[1].url, "https://auth.example.test/token");
        assert_eq!(
            requests[1].headers,
            vec![(
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into()
            )]
        );
        assert!(String::from_utf8_lossy(&requests[1].body).contains("code_verifier="));
    }

    #[test]
    fn rejects_callback_state_before_token_exchange() {
        let oidc = oidc();
        let transport = MockTransport::default();
        transport.push_json(discovery());
        let pending = begin(&oidc, &transport).unwrap();
        let error = complete(
            &oidc,
            &transport,
            &pending,
            "com.example.app://oauth2redirect?code=x&state=wrong",
        )
        .unwrap_err();
        assert!(matches!(error, Error::Oidc(_)));
        assert_eq!(transport.requests.lock().unwrap().len(), 1);
    }
}
