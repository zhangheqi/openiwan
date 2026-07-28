use crate::{Error, Result};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy)]
pub(crate) struct ApiCredentials {
    app_id: &'static str,
    app_secret: &'static str,
}

impl std::fmt::Debug for ApiCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApiCredentials")
            .field("app_id", &self.app_id)
            .field("app_secret", &"[REDACTED]")
            .finish()
    }
}

/// Return the lookup mobile-API credentials for the current client platform.
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub(crate) const fn platform_credentials() -> ApiCredentials {
    ApiCredentials {
        app_id: "mobile_windows",
        app_secret: "CX0QM39kk3Uw8ErpZN3yJhQp",
    }
}

/// Return the lookup mobile-API credentials for the current client platform.
#[cfg(target_os = "ios")]
pub(crate) const fn platform_credentials() -> ApiCredentials {
    ApiCredentials {
        app_id: "mobile_ios",
        app_secret: "QEaLgaP9AQHPxUju1NcZ01Mi",
    }
}

/// Return the lookup mobile-API credentials for the current client platform.
#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "ios")))]
pub(crate) const fn platform_credentials() -> ApiCredentials {
    ApiCredentials {
        app_id: "mobile_android",
        app_secret: "7fbJnRiEVWfBF68yjPpQpDeY",
    }
}

pub(crate) fn mobile_api_headers(
    method: &str,
    endpoint: &str,
    exact_body: &[u8],
) -> Result<Vec<(String, String)>> {
    let credentials = platform_credentials();
    authentication_headers(
        method,
        endpoint,
        exact_body,
        &timestamp_now()?,
        &random_nonce(),
        credentials,
    )
}

pub(crate) fn mobile_api_headers_with_credentials(
    method: &str,
    endpoint: &str,
    exact_body: &[u8],
    app_id: &str,
    app_secret: &str,
) -> Result<Vec<(String, String)>> {
    let timestamp = timestamp_now()?;
    let nonce = random_nonce();
    let signature = sign_http_request(
        method,
        endpoint,
        exact_body,
        &timestamp,
        &nonce,
        app_secret.as_bytes(),
    )?;
    Ok(vec![
        ("X-Auth-AppId".into(), app_id.into()),
        ("X-Auth-Timestamp".into(), timestamp),
        ("X-Auth-Nonce".into(), nonce),
        ("X-Auth-Sign".into(), signature),
    ])
}

pub(crate) fn controller_api_headers(
    method: &str,
    endpoint: &str,
    exact_body: &[u8],
    app_id: &str,
) -> Result<Vec<(String, String)>> {
    let secret = controller_secret(app_id)?;
    mobile_api_headers_with_credentials(method, endpoint, exact_body, app_id, &secret)
}

pub(crate) fn authentication_headers(
    method: &str,
    endpoint: &str,
    exact_body: &[u8],
    timestamp: &str,
    nonce: &str,
    credentials: ApiCredentials,
) -> Result<Vec<(String, String)>> {
    let signature = sign_http_request(
        method,
        endpoint,
        exact_body,
        timestamp,
        nonce,
        credentials.app_secret.as_bytes(),
    )?;
    Ok(vec![
        ("X-Auth-AppId".into(), credentials.app_id.into()),
        ("X-Auth-Timestamp".into(), timestamp.into()),
        ("X-Auth-Nonce".into(), nonce.into()),
        ("X-Auth-Sign".into(), signature),
    ])
}

pub(crate) fn sign_http_request(
    method: &str,
    endpoint: &str,
    exact_body: &[u8],
    timestamp: &str,
    nonce: &str,
    app_secret: &[u8],
) -> Result<String> {
    let canonical = canonical_http_request(method, endpoint, exact_body, timestamp, nonce)?;
    let mut mac = HmacSha256::new_from_slice(app_secret)
        .map_err(|_| Error::Crypto("invalid mobile API HMAC key"))?;
    mac.update(canonical.as_bytes());
    Ok(hex_lower(&mac.finalize().into_bytes()))
}

pub(crate) fn canonical_http_request(
    method: &str,
    endpoint: &str,
    exact_body: &[u8],
    timestamp: &str,
    nonce: &str,
) -> Result<String> {
    if method.is_empty() || !method.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(Error::Controller(
            "mobile API method must be non-empty uppercase ASCII".into(),
        ));
    }
    let url = Url::parse(endpoint)
        .map_err(|error| Error::Controller(format!("invalid mobile API URL: {error}")))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Controller(
            "mobile API URL must be HTTPS without credentials or a fragment".into(),
        ));
    }
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
        "{method}\n{path}\n{canonical_query}\n{}\n{timestamp}\n{nonce}",
        hex_lower(&Sha256::digest(exact_body))
    ))
}

pub(crate) fn controller_secret(app_id: &str) -> Result<String> {
    const FALLBACK_SECRET: &str = "def456_secret_for_android";
    const PANABIT_SECRET: &str = "lPrdS0GtGQShkK5MAc1zMAks";
    const DERIVATION_SALT: &str = "panabit_saas_secret_salt_v1_2025";

    if app_id.is_empty() {
        return Err(Error::Controller(
            "controller lookup has an empty app_id".into(),
        ));
    }
    if matches!(app_id, "saas-panabit" | "saas-unisase") {
        return Ok(FALLBACK_SECRET.into());
    }
    if app_id.contains("panabit") {
        return Ok(PANABIT_SECRET.into());
    }

    let mut mac = HmacSha256::new_from_slice(DERIVATION_SALT.as_bytes())
        .map_err(|_| Error::Crypto("invalid controller secret derivation key"))?;
    mac.update(app_id.as_bytes());
    let derived = hex_lower(&mac.finalize().into_bytes());
    Ok(derived[..24].to_owned())
}

pub(crate) fn timestamp_now() -> Result<String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Controller("system clock is before the Unix epoch".into()))?
        .as_secs()
        .to_string())
}

pub(crate) fn random_nonce() -> String {
    let mut bytes = [0_u8; 16];
    rand::fill(&mut bytes);
    hex_lower(&bytes)
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

    #[test]
    fn canonical_request_supports_get_and_post() {
        assert_eq!(
            canonical_http_request(
                "GET",
                "https://controller.example/auth/example",
                &[],
                "1700000000",
                "000102030405060708090a0b0c0d0e0f",
            )
            .unwrap(),
            "GET\n/auth/example\n\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
             1700000000\n000102030405060708090a0b0c0d0e0f"
        );
        assert_eq!(
            canonical_http_request(
                "POST",
                "https://controller.example/keepalive?b=two&a=one%20x&a=ignored&plus=a+b",
                br#"{"x":1}"#,
                "1700000000",
                "000102030405060708090a0b0c0d0e0f",
            )
            .unwrap(),
            "POST\n/keepalive\na=one x&b=two&plus=a b\n\
             5041bf1f713df204784353e82f6a4a535931cb64f1f4b4a5aeaffcb720918b22\n\
             1700000000\n000102030405060708090a0b0c0d0e0f"
        );
    }

    #[test]
    fn controller_secret_follows_app_id_selector() {
        assert_eq!(
            controller_secret("saas-panabit").unwrap(),
            "def456_secret_for_android"
        );
        assert_eq!(
            controller_secret("saas-unisase").unwrap(),
            "def456_secret_for_android"
        );
        assert_eq!(
            controller_secret("vendor-panabit-controller").unwrap(),
            "lPrdS0GtGQShkK5MAc1zMAks"
        );
        let first = controller_secret("controller-example").unwrap();
        let second = controller_secret("controller-example").unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 24);
        assert!(controller_secret("").is_err());
    }

    #[test]
    fn platform_credentials_are_redacted() {
        let credentials = platform_credentials();
        let debug = format!("{credentials:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(credentials.app_secret));
        assert!(credentials.app_id.starts_with("mobile_"));
    }
}
