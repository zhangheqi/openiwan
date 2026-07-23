use crate::{Error, Result};
use serde::Deserialize;
use std::fmt;
use std::fs;
use std::path::Path;
use url::Url;
use zeroize::Zeroize;

pub const PROVIDER_VERSION: u32 = 1;

const fn default_xor_key_bytes() -> u8 {
    8
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TokenRequestFormat {
    #[default]
    Json,
    Form,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub username_claims: Vec<String>,
    #[serde(default)]
    pub token_request_format: TokenRequestFormat,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerConfig {
    pub base_url: String,
    pub domain: String,
    pub app_id: String,
    pub app_secret: String,
    pub auth_path: String,
    pub keepalive_path: String,
    pub config_path: String,
    pub device_type: String,
    pub oem_name: String,
}

impl fmt::Debug for ControllerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerConfig")
            .field("base_url", &self.base_url)
            .field("domain", &self.domain)
            .field("app_id", &self.app_id)
            .field("app_secret", &"[REDACTED]")
            .field("auth_path", &self.auth_path)
            .field("keepalive_path", &self.keepalive_path)
            .field("config_path", &self.config_path)
            .field("device_type", &self.device_type)
            .field("oem_name", &self.oem_name)
            .finish()
    }
}

impl Drop for ControllerConfig {
    fn drop(&mut self) {
        self.app_secret.zeroize();
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub version: u32,
    pub id: String,
    pub display_name: String,
    #[serde(default)]
    pub require_auth_verify_echo: bool,
    #[serde(default = "default_xor_key_bytes")]
    pub xor_key_bytes: u8,
    pub oidc: OidcConfig,
    pub controller: ControllerConfig,
}

impl ProviderConfig {
    pub fn load(path: &Path) -> Result<Self> {
        validate_secret_file(path)?;
        let mut contents = fs::read_to_string(path)?;
        let provider = toml::from_str(&contents)
            .map_err(|error| Error::ManagedProvider(format!("{}: {error}", path.display())));
        contents.zeroize();
        let provider: Self = provider?;
        provider.validate()?;
        Ok(provider)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != PROVIDER_VERSION {
            return Err(Error::ManagedProvider(format!(
                "unsupported provider version {}; expected {PROVIDER_VERSION}",
                self.version
            )));
        }
        if self.id.is_empty()
            || self.id.len() > 64
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(Error::ManagedProvider(
                "provider id must contain 1..=64 ASCII letters, digits, '-' or '_'".into(),
            ));
        }
        require_nonempty("display_name", &self.display_name)?;
        if !matches!(self.xor_key_bytes, 8 | 16) {
            return Err(Error::ManagedProvider(
                "xor_key_bytes must be either 8 or 16".into(),
            ));
        }
        require_nonempty("oidc.client_id", &self.oidc.client_id)?;
        if !self.oidc.scopes.iter().any(|scope| scope == "openid") {
            return Err(Error::ManagedProvider(
                "oidc.scopes must include \"openid\"".into(),
            ));
        }
        if self.oidc.username_claims.is_empty()
            || self
                .oidc
                .username_claims
                .iter()
                .any(|claim| claim.trim().is_empty())
        {
            return Err(Error::ManagedProvider(
                "oidc.username_claims must contain at least one non-empty claim".into(),
            ));
        }

        validate_https_url("oidc.issuer", &self.oidc.issuer)?;
        let redirect = Url::parse(&self.oidc.redirect_uri).map_err(|error| {
            Error::ManagedProvider(format!("invalid oidc.redirect_uri: {error}"))
        })?;
        if redirect.scheme().is_empty()
            || redirect.query().is_some()
            || redirect.fragment().is_some()
        {
            return Err(Error::ManagedProvider(
                "oidc.redirect_uri must have a scheme and no query or fragment".into(),
            ));
        }

        validate_https_url("controller.base_url", &self.controller.base_url)?;
        for (name, value) in [
            ("controller.domain", self.controller.domain.as_str()),
            ("controller.app_id", self.controller.app_id.as_str()),
            ("controller.app_secret", self.controller.app_secret.as_str()),
            (
                "controller.device_type",
                self.controller.device_type.as_str(),
            ),
            ("controller.oem_name", self.controller.oem_name.as_str()),
        ] {
            require_nonempty(name, value)?;
        }
        for (name, path) in [
            ("controller.auth_path", self.controller.auth_path.as_str()),
            (
                "controller.keepalive_path",
                self.controller.keepalive_path.as_str(),
            ),
            (
                "controller.config_path",
                self.controller.config_path.as_str(),
            ),
        ] {
            validate_controller_path(name, path)?;
        }
        Ok(())
    }
}

fn require_nonempty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::ManagedProvider(format!("{name} must not be empty")));
    }
    Ok(())
}

fn validate_https_url(name: &str, value: &str) -> Result<()> {
    let url = Url::parse(value)
        .map_err(|error| Error::ManagedProvider(format!("invalid {name}: {error}")))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::ManagedProvider(format!(
            "{name} must be an HTTPS URL without credentials, query, or fragment"
        )));
    }
    Ok(())
}

fn validate_controller_path(name: &str, value: &str) -> Result<()> {
    if !value.starts_with('/') || value.contains(['?', '#', '\n', '\r']) {
        return Err(Error::ManagedProvider(format!(
            "{name} must be an absolute URL path without query or fragment"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_secret_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(Error::ManagedProvider(format!(
            "{} contains an app secret and must not be accessible by group or other users",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secret_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> ProviderConfig {
        ProviderConfig {
            version: PROVIDER_VERSION,
            id: "example-1".into(),
            display_name: "Example".into(),
            require_auth_verify_echo: false,
            xor_key_bytes: 16,
            oidc: OidcConfig {
                issuer: "https://auth.example.test".into(),
                client_id: "client".into(),
                redirect_uri: "com.example.app://oauth2redirect".into(),
                scopes: vec!["openid".into(), "profile".into()],
                username_claims: vec!["preferred_username".into(), "sub".into()],
                token_request_format: TokenRequestFormat::Json,
            },
            controller: ControllerConfig {
                base_url: "https://controller.example.test".into(),
                domain: "iwan.example".into(),
                app_id: "controller-example".into(),
                app_secret: "test-secret".into(),
                auth_path: "/m/auth".into(),
                keepalive_path: "/m/keepalive".into(),
                config_path: "/m/config".into(),
                device_type: "android".into(),
                oem_name: "panabit".into(),
            },
        }
    }

    #[test]
    fn validates_provider_shape() {
        provider().validate().unwrap();
        let mut invalid = provider();
        invalid.id = "../escape".into();
        assert!(invalid.validate().is_err());
        let mut insecure = provider();
        insecure.oidc.issuer = "http://auth.example.test".into();
        assert!(insecure.validate().is_err());
    }

    #[test]
    fn bundled_ustc_example_is_valid() {
        let provider: ProviderConfig =
            toml::from_str(include_str!("../../examples/providers/ustc.toml")).unwrap();
        provider.validate().unwrap();
        assert_eq!(provider.id, "ustc");
        assert_eq!(provider.xor_key_bytes, 8);
    }

    #[test]
    fn managed_provider_defaults_to_eight_byte_xor_compatibility() {
        let without_width = include_str!("../../examples/providers/ustc.toml")
            .lines()
            .filter(|line| !line.starts_with("xor_key_bytes"))
            .collect::<Vec<_>>()
            .join("\n");
        let parsed: ProviderConfig = toml::from_str(&without_width).unwrap();
        assert_eq!(parsed.xor_key_bytes, 8);
    }

    #[cfg(unix)]
    #[test]
    fn provider_file_must_be_private() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "openiwan-provider-test-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("thread")
        ));
        let contents = r#"
version = 1
id = "test"
display_name = "Test"
[oidc]
issuer = "https://auth.example.test"
client_id = "client"
redirect_uri = "com.example://callback"
scopes = ["openid"]
username_claims = ["sub"]
token_request_format = "json"
[controller]
base_url = "https://controller.example.test"
domain = "iwan.example"
app_id = "app"
app_secret = "secret"
auth_path = "/m/auth"
keepalive_path = "/m/keepalive"
config_path = "/m/config"
device_type = "android"
oem_name = "panabit"
"#;
        fs::write(&path, contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ProviderConfig::load(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(ProviderConfig::load(&path).unwrap().id, "test");
        fs::remove_file(path).unwrap();
    }
}
