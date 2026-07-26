use crate::{Error, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub username_claim: String,
    pub organization: String,
    pub provider: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerConfig {
    pub base_url: String,
    pub domain: String,
    #[serde(rename = "type")]
    pub service_type: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
    pub controller: ControllerConfig,
}

impl ProviderConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        let provider = toml::from_str(&contents)
            .map_err(|error| Error::ManagedProvider(format!("{}: {error}", path.display())));
        let provider: Self = provider?;
        provider.validate()?;
        Ok(provider)
    }

    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("controller.domain", self.controller.domain.as_str()),
            (
                "controller.service_type",
                self.controller.service_type.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(Error::ManagedProvider(format!("{name} must not be empty")));
            }
        }
        validate_https_url("controller.base_url", &self.controller.base_url)?;
        if let Some(oidc) = &self.oidc {
            for (name, value) in [
                ("oidc.client_id", oidc.client_id.as_str()),
                ("oidc.redirect_uri", oidc.redirect_uri.as_str()),
                ("oidc.username_claim", oidc.username_claim.as_str()),
                ("oidc.organization", oidc.organization.as_str()),
                ("oidc.provider", oidc.provider.as_str()),
            ] {
                if value.trim().is_empty() {
                    return Err(Error::ManagedProvider(format!("{name} must not be empty")));
                }
            }
            if !oidc.scopes.iter().any(|scope| scope == "openid") {
                return Err(Error::ManagedProvider(
                    "oidc.scopes must include \"openid\"".into(),
                ));
            }
            validate_https_url("oidc.issuer", &oidc.issuer)?;
            let redirect = Url::parse(&oidc.redirect_uri).map_err(|error| {
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
        }
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_confirmed_provider_fields() {
        let provider: ProviderConfig = toml::from_str(
            r#"
[oidc]
issuer = "https://auth.example.test"
client_id = "client"
redirect_uri = "com.example://callback"
scopes = ["openid"]
username_claim = "sub"
organization = "example"
provider = "oidc"

[controller]
base_url = "https://controller.example.test"
domain = "iwan.example"
type = "device"
"#,
        )
        .unwrap();
        provider.validate().unwrap();
        assert!(provider.oidc.is_some());
    }

    #[test]
    fn raw_config_provider_does_not_require_oidc_or_keepalive_secrets() {
        let provider: ProviderConfig = toml::from_str(
            r#"
[controller]
base_url = "https://controller.example.test"
domain = "iwan.example"
type = "device"
"#,
        )
        .unwrap();
        provider.validate().unwrap();
        assert!(provider.oidc.is_none());
    }
}
