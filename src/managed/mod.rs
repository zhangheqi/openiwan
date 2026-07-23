mod controller;
mod crypto;
mod http;
mod oidc;
mod provider;
mod store;

pub use http::{HttpRequest, HttpResponse, HttpTransport, UreqTransport};
pub use oidc::PendingAuthorization;
pub use provider::{
    ControllerConfig, OidcConfig, PROVIDER_VERSION, ProviderConfig, TokenRequestFormat,
};
pub use store::{
    ManagedServer, ManagedState, STATE_VERSION, default_state_path, load_state, new_device_id,
    save_state,
};

use crate::{Client, ClientConfig, Error, Result};

pub struct ManagedClient<T = UreqTransport> {
    provider: ProviderConfig,
    transport: T,
}

impl ManagedClient<UreqTransport> {
    pub fn new(provider: ProviderConfig) -> Self {
        Self {
            provider,
            transport: UreqTransport::new(),
        }
    }
}

impl<T: HttpTransport> ManagedClient<T> {
    pub fn with_transport(provider: ProviderConfig, transport: T) -> Self {
        Self {
            provider,
            transport,
        }
    }

    pub fn provider(&self) -> &ProviderConfig {
        &self.provider
    }

    pub fn begin_authorization(&self) -> Result<PendingAuthorization> {
        oidc::begin(&self.provider, &self.transport)
    }

    pub fn fetch(
        &self,
        pending: &PendingAuthorization,
        redirect_url: &str,
        device_id: &str,
    ) -> Result<ManagedState> {
        if device_id.is_empty() {
            return Err(Error::ManagedProvider("device id must not be empty".into()));
        }
        let identity = oidc::complete(&self.provider, &self.transport, pending, redirect_url)?;
        controller::fetch(&self.provider, &self.transport, &identity, device_id)
    }

    pub fn build_client(
        &self,
        state: &ManagedState,
        server: &ManagedServer,
        mut config: ClientConfig,
    ) -> Result<Client> {
        state.validate_for(&self.provider.id, &self.provider.controller.domain)?;
        if !state.servers.iter().any(|candidate| candidate == server) {
            return Err(Error::ManagedProvider(
                "selected line is not present in managed state".into(),
            ));
        }
        config.server = server.endpoint();
        config.require_auth_verify_echo = self.provider.require_auth_verify_echo;
        config.xor_key_bytes = self.provider.xor_key_bytes;
        let password = crypto::decrypt_server_password(&self.provider, server)?;
        Client::new(config, server.username.clone(), password.to_string())
    }
}

pub fn select_server<'a>(
    state: &'a ManagedState,
    index: Option<usize>,
    name: Option<&str>,
) -> Result<Option<&'a ManagedServer>> {
    if index.is_some() && name.is_some() {
        return Err(Error::ManagedProvider(
            "line index and line name are mutually exclusive".into(),
        ));
    }
    if let Some(index) = index {
        if index == 0 || index > state.servers.len() {
            return Err(Error::ManagedProvider(format!(
                "line index must be between 1 and {}",
                state.servers.len()
            )));
        }
        return Ok(Some(&state.servers[index - 1]));
    }
    if let Some(name) = name {
        let matches: Vec<_> = state
            .servers
            .iter()
            .filter(|server| server.name == name)
            .collect();
        return match matches.as_slice() {
            [server] => Ok(Some(*server)),
            [] => Err(Error::ManagedProvider(format!("no line is named {name:?}"))),
            _ => Err(Error::ManagedProvider(format!(
                "multiple lines are named {name:?}; use --line-index"
            ))),
        };
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_by_one_based_index_or_unique_name() {
        let state = ManagedState {
            version: STATE_VERSION,
            provider_id: "test".into(),
            domain: "test".into(),
            device_id: "device".into(),
            fetched_at_unix: 0,
            servers: vec![
                ManagedServer {
                    name: "A".into(),
                    host: "192.0.2.1".into(),
                    port: 6001,
                    username: "a".into(),
                    encrypted_password: "x".into(),
                },
                ManagedServer {
                    name: "B".into(),
                    host: "192.0.2.2".into(),
                    port: 6002,
                    username: "b".into(),
                    encrypted_password: "y".into(),
                },
            ],
        };
        assert_eq!(
            select_server(&state, Some(2), None).unwrap().unwrap().name,
            "B"
        );
        assert_eq!(
            select_server(&state, None, Some("A"))
                .unwrap()
                .unwrap()
                .host,
            "192.0.2.1"
        );
        assert!(select_server(&state, Some(0), None).is_err());
    }
}
