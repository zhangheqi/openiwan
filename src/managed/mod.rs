mod controller;
mod http;
mod keepalive;
mod oidc;
mod provider;

pub use controller::{
    API_LOGIN_PATH, APP_LOGIN_PATH, AUTH_PATH, CONFIG_PATH, ControllerConfiguration, HEALTH_PATH,
    KEEPALIVE_RELOAD_PATH, LOGOS_PATH, LOOKUP_PATH, POSTURE_EVALUATE_PATH, POSTURE_RELOAD_PATH,
    SrEntry, SrIngress, SrPath, UPDATE_CHECK_PATH,
};
pub use http::{HttpRequest, HttpResponse, HttpTransport, UreqTransport};
pub use keepalive::{
    DeviceBinding, IwanActive, IwanMetrics, IwanMetricsTs, IwanServerMetric, IwanServerMetricTs,
    KeepaliveCredentials, KeepaliveRequest, KeepaliveResponse, PathMetrics, PathMetricsTs,
    PostureAck, PostureUpdate, SrActive, SrFullPathMetric, SrFullPathMetricTs, SrMetrics,
    SrMetricsTs, SrPathMetric, SrPathMetricTs, SrSiteMetric, SrSiteMetricTs, UserNotice,
    canonical_request, sign_request,
};
pub use oidc::{OidcIdentity, PendingAuthorization};
pub use provider::{ControllerConfig, OidcConfig, ProviderConfig};

use crate::Result;

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

    pub const fn provider(&self) -> &ProviderConfig {
        &self.provider
    }

    pub fn begin_authorization(&self) -> Result<PendingAuthorization> {
        let oidc = self
            .provider
            .oidc
            .as_ref()
            .ok_or_else(|| crate::Error::ManagedProvider("OIDC is not configured".into()))?;
        oidc::begin(oidc, &self.transport)
    }

    pub fn complete_authorization(
        &self,
        pending: &PendingAuthorization,
        redirect_url: &str,
    ) -> Result<OidcIdentity> {
        let oidc = self
            .provider
            .oidc
            .as_ref()
            .ok_or_else(|| crate::Error::ManagedProvider("OIDC is not configured".into()))?;
        oidc::complete(oidc, &self.transport, pending, redirect_url)
    }

    pub fn fetch_configuration(
        &self,
        identity: &OidcIdentity,
        device_id: &str,
        posture_version: Option<&str>,
    ) -> Result<ControllerConfiguration> {
        controller::fetch(
            &self.provider,
            &self.transport,
            Some(identity.access_token.as_str()),
            Some(&identity.username),
            device_id,
            posture_version,
        )
    }

    /// Fetch `/config` without assuming OIDC. The access-token header and
    /// `userName` member are omitted when their arguments are absent.
    pub fn fetch_configuration_raw(
        &self,
        access_token: Option<&str>,
        username: Option<&str>,
        device_id: &str,
        posture_version: Option<&str>,
    ) -> Result<ControllerConfiguration> {
        controller::fetch(
            &self.provider,
            &self.transport,
            access_token,
            username,
            device_id,
            posture_version,
        )
    }

    pub fn send_keepalive(
        &self,
        endpoint: &str,
        credentials: &KeepaliveCredentials,
        request: &KeepaliveRequest,
    ) -> Result<KeepaliveResponse> {
        keepalive::send(&self.transport, endpoint, credentials, request)
    }
}
