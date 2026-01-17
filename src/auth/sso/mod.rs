use crate::http::handlers::ServerState;
use crate::http::manual_http::{HttpRequest, HttpResponse};
use std::sync::Arc;

pub mod oauth2;
pub mod saml;

/// Route definition for SSO providers
#[derive(Debug, Clone)]
pub struct SsoRoute {
    pub method: &'static str,
    pub path: &'static str,
}

/// SSO Provider trait for abstracting SAML/OIDC authentication
pub trait SsoProvider: Send + Sync {
    /// Provider name (e.g., "saml", "oauth2")
    fn name(&self) -> &'static str;

    /// Whether this provider is enabled
    fn is_enabled(&self) -> bool;

    /// Routes this provider handles
    fn routes(&self) -> Vec<SsoRoute>;

    /// URL to initiate SSO login (shown in XML to client)
    fn login_url(&self, base_url: &str, ctx: Option<&str>) -> String;

    /// URL for final page after IdP callback
    fn final_url(&self, base_url: &str) -> String;

    /// Handle an SSO request - provider decides based on path
    fn handle(&self, req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse;
}
