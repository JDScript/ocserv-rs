//! Authentication provider abstraction
//!
//! Provides a trait-based authentication system that supports multiple
//! auth methods (password, SSO, etc.) with dynamic selection based on config.

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::sync::Arc;

use crate::auth::sso::oauth2::OAuth2Provider;
use crate::auth::sso::saml::SamlProvider;
use crate::auth::sso::SsoProvider;
use crate::auth::UserInfo;
use crate::config::{AuthConfig, UserConfig};

/// Authentication request types
#[derive(Debug, Clone)]
pub enum AuthRequest {
    /// Username/password authentication
    Password { username: String, password: String },
    /// SSO token authentication
    SsoToken { token: String },
}

/// Password-based authentication provider
pub struct PasswordAuthProvider {
    enabled: bool,
    users: HashMap<String, String>,
}

impl PasswordAuthProvider {
    pub fn new(user_configs: Vec<UserConfig>) -> Self {
        let mut users = HashMap::new();
        for user in user_configs {
            users.insert(user.username, user.password);
        }
        Self {
            enabled: true,
            users,
        }
    }

    pub fn with_enabled(user_configs: Vec<UserConfig>, enabled: bool) -> Self {
        let mut provider = Self::new(user_configs);
        provider.enabled = enabled;
        provider
    }

    pub fn name(&self) -> &'static str {
        "password"
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn authenticate(&self, request: &AuthRequest) -> Result<UserInfo> {
        match request {
            AuthRequest::Password { username, password } => match self.users.get(username) {
                Some(stored_password) if stored_password == password => Ok(UserInfo {
                    username: username.clone(),
                    groups: vec![],
                    attributes: HashMap::new(),
                }),
                Some(_) => bail!("Invalid password"),
                None => bail!("User not found"),
            },
            _ => bail!("Password provider does not handle this request type"),
        }
    }
}

/// Authentication manager that coordinates multiple providers
pub struct AuthManager {
    password_provider: Option<PasswordAuthProvider>,
    sso_provider: Option<Arc<dyn SsoProvider>>,
}

impl AuthManager {
    /// Create an AuthManager from configuration
    pub fn from_config(config: &AuthConfig) -> Self {
        let password_provider = if config.password.enabled {
            Some(PasswordAuthProvider::new(config.password.users.clone()))
        } else {
            None
        };

        // SAML and OAuth2 are mutually exclusive
        let sso_provider: Option<Arc<dyn SsoProvider>> = if config.saml.enabled {
            Some(Arc::new(SamlProvider::new(config.saml.clone())))
        } else if config.oauth2.enabled {
            Some(Arc::new(OAuth2Provider::new(config.oauth2.clone())))
        } else {
            None
        };

        Self {
            password_provider,
            sso_provider,
        }
    }

    /// Get the active SSO provider (if any)
    pub fn sso_provider(&self) -> Option<&Arc<dyn SsoProvider>> {
        self.sso_provider.as_ref()
    }

    /// Check if any provider is enabled for the given request type
    pub fn has_provider_for(&self, request: &AuthRequest) -> bool {
        match request {
            AuthRequest::Password { .. } => self
                .password_provider
                .as_ref()
                .map_or(false, |p| p.is_enabled()),
            AuthRequest::SsoToken { .. } => {
                self.sso_provider.as_ref().map_or(false, |p| p.is_enabled())
            }
        }
    }

    /// Attempt authentication using password provider
    pub fn authenticate(&self, request: &AuthRequest) -> Result<UserInfo> {
        match request {
            AuthRequest::Password { .. } => {
                if let Some(ref provider) = self.password_provider {
                    if provider.is_enabled() {
                        return provider.authenticate(request);
                    }
                }
                bail!("Password authentication not enabled")
            }
            AuthRequest::SsoToken { .. } => {
                // SSO token validation is handled at the handler level
                // because it requires access to SessionManager
                bail!("SSO token requires session manager validation")
            }
        }
    }

    /// Check if SSO is enabled
    pub fn is_sso_enabled(&self) -> bool {
        self.sso_provider.as_ref().map_or(false, |p| p.is_enabled())
    }

    /// Check if password auth is enabled
    pub fn is_password_enabled(&self) -> bool {
        self.password_provider
            .as_ref()
            .map_or(false, |p| p.is_enabled())
    }
}
