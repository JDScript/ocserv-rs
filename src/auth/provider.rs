//! Authentication provider abstraction
//!
//! Provides a trait-based authentication system that supports multiple
//! auth methods (password, SSO, etc.) with dynamic selection based on config.

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::sync::Arc;

use crate::auth::UserInfo;
use crate::config::{AuthConfig, SamlAuthConfig, UserConfig};

/// Authentication request types
#[derive(Debug, Clone)]
pub enum AuthRequest {
    /// Username/password authentication
    Password { username: String, password: String },
    /// SSO token authentication
    SsoToken { token: String },
}

/// Authentication provider trait
///
/// Implement this trait for each authentication method you want to support.
pub trait AuthProvider: Send + Sync {
    /// Returns the name of this authentication provider
    fn name(&self) -> &'static str;

    /// Check if this provider is enabled
    fn is_enabled(&self) -> bool;

    /// Attempt to authenticate using this provider
    /// Returns UserInfo on success, error on failure
    fn authenticate(&self, request: &AuthRequest) -> Result<UserInfo>;
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
}

impl AuthProvider for PasswordAuthProvider {
    fn name(&self) -> &'static str {
        "password"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn authenticate(&self, request: &AuthRequest) -> Result<UserInfo> {
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

/// SSO token authentication provider
///
/// This provider validates SSO tokens against the session manager.
/// NOTE: This is a placeholder - actual SSO token validation requires
/// access to the session manager which is handled separately in handlers.
pub struct SsoAuthProvider {
    enabled: bool,
    #[allow(dead_code)]
    config: SamlAuthConfig,
}

impl SsoAuthProvider {
    pub fn new(config: SamlAuthConfig) -> Self {
        let enabled = config.enabled;
        Self { enabled, config }
    }
}

impl AuthProvider for SsoAuthProvider {
    fn name(&self) -> &'static str {
        "sso"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn authenticate(&self, request: &AuthRequest) -> Result<UserInfo> {
        match request {
            AuthRequest::SsoToken { token } => {
                // SSO token validation is handled at the handler level
                // because it requires access to SessionManager.
                // This provider just signals that SSO is enabled.
                bail!("SSO token '{}' requires session manager validation", token)
            }
            _ => bail!("SSO provider does not handle this request type"),
        }
    }
}

/// Authentication manager that coordinates multiple providers
pub struct AuthManager {
    providers: Vec<Arc<dyn AuthProvider>>,
}

impl AuthManager {
    /// Create an AuthManager from configuration
    pub fn from_config(config: &AuthConfig) -> Self {
        let mut providers: Vec<Arc<dyn AuthProvider>> = Vec::new();

        if config.password.enabled {
            providers.push(Arc::new(PasswordAuthProvider::new(
                config.password.users.clone(),
            )));
        }

        if config.saml.enabled {
            providers.push(Arc::new(SsoAuthProvider::new(config.saml.clone())));
        }

        Self { providers }
    }

    /// Check if any provider is enabled for the given request type
    pub fn has_provider_for(&self, request: &AuthRequest) -> bool {
        match request {
            AuthRequest::Password { .. } => self
                .providers
                .iter()
                .any(|p| p.name() == "password" && p.is_enabled()),
            AuthRequest::SsoToken { .. } => self
                .providers
                .iter()
                .any(|p| p.name() == "sso" && p.is_enabled()),
        }
    }

    /// Attempt authentication using all enabled providers
    /// Returns the first successful result
    pub fn authenticate(&self, request: &AuthRequest) -> Result<UserInfo> {
        for provider in &self.providers {
            if provider.is_enabled() {
                match provider.authenticate(request) {
                    Ok(user) => return Ok(user),
                    Err(_) => continue, // Try next provider
                }
            }
        }
        bail!("No provider could authenticate this request")
    }

    /// Check if SSO is enabled
    pub fn is_sso_enabled(&self) -> bool {
        self.providers
            .iter()
            .any(|p| p.name() == "sso" && p.is_enabled())
    }

    /// Check if password auth is enabled
    pub fn is_password_enabled(&self) -> bool {
        self.providers
            .iter()
            .any(|p| p.name() == "password" && p.is_enabled())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PasswordAuthConfig, UserConfig};

    #[test]
    fn test_password_provider_success() {
        let users = vec![UserConfig {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        }];
        let provider = PasswordAuthProvider::new(users);

        let request = AuthRequest::Password {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        let result = provider.authenticate(&request);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().username, "testuser");
    }

    #[test]
    fn test_password_provider_invalid_password() {
        let users = vec![UserConfig {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        }];
        let provider = PasswordAuthProvider::new(users);

        let request = AuthRequest::Password {
            username: "testuser".to_string(),
            password: "wrongpass".to_string(),
        };

        let result = provider.authenticate(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_auth_manager_from_config() {
        let config = AuthConfig {
            banner: Some("Test".to_string()),
            password: PasswordAuthConfig {
                enabled: true,
                users: vec![UserConfig {
                    username: "admin".to_string(),
                    password: "admin".to_string(),
                }],
            },
            saml: SamlAuthConfig::default(),
        };

        let manager = AuthManager::from_config(&config);
        assert!(manager.is_password_enabled());
        assert!(!manager.is_sso_enabled());

        let request = AuthRequest::Password {
            username: "admin".to_string(),
            password: "admin".to_string(),
        };

        let result = manager.authenticate(&request);
        assert!(result.is_ok());
    }
}
