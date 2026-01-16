use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// Main configuration structure
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    /// Network Configuration (Phase 5)
    #[serde(default)]
    pub network: NetworkConfig,
}

/// Server configuration
#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    /// Listen address (e.g., "0.0.0.0:8443")
    pub listen: String,
    /// Path to TLS certificate
    pub cert_path: String,
    /// Path to TLS private key
    pub key_path: String,
}

/// Authentication configuration
#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    /// Banner message shown during authentication
    pub banner: Option<String>,
    /// Password authentication settings
    pub password: PasswordAuthConfig,
    /// SAML authentication settings (Phase 4)
    #[serde(default)]
    pub saml: SamlAuthConfig,
}

/// Password-based authentication configuration
#[derive(Debug, Deserialize, Clone)]
pub struct PasswordAuthConfig {
    /// Whether password auth is enabled
    pub enabled: bool,
    /// List of users (TODO: support password hashing in future)
    #[serde(default)]
    pub users: Vec<UserConfig>,
}

/// User configuration
#[derive(Debug, Deserialize, Clone)]
pub struct UserConfig {
    pub username: String,
    /// TODO: Support hashed passwords (bcrypt/argon2) in future
    pub password: String,
}

/// SAML/SSO authentication configuration (Phase 4)
#[derive(Debug, Deserialize, Clone, Default)]
pub struct SamlAuthConfig {
    /// Whether SAML auth is enabled
    #[serde(default)]
    pub enabled: bool,
    /// IdP metadata URL (e.g. https://shibboleth.nyu.edu/idp/profile/SAML2/Redirect/SSO)
    /// This is where we redirect the user for login
    pub idp_metadata_url: Option<String>,
    /// IdP Entity ID (for validating Issuer in SAMLResponse)
    pub idp_entity_id: Option<String>,
    /// SP Entity ID (our identifier, e.g. https://vpn.example.com/saml)
    pub sp_entity_id: Option<String>,
    /// SP ACS URL (where IdP posts back, e.g. https://vpn.example.com/+CSCOE+/saml/sp/acs)
    pub acs_url: Option<String>,

    /// Base URL for constructing absolute links (e.g. https://vpn.example.com)
    /// Required for correct AnyConnect behavior
    pub base_url: Option<String>,

    /// Development Mode: Enable built-in Mock IdP at /dev/idp
    #[serde(default)]
    pub dev_idp_enabled: bool,
}

/// Network Configuration (Phase 5)
#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    /// IPv4 Address Pool (CIDR)
    #[serde(default = "default_ipv4_pool")]
    pub ipv4_pool: String,
    /// IPv6 Address Pool (CIDR)
    pub ipv6_pool: Option<String>,
    /// DNS Servers
    #[serde(default = "default_dns_servers")]
    pub dns_servers: Vec<String>,
    /// Split Tunnel Routes
    #[serde(default)]
    pub split_include: Vec<String>,
    /// MTU
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            ipv4_pool: default_ipv4_pool(),
            ipv6_pool: None,
            dns_servers: default_dns_servers(),
            split_include: Vec::new(),
            mtu: default_mtu(),
        }
    }
}

fn default_ipv4_pool() -> String {
    "10.10.0.0/24".to_string()
}

fn default_dns_servers() -> Vec<String> {
    vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()]
}

fn default_mtu() -> u16 {
    1280
}

impl Config {
    /// Load configuration from TOML file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content =
            std::fs::read_to_string(path.as_ref()).context("Failed to read config file")?;
        let config: Config = toml::from_str(&content).context("Failed to parse config file")?;
        Ok(config)
    }

    /// Create default configuration for testing
    pub fn default() -> Self {
        Config {
            server: ServerConfig {
                listen: "0.0.0.0:8443".to_string(),
                cert_path: "server.crt".to_string(),
                key_path: "server.key".to_string(),
            },
            auth: AuthConfig {
                banner: Some("Welcome to VPN".to_string()),
                password: PasswordAuthConfig {
                    enabled: true,
                    users: vec![
                        UserConfig {
                            username: "test".to_string(),
                            password: "test".to_string(),
                        },
                        UserConfig {
                            username: "admin".to_string(),
                            password: "admin".to_string(),
                        },
                    ],
                },
                saml: SamlAuthConfig::default(),
            },
            network: NetworkConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server.listen, "0.0.0.0:8443");
        assert_eq!(config.auth.password.users.len(), 2);
    }

    #[test]
    fn test_parse_toml() {
        let toml = r#"
[server]
listen = "127.0.0.1:8443"
cert_path = "test.crt"
key_path = "test.key"

[auth]
banner = "Test Banner"

[auth.password]
enabled = true

[[auth.password.users]]
username = "user1"
password = "pass1"

[auth.saml]
enabled = false
idp_metadata_url = "https://mock-idp"
idp_entity_id = "mock-idp"
sp_entity_id = "my-vpn"
acs_url = "https://vpn/acs"
base_url = "https://vpn"
dev_idp_enabled = false
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.server.listen, "127.0.0.1:8443");
        assert_eq!(config.auth.banner.unwrap(), "Test Banner");
        assert_eq!(config.auth.password.users.len(), 1);
    }
}
