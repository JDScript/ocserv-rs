use serde::{Deserialize, Serialize};

/// Main config-auth XML structure
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename = "config-auth")]
pub struct ConfigAuth {
    #[serde(rename = "@client")]
    pub client: String,

    #[serde(rename = "@type")]
    pub auth_type: ConfigAuthType,

    #[serde(
        rename = "@aggregate-auth-version",
        skip_serializing_if = "Option::is_none"
    )]
    pub aggregate_auth_version: Option<u8>,

    #[serde(default)]
    pub version: Vec<Version>,

    #[serde(default)]
    pub auth: Vec<Auth>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub opaque: Option<Opaque>,

    #[serde(rename = "device-id", skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,

    #[serde(rename = "session-id", skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    #[serde(rename = "session-token", skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<Config>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigAuthType {
    Init,
    AuthRequest,
    AuthReply,
    Complete,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Version {
    #[serde(rename = "@who")]
    pub who: String,

    #[serde(rename = "$text")]
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Opaque {
    #[serde(rename = "@is-for")]
    pub is_for: String,

    #[serde(rename = "tunnel-group", skip_serializing_if = "Option::is_none")]
    pub tunnel_group: Option<String>,

    #[serde(rename = "aggauth-handle", skip_serializing_if = "Option::is_none")]
    pub aggauth_handle: Option<String>,

    #[serde(rename = "auth-method", default)]
    pub auth_methods: Vec<String>,

    #[serde(rename = "config-hash", skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Auth {
    #[serde(rename = "@id", skip_serializing_if = "Option::is_none", default)]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,

    // SAML-specific fields
    #[serde(rename = "sso-v2-login", skip_serializing_if = "Option::is_none")]
    pub sso_v2_login: Option<String>,

    #[serde(rename = "sso-v2-login-final", skip_serializing_if = "Option::is_none")]
    pub sso_v2_login_final: Option<String>,

    #[serde(rename = "sso-v2-logout", skip_serializing_if = "Option::is_none")]
    pub sso_v2_logout: Option<String>,

    #[serde(
        rename = "sso-v2-browser-mode",
        skip_serializing_if = "Option::is_none"
    )]
    pub sso_v2_browser_mode: Option<String>,

    #[serde(
        rename = "sso-v2-token-cookie-name",
        skip_serializing_if = "Option::is_none"
    )]
    pub sso_v2_token_cookie_name: Option<String>,

    #[serde(
        rename = "sso-v2-error-cookie-name",
        skip_serializing_if = "Option::is_none"
    )]
    pub sso_v2_error_cookie_name: Option<String>,

    #[serde(default)]
    pub form: Vec<Form>,

    #[serde(rename = "sso-token", skip_serializing_if = "Option::is_none")]
    pub sso_token: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Form {
    #[serde(rename = "@action", skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,

    #[serde(rename = "@method", skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    #[serde(default)]
    pub input: Vec<Input>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub select: Option<Select>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Input {
    #[serde(rename = "@type")]
    pub input_type: String,

    #[serde(rename = "@name")]
    pub name: String,

    #[serde(rename = "@label", skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Select {
    #[serde(rename = "@label", skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    #[serde(rename = "@name")]
    pub name: String,

    #[serde(default)]
    pub option: Vec<SelectOption>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SelectOption {
    #[serde(rename = "@value")]
    pub value: String,

    #[serde(rename = "$text")]
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Config {
    #[serde(rename = "@client")]
    pub client: String,

    #[serde(rename = "@type")]
    pub config_type: String,
    // Will be extended with VPN configuration elements later
}

/// Client capabilities
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Capabilities {
    #[serde(rename = "auth-method", default)]
    pub auth_methods: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_init() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <config-auth client="vpn" type="init">
            <version who="vpn">v5.01</version>
        </config-auth>"#;

        let config: ConfigAuth = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(config.client, "vpn");
        assert_eq!(config.auth_type, ConfigAuthType::Init);
        assert_eq!(config.version.len(), 1);
    }

    #[test]
    fn test_serialize_auth_request_saml() {
        let config = ConfigAuth {
            client: "vpn".to_string(),
            auth_type: ConfigAuthType::AuthRequest,
            aggregate_auth_version: Some(2),
            opaque: Some(Opaque {
                is_for: "sg".to_string(),
                tunnel_group: Some("test-group".to_string()),
                aggauth_handle: Some("12345".to_string()),
                auth_methods: vec![
                    "single-sign-on-v2".to_string(),
                    "single-sign-on-external-browser".to_string(),
                ],
                config_hash: None,
            }),
            auth: vec![Auth {
                id: Some("main".to_string()),
                title: Some("Login".to_string()),
                message: Some("Please authenticate".to_string()),
                sso_v2_login: Some("https://example.com/saml/login".to_string()),
                sso_v2_browser_mode: Some("external".to_string()),
                sso_v2_token_cookie_name: Some("acSamlv2Token".to_string()),
                sso_v2_error_cookie_name: Some("acSamlv2Error".to_string()),
                form: vec![Form {
                    action: None,
                    method: None,
                    input: vec![Input {
                        input_type: "sso".to_string(),
                        name: "sso-token".to_string(),
                        label: None,
                    }],
                    select: None,
                }],
                ..Default::default()
            }],
            version: vec![],
            device_id: None,
            capabilities: None,
            session_id: None,
            session_token: None,
            config: None,
        };

        let xml = quick_xml::se::to_string(&config).unwrap();
        assert!(xml.contains("aggregate-auth-version=\"2\""));
        assert!(xml.contains("single-sign-on-v2"));
    }
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            id: None,
            title: None,
            message: None,
            banner: None,
            sso_v2_login: None,
            sso_v2_login_final: None,
            sso_v2_logout: None,
            sso_v2_browser_mode: None,
            sso_v2_token_cookie_name: None,
            sso_v2_error_cookie_name: None,
            form: vec![],
            sso_token: None,
            username: None,
            password: None,
        }
    }
}
