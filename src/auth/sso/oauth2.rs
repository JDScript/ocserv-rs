use crate::http::handlers::ServerState;
use crate::http::manual_http::{HttpRequest, HttpResponse};
use serde::Deserialize;
use std::sync::Arc;

/// OAuth2 configuration
#[derive(Debug, Deserialize, Clone)]
pub struct OAuth2Config {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    /// Full callback URL (e.g., https://vpn.example.com/+CSCOE+/oauth2/callback)
    #[serde(default)]
    pub redirect_uri: String,
    /// Authorization endpoint
    #[serde(default)]
    pub auth_url: String,
    /// Token endpoint
    #[serde(default)]
    pub token_url: String,
    /// OAuth2 scope (default: "openid profile email")
    pub scope: Option<String>,
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            enabled: false,
            client_id: String::new(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            auth_url: String::new(),
            token_url: String::new(),
            scope: None,
        }
    }
}

/// OAuth2 SSO Provider
pub struct OAuth2Provider {
    config: OAuth2Config,
}

impl OAuth2Provider {
    pub fn new(config: OAuth2Config) -> Self {
        Self { config }
    }

    fn handle_login(&self, ctx: Option<String>, _state: &Arc<ServerState>) -> HttpResponse {
        use crate::http::manual_http::HttpResponse;

        // Build OAuth2 authorization URL
        let scope = self
            .config
            .scope
            .as_deref()
            .unwrap_or("openid profile email");
        let state_param = ctx.unwrap_or_default();

        let auth_url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
            self.config.auth_url,
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(&self.config.redirect_uri),
            urlencoding::encode(scope),
            urlencoding::encode(&state_param),
        );

        HttpResponse::new(302, "Found")
            .header("Location", &auth_url)
            .body_str("")
    }

    fn handle_callback(&self, req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
        use crate::auth::UserInfo;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use std::collections::HashMap;
        use tracing::{error, info, warn};

        // Extract code and state from query params
        let query = req.path.split('?').nth(1).unwrap_or("");
        let params: HashMap<_, _> = url::form_urlencoded::parse(query.as_bytes()).collect();

        let code = match params.get("code") {
            Some(c) => c.to_string(),
            None => {
                warn!("OAuth2 callback missing code parameter");
                return HttpResponse::new(400, "Missing code parameter");
            }
        };

        let ctx_from_state = params.get("state").map(|s| s.to_string());

        info!(
            "OAuth2 callback: code={}..., state={:?}",
            &code[..code.len().min(10)],
            ctx_from_state
        );

        // Exchange code for token using reqwest blocking client
        let client = match reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true) // For dev/testing
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to create HTTP client: {}", e);
                return HttpResponse::new(500, "Internal error");
            }
        };

        let token_response = client
            .post(&self.config.token_url)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", &self.config.redirect_uri),
                ("client_id", &self.config.client_id),
                ("client_secret", &self.config.client_secret),
            ])
            .send();

        let token_data: serde_json::Value = match token_response {
            Ok(resp) => {
                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().unwrap_or_default();
                    error!("Token exchange failed: {} - {}", status, body);
                    return HttpResponse::new(401, "Token exchange failed");
                }
                match resp.json() {
                    Ok(j) => j,
                    Err(e) => {
                        error!("Failed to parse token response: {}", e);
                        return HttpResponse::new(500, "Token parse error");
                    }
                }
            }
            Err(e) => {
                error!("Token exchange request failed: {}", e);
                return HttpResponse::new(500, "Token exchange error");
            }
        };

        info!("Token exchange successful");

        // Extract username from ID token (JWT)
        let username = token_data
            .get("id_token")
            .and_then(|t| t.as_str())
            .and_then(|jwt| {
                // JWT format: header.payload.signature
                let parts: Vec<&str> = jwt.split('.').collect();
                if parts.len() >= 2 {
                    // Decode payload (2nd part)
                    URL_SAFE_NO_PAD
                        .decode(parts[1])
                        .ok()
                        .and_then(|bytes| String::from_utf8(bytes).ok())
                        .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
                        .and_then(|claims| {
                            // Try preferred_username, then upn, then email, then sub
                            claims
                                .get("preferred_username")
                                .or_else(|| claims.get("upn"))
                                .or_else(|| claims.get("email"))
                                .or_else(|| claims.get("sub"))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string())
                        })
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "oauth2_user".to_string());

        info!("Authenticated user: {}", username);

        let user_info = UserInfo {
            username: username.clone(),
            groups: vec!["oauth2_users".to_string()],
            attributes: HashMap::new(),
        };

        // Get HPKE context ID from state parameter
        let hpke_ctx_id = ctx_from_state.as_ref().and_then(|s| {
            url::form_urlencoded::parse(s.as_bytes())
                .find(|(k, _)| k == "ctx")
                .map(|(_, v)| v.to_string())
        });

        let session = state.session_manager.create_session(user_info, hpke_ctx_id);
        info!("Created session for user: {}", username);

        HttpResponse::new(302, "Found")
            .header("Location", "/+CSCOE+/oauth2_login.html")
            .header(
                "Set-Cookie",
                &format!(
                    "acSamlv2Token={}; path=/; Secure; HttpOnly",
                    session.session_token
                ),
            )
            .body_str("")
    }

    fn handle_success(&self, req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
        use crate::protocol::xml::render_template;
        use serde_json::json;
        use tracing::{info, warn};

        info!("Handling OAuth2 Success page");

        let token = req
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "cookie")
            .and_then(|(_, v)| {
                v.split(';')
                    .find(|p| p.trim().starts_with("acSamlv2Token="))
                    .and_then(|p| p.split('=').nth(1))
            })
            .unwrap_or("")
            .to_string();

        let mut final_token = token.clone();

        // Check if session has HPKE context associated
        if let Some(session) = state.session_manager.get_session_by_token(&token) {
            if let Some(ref hpke_id) = session.hpke_ctx_id {
                if let Some(ctx) = state.get_hpke_context(hpke_id) {
                    info!("Encrypting token for AnyConnect client...");
                    match ctx.encrypt_token(&token) {
                        Ok(encrypted) => {
                            final_token = encrypted;
                        }
                        Err(e) => warn!("HPKE encryption failed: {}", e),
                    }
                }
            }
        }

        let html = match render_template(
            "saml_ac_login.html",
            &json!({
                "AC_SAML_TOKEN": final_token
            }),
        ) {
            Ok(h) => h,
            Err(e) => return HttpResponse::new(500, &format!("Template Error: {}", e)),
        };

        HttpResponse::ok()
            .header("Content-Type", "text/html; charset=utf-8")
            .header("Cache-Control", "no-store")
            .body_str(&html)
    }
}

use super::{SsoProvider, SsoRoute};

impl SsoProvider for OAuth2Provider {
    fn name(&self) -> &'static str {
        "oauth2"
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    fn routes(&self) -> Vec<SsoRoute> {
        vec![
            SsoRoute {
                method: "GET",
                path: "/+CSCOE+/oauth2/login",
            },
            SsoRoute {
                method: "GET",
                path: "/+CSCOE+/oauth2/callback",
            },
            SsoRoute {
                method: "GET",
                path: "/+CSCOE+/oauth2_login.html",
            },
        ]
    }

    fn login_url(&self, base_url: &str, ctx: Option<&str>) -> String {
        let state_param = ctx.map(|c| format!("ctx={}", c)).unwrap_or_default();
        format!(
            "{}/+CSCOE+/oauth2/login?state={}",
            base_url,
            urlencoding::encode(&state_param)
        )
    }

    fn final_url(&self, base_url: &str) -> String {
        format!("{}/+CSCOE+/oauth2_login.html", base_url)
    }

    fn handle(&self, req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
        let path = req.path.split('?').next().unwrap_or("");

        // Extract ctx from query for login
        let ctx = req.path.split('?').nth(1).and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == "state")
                .and_then(|(_, v)| {
                    url::form_urlencoded::parse(v.as_bytes())
                        .find(|(k, _)| k == "ctx")
                        .map(|(_, ctx)| ctx.to_string())
                })
        });

        match path {
            "/+CSCOE+/oauth2/login" => self.handle_login(ctx, state),
            "/+CSCOE+/oauth2/callback" => self.handle_callback(req, state),
            "/+CSCOE+/oauth2_login.html" => self.handle_success(req, state),
            _ => HttpResponse::not_found(),
        }
    }
}
