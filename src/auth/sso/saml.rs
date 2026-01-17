use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use tracing::{info, warn};
use url::Url;
use uuid::Uuid;

use crate::auth::UserInfo;
use crate::config::SamlAuthConfig;
use crate::http::handlers::ServerState;
use crate::http::manual_http::{HttpRequest, HttpResponse};
use crate::protocol::xml::render_template;
use serde_json::json;

use super::{SsoProvider, SsoRoute};

/// Generate AuthnRequest XML
fn generate_authn_request(sp_entity_id: &str, acs_url: &str) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let issue_instant = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let xml = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_{}" Version="2.0" IssueInstant="{}" Destination="{}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{}"><saml:Issuer>{}</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" AllowCreate="true"/></samlp:AuthnRequest>"#,
        id, issue_instant, "DESTINATION_PLACEHOLDER", acs_url, sp_entity_id
    );

    Ok(xml)
}

/// Compress and Base64 encode the AuthnRequest (Deflate + Base64)
fn compress_and_encode_authn_request(xml: &str) -> Result<String> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(xml.as_bytes())?;
    let compressed = encoder.finish()?;
    Ok(BASE64.encode(compressed))
}

/// SAML SSO Provider
pub struct SamlProvider {
    config: SamlAuthConfig,
}

impl SamlProvider {
    pub fn new(config: SamlAuthConfig) -> Self {
        Self { config }
    }

    fn get_base_url(&self, state: &Arc<ServerState>) -> String {
        state
            .config
            .server
            .base_url
            .clone()
            .unwrap_or_else(|| "https://localhost:8443".to_string())
    }

    fn handle_login(&self, ctx: Option<String>, state: &Arc<ServerState>) -> HttpResponse {
        info!("Handling SAML Login request");

        if let Some(ref c) = ctx {
            info!("SAML Login: Preserving ctx={} in RelayState", c);
        }

        let idp_metadata_url = match self.config.idp_metadata_url.as_ref() {
            Some(url) => url,
            None => {
                warn!("SAML enabled but idp_metadata_url not configured");
                return HttpResponse::new(500, "SAML Configuration Error");
            }
        };

        let sp_entity_id = self.config.sp_entity_id.as_deref().unwrap_or("ocserv-rs");
        let acs_url = self.config.acs_url.as_deref().unwrap_or_else(|| {
            let base = self.get_base_url(state);
            // Return default constructed in-place - config should have this
            Box::leak(format!("{}/+CSCOE+/saml/sp/acs", base).into_boxed_str())
        });

        let xml = match generate_authn_request(sp_entity_id, acs_url) {
            Ok(x) => x,
            Err(e) => return HttpResponse::new(500, &format!("SAML Error: {}", e)),
        };

        let compressed_encoded = match compress_and_encode_authn_request(&xml) {
            Ok(x) => x,
            Err(e) => return HttpResponse::new(500, &format!("SAML Compression Error: {}", e)),
        };

        let mut url = match Url::parse(idp_metadata_url) {
            Ok(u) => u,
            Err(e) => return HttpResponse::new(500, &format!("IdP URL Parse Error: {}", e)),
        };

        url.query_pairs_mut()
            .append_pair("SAMLRequest", &compressed_encoded);

        if let Some(c) = ctx {
            url.query_pairs_mut()
                .append_pair("RelayState", &format!("ctx={}", c));
        }

        HttpResponse::new(302, "Found")
            .header("Location", url.to_string().as_str())
            .body_str("")
    }

    fn handle_acs(&self, req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
        info!("Handling SAML ACS POST");

        let form_data = req.parse_form();

        let saml_response_b64 = match form_data.get("SAMLResponse") {
            Some(s) => s,
            None => return HttpResponse::new(400, "Missing SAMLResponse"),
        };

        info!("Received SAML Response, size: {}", saml_response_b64.len());

        // Extract HPKE Context ID from RelayState
        let relay_state = form_data
            .get("RelayState")
            .map(|s| s.as_str())
            .unwrap_or("");

        let hpke_ctx_id = if !relay_state.is_empty() {
            url::form_urlencoded::parse(relay_state.as_bytes())
                .find(|(k, _)| k == "ctx")
                .map(|(_, v)| v.to_string())
        } else {
            None
        };

        if let Some(ref id) = hpke_ctx_id {
            info!("SAML ACS: Found HPKE Context ID from RelayState: {}", id);
        }

        // TODO: Validate SAML response signature
        let user_info = UserInfo {
            username: "saml_user".to_string(),
            groups: vec!["saml_users".to_string()],
            attributes: HashMap::new(),
        };

        let session = state.session_manager.create_session(user_info, hpke_ctx_id);

        HttpResponse::new(302, "Found")
            .header("Location", "/+CSCOE+/saml_ac_login.html")
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
        info!("Handling SAML Success page");

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

        if let Some(session) = state.session_manager.get_session_by_token(&token) {
            if let Some(ref hpke_id) = session.hpke_ctx_id {
                info!(
                    "Session {} has HPKE context ID: {}",
                    session.session_id, hpke_id
                );
                if let Some(ctx) = state.get_hpke_context(hpke_id) {
                    info!("Encrypting token for AnyConnect client...");
                    match ctx.encrypt_token(&token) {
                        Ok(encrypted) => {
                            info!("Token encrypted successfully (len={})", encrypted.len());
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
            .header("Pragma", "no-cache")
            .header("X-Frame-Options", "SAMEORIGIN")
            .body_str(&html)
    }
}

impl SsoProvider for SamlProvider {
    fn name(&self) -> &'static str {
        "saml"
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    fn routes(&self) -> Vec<SsoRoute> {
        vec![
            SsoRoute {
                method: "GET",
                path: "/+CSCOE+/saml/sp/login",
            },
            SsoRoute {
                method: "POST",
                path: "/+CSCOE+/saml/sp/acs",
            },
            SsoRoute {
                method: "GET",
                path: "/+CSCOE+/saml_ac_login.html",
            },
        ]
    }

    fn login_url(&self, base_url: &str, ctx: Option<&str>) -> String {
        match ctx {
            Some(c) => format!("{}/+CSCOE+/saml/sp/login?ctx={}", base_url, c),
            None => format!("{}/+CSCOE+/saml/sp/login", base_url),
        }
    }

    fn final_url(&self, base_url: &str) -> String {
        format!("{}/+CSCOE+/saml_ac_login.html", base_url)
    }

    fn handle(&self, req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
        let path = req.path.split('?').next().unwrap_or("");

        // Extract ctx from query for login
        let ctx = req
            .path
            .split('?')
            .nth(1)
            .and_then(|q| q.split('&').find(|p| p.starts_with("ctx=")))
            .and_then(|p| p.split('=').nth(1))
            .map(|s| s.to_string());

        match path {
            "/+CSCOE+/saml/sp/login" => self.handle_login(ctx, state),
            "/+CSCOE+/saml/sp/acs" => self.handle_acs(req, state),
            "/+CSCOE+/saml_ac_login.html" => self.handle_success(req, state),
            _ => HttpResponse::not_found(),
        }
    }
}

// Keep mock IdP handlers for dev mode
pub fn handle_mock_idp_get(req: &HttpRequest, _state: &Arc<ServerState>) -> HttpResponse {
    let saml_request = req
        .headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == "samlrequest")
        .map(|(_, v)| v.as_str())
        .or_else(|| {
            req.path
                .split('?')
                .nth(1)
                .and_then(|q| q.split('&').find(|p| p.starts_with("SAMLRequest=")))
                .and_then(|p| p.split('=').nth(1))
        })
        .unwrap_or("");

    let relay_state = req
        .path
        .split('?')
        .nth(1)
        .and_then(|q| q.split('&').find(|p| p.starts_with("RelayState=")))
        .and_then(|p| p.split('=').nth(1))
        .map(|s| {
            urlencoding::decode(s)
                .unwrap_or(std::borrow::Cow::Borrowed(s))
                .to_string()
        })
        .unwrap_or_default();

    let html = match render_template(
        "mock_idp_login.html",
        &json!({
            "saml_request": saml_request,
            "relay_state": relay_state
        }),
    ) {
        Ok(h) => h,
        Err(e) => return HttpResponse::new(500, &format!("Template Error: {}", e)),
    };

    HttpResponse::ok()
        .header("Content-Type", "text/html")
        .body_str(&html)
}

pub fn handle_mock_idp_post(req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
    info!("Mock IdP POST: Generating dummy SAMLResponse");

    let form_data = req.parse_form();
    let relay_state = form_data.get("RelayState").cloned().unwrap_or_default();

    let acs_url = state
        .config
        .auth
        .saml
        .acs_url
        .as_deref()
        .unwrap_or("https://localhost:8443/+CSCOE+/saml/sp/acs");

    let dummy_response = "DUMMY_SAML_RESPONSE_BASE64_ENCODED";

    let mut html = String::new();
    html.push_str("<html><body onload=\"document.forms[0].submit()\">");
    html.push_str(&format!("<form method=\"POST\" action=\"{}\">", acs_url));
    html.push_str(&format!(
        "<input type=\"hidden\" name=\"SAMLResponse\" value=\"{}\"/>",
        dummy_response
    ));
    if !relay_state.is_empty() {
        html.push_str(&format!(
            "<input type=\"hidden\" name=\"RelayState\" value=\"{}\"/>",
            relay_state
        ));
    }
    html.push_str("</form></body></html>");

    HttpResponse::ok()
        .header("Content-Type", "text/html")
        .body_str(&html)
}
