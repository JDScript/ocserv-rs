use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::http::handlers::ServerState;
use crate::http::manual_http::{HttpRequest, HttpResponse};
use crate::protocol::xml::render_template;
use serde_json::json;

/// Handle initial auth request (GET or POST to /)
pub fn handle_auth_init(req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
    // Special case: HTTP/1.0 with Connection: close and no cookies
    // This is likely a VPN agent keepalive/session check
    let connection = req.header("Connection").unwrap_or("");
    let has_cookies = req.header("Cookie").is_some();

    if req.version == 0 && connection.to_lowercase() == "close" && !has_cookies {
        debug!(
            "HTTP/1.0 Connection:close without cookies - VPN agent check - returning 204 No Content"
        );
        return HttpResponse::new(204, "No Content")
            .header("X-Transcend-Version", "1")
            .header("Connection", "close");
    }

    // Check for existing session cookie
    if let Some(cookie) = req.header("Cookie") {
        debug!("Got Cookie header: {}", cookie);
        if let Some(token) = extract_webvpn_token(cookie) {
            debug!("Extracted webvpn token: {}", token);
            if let Some(session) = state.session_manager.get_session_by_token(&token) {
                info!("Valid session found: {}", session.session_id);
                let xml = match render_template(
                    "auth_complete.xml",
                    &json!({
                        "banner": state.config.auth.banner.as_deref().unwrap_or("Welcome to AI4CE VPN")
                    }),
                ) {
                    Ok(x) => x,
                    Err(e) => return HttpResponse::new(500, &format!("Template Error: {}", e)),
                };

                let context_b64 = BASE64.encode(session.session_id.as_bytes());

                return HttpResponse::ok()
                    .header("Content-Type", "text/xml")
                    .header("X-Transcend-Version", "1")
                    .header(
                        "Set-Cookie",
                        &format!("webvpncontext={}; Secure; HttpOnly", context_b64),
                    )
                    .body_str(&xml);
            }
        }
    }

    // SSO Check
    if state.config.auth.saml.enabled {
        let base_url = state.config.auth.saml.base_url.as_deref().unwrap_or("");
        let mut sso_login_url = format!("{}/+CSCOE+/saml/sp/login", base_url);
        let sso_login_final_url = format!("{}/+CSCOE+/saml_ac_login.html", base_url);

        // Extract AnyConnect version (simplified)
        let user_agent = req.header("User-Agent").unwrap_or("");
        let acvers = if let Some(idx) = user_agent.find("AnyConnect") {
            user_agent[idx..]
                .split_whitespace()
                .nth(2)
                .unwrap_or("5.0.0")
        } else {
            "5.0.0"
        };

        // Debug Headers
        for (k, v) in &req.headers {
            debug!("Header: {} = {}", k, v);
        }

        // Check for STRAP-DH-Pubkey for HPKE match
        if let Some(strap_dh_pubkey) = req.header("X-AnyConnect-STRAP-DH-Pubkey") {
            info!("Got X-AnyConnect-STRAP-DH-Pubkey, setting up HPKE context");
            let mut hpke_ctx = crate::crypto::HpkeContext::new();
            if let Err(e) = hpke_ctx.set_client_dh_pubkey(strap_dh_pubkey) {
                warn!("Failed to parse STRAP-DH-Pubkey: {}", e);
            } else {
                // Generate unique HPKE Context ID
                let ctx_id = uuid::Uuid::new_v4().to_string();
                state.store_hpke_context(&ctx_id, hpke_ctx);
                info!("Stored HPKE context with ID: {}", ctx_id);

                // Append ctx to SSO URL
                sso_login_url = format!("{}?ctx={}", sso_login_url, ctx_id);
                info!("Updated SSO URL with ctx: {}", sso_login_url);
            }
        }

        info!("SAML enabled - responding with SSO initiation form");
        return HttpResponse::ok()
            .header("Content-Type", "text/xml; charset=utf-8")
            .header("X-Transcend-Version", "1")
            .header("X-Aggregate-Auth", "1")
            .header(
                "Set-Cookie",
                "webvpncontext=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; Secure; HttpOnly",
            )
            .header("Set-Cookie", &format!("acvers={}; path=/; Secure", acvers))
            .body_str(&build_sso_form_xml(
                state,
                &sso_login_url,
                &sso_login_final_url,
            ));
    }

    // Default Password Auth Form
    let xml = match render_template(
        "auth_request_password.xml",
        &json!({
            "message": "Please enter your username and password",
            "banner": state.config.auth.banner.clone()
        }),
    ) {
        Ok(x) => x,
        Err(e) => return HttpResponse::new(500, &format!("Template Error: {}", e)),
    };

    HttpResponse::ok()
        .header(
            "Set-Cookie",
            "webvpncontext=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; Secure; HttpOnly",
        )
        .header("Content-Type", "text/xml")
        .header("X-Transcend-Version", "1")
        .body_str(&xml)
}

/// Handle XML auth submission
pub fn handle_xml_auth(req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
    use crate::auth::AuthRequest;
    use crate::protocol::dtd::{ConfigAuth, ConfigAuthType};

    let body = String::from_utf8_lossy(&req.body);
    debug!("XML auth submission: {}", body);

    // Parse XML
    let config: ConfigAuth = match quick_xml::de::from_str(&body) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to parse auth XML: {}", e);
            return HttpResponse::new(400, "Invalid XML");
        }
    };

    // If this is an init request, fallback to handle_auth_init to show login form
    if config.auth_type == ConfigAuthType::Init {
        debug!("XML auth is type='init' - falling back to handle_auth_init");
        return handle_auth_init(req, state);
    }

    // Look for SSO token in any Auth block
    for auth in &config.auth {
        if let Some(token) = &auth.sso_token {
            info!("Found sso-token in XML: {}", token);
            if let Some(session) = state.session_manager.get_session_by_token(token) {
                info!("Valid session found for sso-token: {}", session.session_id);
                return create_auth_success_response_for_session(
                    state,
                    &session.session_token,
                    &session.session_id,
                );
            } else {
                warn!("Invalid sso-token provided: {}", token);
                return HttpResponse::new(401, "Unauthorized")
                    .header("Content-Type", "text/xml")
                    .body_str("<error>Invalid SSO token</error>");
            }
        }
    }

    // Check for username/password authentication using AuthManager
    let username = config.auth.iter().find_map(|a| a.username.clone());
    let password = config.auth.iter().find_map(|a| a.password.clone());

    if let (Some(u), Some(p)) = (username, password) {
        let auth_request = AuthRequest::Password {
            username: u.clone(),
            password: p,
        };

        match state.auth_manager.authenticate(&auth_request) {
            Ok(user_info) => {
                info!("Password auth successful for user: {}", user_info.username);
                let session = state.session_manager.create_session(user_info, None);
                return create_auth_success_response_for_session(
                    state,
                    &session.session_token,
                    &session.session_id,
                );
            }
            Err(e) => {
                warn!("Password auth failed for user {}: {}", u, e);
                return HttpResponse::new(401, "Unauthorized")
                    .header("Content-Type", "text/xml")
                    .body_str("<error>Invalid credentials</error>");
            }
        }
    }

    // No valid auth method found (for auth-reply without credentials)
    warn!(
        "No valid auth method found in XML submission (type={:?})",
        config.auth_type
    );
    HttpResponse::new(401, "Unauthorized")
        .header("Content-Type", "text/xml")
        .body_str("<error>No credentials provided</error>")
}

/// Handle form auth submission
pub fn handle_form_auth(req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
    use crate::auth::AuthRequest;

    let form_data = req.parse_form();
    info!(
        "Form auth submission - keys: {:?}",
        form_data.keys().collect::<Vec<_>>()
    );

    // Log the raw body for debugging
    let body_str = String::from_utf8_lossy(&req.body);
    debug!(
        "Form auth raw body (first 200 chars): {}",
        &body_str[..body_str.len().min(200)]
    );

    // Check for SSO token first
    if let Some(token) = form_data.get("sso-token") {
        info!("Found sso-token in form data: {}", token);
        if let Some(session) = state.session_manager.get_session_by_token(token) {
            info!("Valid session found for sso-token: {}", session.session_id);
            return create_auth_success_response_for_session(
                state,
                &session.session_token,
                &session.session_id,
            );
        } else {
            warn!(
                "Invalid sso-token provided in form: {} - not found in session manager",
                token
            );
            return HttpResponse::new(401, "Unauthorized")
                .header("Content-Type", "text/xml")
                .body_str("<error>Invalid SSO token</error>");
        }
    } else {
        debug!("No sso-token found in form data");
    }

    // Check for username/password authentication using AuthManager
    let username = form_data.get("username").map(|s| s.to_string());
    let password = form_data.get("password").map(|s| s.to_string());

    // If credentials were provided, attempt authentication
    if let (Some(u), Some(p)) = (username.clone(), password) {
        let auth_request = AuthRequest::Password {
            username: u.clone(),
            password: p,
        };

        match state.auth_manager.authenticate(&auth_request) {
            Ok(user_info) => {
                info!(
                    "Password auth successful (form) for user: {}",
                    user_info.username
                );
                let session = state.session_manager.create_session(user_info, None);
                return create_auth_success_response_for_session(
                    state,
                    &session.session_token,
                    &session.session_id,
                );
            }
            Err(e) => {
                // Credentials were provided but invalid - return 401
                warn!("Password auth failed (form) for user {}: {}", u, e);
                return HttpResponse::new(401, "Unauthorized")
                    .header("Content-Type", "text/xml")
                    .body_str("<error>Invalid credentials</error>");
            }
        }
    }

    // No credentials provided - this is likely an init request
    // Fallback to auth init to show the login form
    if username.is_none() && form_data.get("password").is_none() {
        debug!("No credentials in form data - treating as init request");
        return handle_auth_init(req, state);
    }

    // Partial credentials (username but no password, or vice versa) - return 401
    warn!("Incomplete credentials in form data");
    HttpResponse::new(401, "Unauthorized")
        .header("Content-Type", "text/xml")
        .body_str("<error>Incomplete credentials</error>")
}

fn create_auth_success_response_for_session(
    state: &Arc<ServerState>,
    session_token: &str,
    session_id: &str,
) -> HttpResponse {
    let cookie_b64 = BASE64.encode(session_token.as_bytes());

    let webvpncontext = format!("webvpncontext={}; Secure; HttpOnly", cookie_b64);
    let webvpn = format!("webvpn={}; Secure; HttpOnly", cookie_b64);
    let webvpnc_clear =
        "webvpnc=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; Secure; HttpOnly".to_string();

    // Use the UPPERCASE hash fix we implemented
    let webvpnc_set = format!(
        "webvpnc=bu:/&p:t&iu:1/&sh:{}; path=/; Secure; HttpOnly",
        state.cert_hash.to_uppercase()
    );

    let xml = match render_template(
        "auth_complete.xml",
        &json!({
            "banner": state.config.auth.banner.as_deref().unwrap_or("Welcome to AI4CE VPN"),
            "session_id": session_id,
            "session_token": session_token,
            "cert_hash": state.cert_hash.to_uppercase()
        }),
    ) {
        Ok(x) => x,
        Err(e) => return HttpResponse::new(500, &format!("Template Error: {}", e)),
    };

    let mut response = HttpResponse::ok()
        .header("Connection", "Keep-Alive")
        .header("Content-Type", "text/xml")
        .header("X-Transcend-Version", "1");

    response = response
        .header("Set-Cookie", &webvpncontext)
        .header("Set-Cookie", &webvpn)
        .header("Set-Cookie", &webvpnc_clear)
        .header("Set-Cookie", &webvpnc_set);

    response.body_str(&xml)
}

/// Build SSO initiation form XML using tera template
fn build_sso_form_xml(state: &Arc<ServerState>, sso_url: &str, sso_final_url: &str) -> String {
    match render_template(
        "auth_request_sso.xml",
        &json!({
            "tunnel_group": "Default",
            "message": "Please complete the authentication process in the browser window.",
            "banner": state.config.auth.banner.clone(),
            "sso_login_url": sso_url,
            "sso_login_final_url": sso_final_url
        }),
    ) {
        Ok(x) => x,
        Err(e) => format!("Template Error: {}", e),
    }
}

// build_auth_form_xml removed as its logic is now inside handle_auth_init via render_template

fn extract_webvpn_token(cookie: &str) -> Option<String> {
    for pair in cookie.split(';') {
        let pair = pair.trim();
        // Check for standard webvpn cookie or anyconnect SAML cookie
        let value = if let Some(v) = pair.strip_prefix("webvpn=") {
            Some(v)
        } else if let Some(v) = pair.strip_prefix("acSamlv2Token=") {
            Some(v)
        } else {
            None
        };

        if let Some(value) = value {
            if let Ok(decoded) = BASE64.decode(value) {
                if let Ok(token) = String::from_utf8(decoded) {
                    return Some(token);
                }
            }
            return Some(value.to_string());
        }
    }
    None
}
