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
use crate::http::handlers::ServerState;
use crate::http::manual_http::{HttpRequest, HttpResponse};
use crate::protocol::xml::render_template;
use serde_json::json;

/// Generate AuthnRequest XML
pub fn generate_authn_request(sp_entity_id: &str, acs_url: &str) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let issue_instant = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let xml = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_{}" Version="2.0" IssueInstant="{}" Destination="{}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{}"><saml:Issuer>{}</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" AllowCreate="true"/></samlp:AuthnRequest>"#,
        id, issue_instant, "DESTINATION_PLACEHOLDER", acs_url, sp_entity_id
    );

    Ok(xml)
}

/// Compress and Base64 encode the AuthnRequest (Deflate + Base64)
pub fn compress_and_encode_authn_request(xml: &str) -> Result<String> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(xml.as_bytes())?;
    let compressed = encoder.finish()?;
    Ok(BASE64.encode(compressed))
}

/// Handle SAML Login Request (Redirect to IdP)
/// Handle SAML Login Request (Redirect to IdP)
pub fn handle_saml_login(req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
    info!("Handling SAML Login request");

    // Extract 'ctx' from query parameters if present
    // This comes from auth.rs SSO URL construction: /+CSCOE+/saml/sp/login?ctx=<hpke_ctx_id>
    let ctx = req
        .path
        .split('?')
        .nth(1)
        .and_then(|q| q.split('&').find(|p| p.starts_with("ctx=")))
        .and_then(|p| p.split('=').nth(1))
        .map(|s| s.to_string());

    if let Some(ref c) = ctx {
        info!("SAML Login: Preserving ctx={} in RelayState", c);
    }

    // 1. Get Config
    let idp_metadata_url = match state.config.auth.saml.idp_metadata_url.as_ref() {
        Some(url) => url,
        None => {
            warn!("SAML enabled but idp_metadata_url not configured");
            return HttpResponse::new(500, "SAML Configuration Error");
        }
    };

    let sp_entity_id = state
        .config
        .auth
        .saml
        .sp_entity_id
        .as_deref()
        .unwrap_or("ocserv-rs");

    let acs_url = state
        .config
        .auth
        .saml
        .acs_url
        .as_deref()
        .unwrap_or("https://localhost:8443/+CSCOE+/saml/sp/acs");

    // 2. Generate AuthnRequest
    let xml = match generate_authn_request(sp_entity_id, acs_url) {
        Ok(x) => x,
        Err(e) => return HttpResponse::new(500, &format!("SAML Error: {}", e)),
    };

    let compressed_encoded = match compress_and_encode_authn_request(&xml) {
        Ok(x) => x,
        Err(e) => return HttpResponse::new(500, &format!("SAML Compression Error: {}", e)),
    };

    // 3. Construct Redirect URL
    // TODO: Parsing the IdP URL might fail if malformed in config
    let mut url = match Url::parse(idp_metadata_url) {
        Ok(u) => u,
        Err(e) => return HttpResponse::new(500, &format!("IdP URL Parse Error: {}", e)),
    };

    url.query_pairs_mut()
        .append_pair("SAMLRequest", &compressed_encoded);

    // Add RelayState if present (to pass ctx back to ACS)
    if let Some(c) = ctx {
        // We pass "ctx=<value>" as RelayState
        url.query_pairs_mut()
            .append_pair("RelayState", &format!("ctx={}", c));
    }

    HttpResponse::new(302, "Found")
        .header("Location", url.to_string().as_str())
        .body_str("")
}

/// Handle SAML ACS (Assertion Consumer Service) POST
pub fn handle_saml_acs(req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
    info!("Handling SAML ACS POST");

    // 1. Parse Form Body
    let form_data = req.parse_form();

    let saml_response_b64 = match form_data.get("SAMLResponse") {
        Some(s) => s,
        None => return HttpResponse::new(400, "Missing SAMLResponse"),
    };

    info!("Received SAML Response, size: {}", saml_response_b64.len());

    // 2. Validate Response (MOCK for now, as in old code phase 4)
    // TODO: Implement real XML signature validation using openssl/samael

    // 3. Extract HPKE Context ID from RelayState
    // RelayState is passed by us in handle_saml_login, echoed by IdP
    let relay_state = match form_data.get("RelayState") {
        Some(s) => s,
        None => "",
    };

    // Parse ctx=... from RelayState
    let hpke_ctx_id = if !relay_state.is_empty() {
        // Expected format: "ctx=<uuid>" or "ctx=<uuid>&..."
        // Or sometimes just stored as URL encoded.
        // We set it as "ctx=<uuid>" in handle_saml_login (to be implemented)
        url::form_urlencoded::parse(relay_state.as_bytes())
            .find(|(k, _)| k == "ctx")
            .map(|(_, v)| v.to_string())
    } else {
        None
    };

    if let Some(ref id) = hpke_ctx_id {
        info!("SAML ACS: Found HPKE Context ID from RelayState: {}", id);
    }

    // 4. Create Session (bind HPKE context to session)
    let user_info = UserInfo {
        username: "saml_user".to_string(), // Placeholder
        groups: vec!["saml_users".to_string()],
        attributes: HashMap::new(),
    };

    let session = state.session_manager.create_session(user_info, hpke_ctx_id);

    // 5. Set Cookie and Redirect to Final Page
    // Cookie name must match <sso-v2-token-cookie-name> if specified, or we use our standard `acSamlv2Token`
    // The client expects a specific cookie set by the browser which the client then reads.

    let cookie_val = &session.session_token;

    HttpResponse::new(302, "Found")
        .header("Location", "/+CSCOE+/saml_ac_login.html")
        .header(
            "Set-Cookie",
            &format!("acSamlv2Token={}; path=/; Secure; HttpOnly", cookie_val),
        )
        .body_str("")
}

/// Handle Mock IdP GET (Login Page)
pub fn handle_mock_idp_get(req: &HttpRequest, _state: &Arc<ServerState>) -> HttpResponse {
    let saml_request = req
        .headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == "samlrequest")
        .map(|(_, v)| v.as_str())
        .or_else(|| {
            // Check query params if not in headers
            // Basic parsing for mock IdP
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

/// Handle Mock IdP POST (Login Form Submission)
pub fn handle_mock_idp_post(req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
    info!("Mock IdP POST: Generating dummy SAMLResponse");

    // Parse form data to get RelayState
    let form_data = req.parse_form();
    let relay_state = form_data.get("RelayState").cloned().unwrap_or_default();

    let acs_url = state
        .config
        .auth
        .saml
        .acs_url
        .as_deref()
        .unwrap_or("https://localhost:8443/+CSCOE+/saml/sp/acs");

    // Generate Dummy SAMLResponse (Base64 encoded)
    // SP side (handle_saml_acs) is currently lax and just checks presence.
    let dummy_response = "DUMMY_SAML_RESPONSE_BASE64_ENCODED";

    let mut html = String::new();
    html.push_str("<html><body onload=\"document.forms[0].submit()\">");
    html.push_str(&format!("<form method=\"POST\" action=\"{}\">", acs_url));
    html.push_str(&format!(
        "<input type=\"hidden\" name=\"SAMLResponse\" value=\"{}\"/>",
        dummy_response
    ));
    // Include RelayState if present
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

/// Handle SAML success page (Final step, opens AnyConnect app)
pub fn handle_saml_success(req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
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
        .to_string(); // Clone to own string

    let mut final_token = token.clone();

    // Check if session has HPKE context associated
    if let Some(session) = state.session_manager.get_session_by_token(&token) {
        if let Some(ref hpke_id) = session.hpke_ctx_id {
            info!(
                "Session {} has HPKE context ID: {}",
                session.session_id, hpke_id
            );
            // Retrieve HPKE context (cloned) so we can encrypt
            if let Some(ctx) = state.get_hpke_context(hpke_id) {
                // If this is a repeat request (e.g. valid session), we re-encrypt?
                // AnyConnect might hit this URL multiple times.
                // HPKE context isn't single use in our implementation (ephemeral key is generated per encrypt call)
                // BUT we need to ensure we don't rotate keys if that matters?
                // Actually, our encrypt_token generates NEW ephemeral keys each time.
                // This is fine as long as client accepts any matching message.

                info!("Encrypting token for legacy AnyConnect client...");
                match ctx.encrypt_token(&token) {
                    Ok(encrypted) => {
                        info!("Token encrypted successfully (len={})", encrypted.len());
                        final_token = encrypted;
                    }
                    Err(e) => warn!("HPKE encryption failed: {}", e),
                }
            } else {
                warn!(
                    "HPKE context ID {} found but context missing from store (expired?)",
                    hpke_id
                );
            }
        }
    }

    let html = match render_template(
        "saml_ac_login.html", // Using real AnyConnect template
        &json!({
            "AC_SAML_TOKEN": final_token // Token variable expected by template
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
