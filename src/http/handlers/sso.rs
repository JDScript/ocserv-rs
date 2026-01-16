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
pub fn handle_saml_login(_req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
    info!("Handling SAML Login request");

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

    // Add RelayState if provided in query params of original request?
    // Not strictly needed for basic flow, but good practice.

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

    // 3. Create Session
    let user_info = UserInfo {
        username: "saml_user".to_string(), // Placeholder
        groups: vec!["saml_users".to_string()],
        attributes: HashMap::new(),
    };

    let session = state.session_manager.create_session(user_info);

    // 4. Set Cookie and Redirect to Final Page
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
        .unwrap_or("");

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
pub fn handle_mock_idp_post(_req: &HttpRequest, state: &Arc<ServerState>) -> HttpResponse {
    info!("Mock IdP POST: Generating dummy SAMLResponse");

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
    html.push_str("</form></body></html>");

    HttpResponse::ok()
        .header("Content-Type", "text/html")
        .body_str(&html)
}

/// Handle SAML success page (Final step, opens AnyConnect app)
pub fn handle_saml_success(req: &HttpRequest, _state: &Arc<ServerState>) -> HttpResponse {
    info!("Handling SAML Success page");

    // We can try to extract the token from the cookie to pass it to the template
    // although the template JS also does this.
    let token = req
        .headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == "cookie")
        .and_then(|(_, v)| {
            v.split(';')
                .find(|p| p.trim().starts_with("acSamlv2Token="))
                .and_then(|p| p.split('=').nth(1))
        })
        .unwrap_or("");

    let html = match render_template(
        "sso_success.html",
        &json!({
            "token": token
        }),
    ) {
        Ok(h) => h,
        Err(e) => return HttpResponse::new(500, &format!("Template Error: {}", e)),
    };

    HttpResponse::ok()
        .header("Content-Type", "text/html")
        .header("Cache-Control", "no-store")
        .body_str(&html)
}
