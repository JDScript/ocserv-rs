use anyhow::{Context, Result};
use bytes::Bytes;
use http_body::Body;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info};
use url::Url;

use crate::auth::{Authenticator, PasswordAuthenticator, SessionManager};
use crate::config::Config;
use crate::protocol::xml::render_template;
use crate::protocol::{ConfigAuth, ConfigAuthType};

// SAML helper
mod saml {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use chrono::Utc;
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;
    use uuid::Uuid;

    pub fn generate_authn_request(sp_entity_id: &str, acs_url: &str) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let issue_instant = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let xml = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_{}" Version="2.0" IssueInstant="{}" Destination="{}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{}"><saml:Issuer>{}</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" AllowCreate="true"/></samlp:AuthnRequest>"#,
            id, issue_instant, "DESTINATION_PLACEHOLDER", acs_url, sp_entity_id
        );

        Ok(xml)
    }

    pub fn compress_and_encode_authn_request(xml: &str) -> Result<String> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(xml.as_bytes())?;
        let compressed = encoder.finish()?;
        Ok(BASE64.encode(compressed))
    }
}

/// Server state shared across handlers
pub struct ServerState {
    pub authenticator: Arc<dyn Authenticator>,
    pub session_manager: Arc<SessionManager>,
    pub config: Arc<Config>,
}

impl ServerState {
    pub fn new(config: Arc<Config>) -> Self {
        let authenticator: Arc<dyn Authenticator> = if config.auth.password.enabled {
            Arc::new(PasswordAuthenticator::new(
                config.auth.password.users.clone(),
            ))
        } else {
            Arc::new(PasswordAuthenticator::with_defaults())
        };

        Self {
            authenticator,
            session_manager: Arc::new(SessionManager::new()),
            config,
        }
    }
}

/// Main HTTP request handler - MUST always return a Response, never error
pub async fn handle_request<B>(
    req: Request<B>,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    info!("Received {} request to {}", method, path);
    debug!("Headers: {:?}", req.headers());

    // Call internal handler and convert any errors to HTTP responses
    let result = handle_request_internal(req, state).await;

    Ok(match result {
        Ok(response) => response,
        Err(e) => {
            error!("Handler error: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from(format!(
                    "Internal Server Error: {}",
                    e
                ))))
                .unwrap()
        }
    })
}

/// Internal request handler that can return errors
async fn handle_request_internal<B>(
    req: Request<B>,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let method = req.method();
    let path = req.uri().path();
    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Log User-Agent to help debug different client types
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    debug!("User-Agent: {}", user_agent);

    match (method, path) {
        // GET requests - AnyConnect may use GET for initial handshake
        (&Method::GET, path) if !path.starts_with("/+CSCOE+") && !path.starts_with("/dev/") => {
            info!("Handling GET request - likely AnyConnect initial request");
            handle_auth_init(state).await
        }

        // POST to /auth - can be XML or form data
        (&Method::POST, "/auth") => {
            // OpenConnect sends XML, browser/form clients send form data
            if content_type.contains("xml") {
                info!("Handling XML POST to /auth");
                handle_xml_auth_submission(req, state).await
            } else {
                info!("Handling form POST to /auth");
                handle_auth_form_submit(req, state).await
            }
        }

        // XML POST to tunnel group (root or named group)
        (&Method::POST, path)
            if !path.starts_with("/+CSCOE+") && !path.starts_with("/dev/") && path != "/auth" =>
        {
            handle_tunnel_group_post(req, state).await
        }

        // SAML: Initiate Login (Redirect to IdP)
        (&Method::GET, "/+CSCOE+/saml/sp/login") => handle_saml_login(req, state).await,

        // SAML: ACS (Assertion Consumer Service) - IdP POSTs back here
        (&Method::POST, "/+CSCOE+/saml/sp/acs") => handle_saml_acs(req, state).await,

        // SAML: Final Login Page (sets cookie)
        (&Method::GET, "/+CSCOE+/saml_ac_login.html") => {
            // This page is hit after ACS sets the token cookie.
            // It just needs to exist so the browser stops spinning and AnyConnect detects the cookie.
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from(
                    "<html><body>Login Complete. You can close this window.</body></html>",
                )))?)
        }

        // MOCK IdP (Development only)
        (&Method::GET, "/dev/idp") => {
            if state.config.auth.saml.dev_idp_enabled {
                handle_mock_idp_get(req).await
            } else {
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::from("Mock IdP disabled")))
                    .unwrap())
            }
        }
        (&Method::POST, "/dev/idp") => {
            if state.config.auth.saml.dev_idp_enabled {
                handle_mock_idp_post(req, state).await
            } else {
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::from("Mock IdP disabled")))
                    .unwrap())
            }
        }

        // HTTP CONNECT for tunnel establishment
        (&Method::CONNECT, "/CSCOSSLC/tunnel") => handle_connect(req).await,

        // Default 404
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))?),
    }
}

/// Handle POST to tunnel group endpoint (XML-based)
/// Handle POST to tunnel group endpoint (XML-based)
async fn handle_tunnel_group_post<B>(
    req: Request<B>,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    // Read request body
    let body_bytes = req.into_body().collect().await?.to_bytes();

    // Parse XML request
    let config_auth: ConfigAuth = quick_xml::de::from_reader(body_bytes.as_ref())
        .context("Failed to parse config-auth XML")?;

    debug!("Parsed config-auth type: {:?}", config_auth.auth_type);

    match config_auth.auth_type {
        ConfigAuthType::Init => {
            // Client is initiating connection
            handle_auth_init(state).await
        }

        ConfigAuthType::AuthReply => {
            // XML-based auth reply to root endpoint
            handle_xml_auth_reply(config_auth, state).await
        }

        _ => Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("Invalid auth type")))?),
    }
}

/// Handle initial auth - respond with auth-request
async fn handle_auth_init(state: Arc<ServerState>) -> Result<Response<Full<Bytes>>> {
    // Check if SAML is enabled
    if state.config.auth.saml.enabled {
        let base_url = state.config.auth.saml.base_url.as_deref().unwrap_or("");
        let sso_login_url = if let Some(_sp_entity_id) = &state.config.auth.saml.sp_entity_id {
            // If we have proper config, use it or fallback to base_url construction
            // But for AnyConnect we often need the full path
            format!("{}/+CSCOE+/saml/sp/login", base_url)
        } else {
            format!("{}/+CSCOE+/saml/sp/login", base_url)
        };

        let sso_login_final_url = format!("{}/+CSCOE+/saml_ac_login.html", base_url);

        let xml = render_template(
            "auth_request_sso.xml",
            &json!({
                "tunnel_group": "Default",
                "message": "Please complete the authentication process in the browser window.",
                "banner": state.config.auth.banner.clone(),
                "sso_login_url": sso_login_url,
                "sso_login_final_url": sso_login_final_url
            }),
        )?;

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/xml; charset=utf-8")
            .header("X-Transcend-Version", "1")
            .header("X-Aggregate-Auth", "1") // Important for AnyConnect to recognize Aggregate Auth
            .header(
                "Set-Cookie",
                "webvpncontext=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; Secure; HttpOnly",
            )
            .body(Full::new(Bytes::from(xml)))?);
    }

    // Default Password Auth
    let xml = render_template(
        "auth_request_password.xml",
        &json!({
            "message": "Please enter your username and password",
            "banner": state.config.auth.banner.clone()
        }),
    )?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/xml; charset=utf-8")
        .header("X-Transcend-Version", "1")
        .header(
            "Set-Cookie",
            "webvpncontext=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; Secure; HttpOnly",
        )
        .header("Cache-Control", "no-store")
        .header("Pragma", "no-cache")
        .body(Full::new(Bytes::from(xml)))?)
}

/// Handle XML submission to /auth endpoint (OpenConnect style)
async fn handle_xml_auth_submission<B>(
    req: Request<B>,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let body_bytes = req.into_body().collect().await?.to_bytes();
    info!(
        "XML auth submission body: {}",
        String::from_utf8_lossy(&body_bytes)
    );
    let config_auth: ConfigAuth =
        quick_xml::de::from_reader(body_bytes.as_ref()).context("Failed to parse auth XML")?;
    handle_xml_auth_reply(config_auth, state).await
}

/// Handle form submission to /auth endpoint (form-encoded)
async fn handle_auth_form_submit<B>(
    req: Request<B>,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let body_bytes = req.into_body().collect().await?.to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec())?;
    let form_data = parse_form_urlencoded(&body_str);
    let username = form_data.get("username").context("Missing username")?;
    let password = form_data.get("password").context("Missing password")?;

    match state.authenticator.authenticate(username, password) {
        Ok(user_info) => {
            let session = state.session_manager.create_session(user_info);
            let xml = render_template(
                "auth_complete.xml",
                &json!({"session_id": session.session_id, "session_token": session.session_token}),
            )?;
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/xml")
                .header("X-Transcend-Version", "1")
                .body(Full::new(Bytes::from(xml)))?)
        }
        Err(_) => Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Full::new(Bytes::from("Auth failed")))?),
    }
}

async fn handle_xml_auth_reply(
    config_auth: ConfigAuth,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>> {
    let username = config_auth
        .auth
        .get(0)
        .and_then(|a| a.username.clone())
        .context("Missing username")?;
    let password = config_auth
        .auth
        .get(0)
        .and_then(|a| a.password.clone())
        .context("Missing password")?;

    match state.authenticator.authenticate(&username, &password) {
        Ok(user_info) => {
            let session = state.session_manager.create_session(user_info);
            let xml = render_template(
                "auth_complete.xml",
                &json!({"session_id": session.session_id, "session_token": session.session_token}),
            )?;
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/xml")
                .header("X-Transcend-Version", "1")
                .body(Full::new(Bytes::from(xml)))?)
        }
        Err(_) => Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Full::new(Bytes::from("Auth failed")))?),
    }
}

/// Handle HTTP CONNECT request (tunnel establishment)
/// Handle HTTP CONNECT request (tunnel establishment)
async fn handle_connect<B>(_req: Request<B>) -> Result<Response<Full<Bytes>>> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("X-CSTP-Version", "1")
        .body(Full::new(Bytes::new()))?)
}

/// Parse application/x-www-form-urlencoded data
fn parse_form_urlencoded(body: &str) -> HashMap<String, String> {
    body.split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next().unwrap_or("");
            Some((
                urlencoding::decode(key).ok()?.into_owned(),
                urlencoding::decode(value).ok()?.into_owned(),
            ))
        })
        .collect()
}

// --- SAML HANDLERS ---

async fn handle_saml_login<B>(
    _req: Request<B>,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    // 1. Get Config
    let idp_url = state
        .config
        .auth
        .saml
        .idp_metadata_url
        .as_ref()
        .context("No IdP URL configured")?;
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
    let xml = saml::generate_authn_request(sp_entity_id, acs_url)?;
    let compressed_encoded = saml::compress_and_encode_authn_request(&xml)?;

    // 3. Construct Redirect URL
    let mut url = Url::parse(idp_url)?;
    url.query_pairs_mut()
        .append_pair("SAMLRequest", &compressed_encoded);

    // 4. Redirect
    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", url.to_string())
        .body(Full::new(Bytes::new()))?)
}

async fn handle_saml_acs<B>(
    req: Request<B>,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    // 1. Parse Form Body (SAMLResponse)
    let body_bytes = req.into_body().collect().await?.to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec())?;
    let form_data = parse_form_urlencoded(&body_str);

    let saml_response_b64 = form_data
        .get("SAMLResponse")
        .context("Missing SAMLResponse")?;

    // 2. Mock Validation (In Phase 4 real validation is hard, so we assume success if Mock IdP is used)
    // TODO: Phase 4.x - Implement real signature validation
    info!("Received SAML Response, size: {}", saml_response_b64.len());

    // 3. Create Session
    // We assume the user is "saml_user" for now since we don't parse the XML Assertions yet
    use crate::auth::UserInfo;
    let user_info = UserInfo {
        username: "saml_user".to_string(),
        groups: vec!["saml_users".to_string()],
        attributes: HashMap::new(),
    };
    let session = state.session_manager.create_session(user_info);

    // 4. Set Cookie and Redirect to Final Page
    // Cookie name must match <sso-v2-token-cookie-name> in auth-request
    // AnyConnect/OpenConnect picks this up.
    let cookie_val = session.session_token; // Use session token as the "SAML token" for now

    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", "/+CSCOE+/saml_ac_login.html")
        .header(
            "Set-Cookie",
            format!("acSamlv2Token={}; path=/; Secure; HttpOnly", cookie_val),
        )
        .body(Full::new(Bytes::new()))?)
}

async fn handle_mock_idp_get<B>(req: Request<B>) -> Result<Response<Full<Bytes>>> {
    // Render info page
    let query = req.uri().query().unwrap_or("");
    let mut query_params = HashMap::new();
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            query_params.insert(k, v);
        }
    }

    let saml_request = query_params.get("SAMLRequest").unwrap_or(&"");
    let relay_state = query_params.get("RelayState").unwrap_or(&"");

    let html = render_template(
        "mock_idp_login.html",
        &json!({
            "saml_request": saml_request,
            "relay_state": relay_state
        }),
    )?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(Full::new(Bytes::from(html)))?)
}

async fn handle_mock_idp_post<B>(
    req: Request<B>,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let body_bytes = req.into_body().collect().await?.to_bytes();
    let _form = parse_form_urlencoded(&String::from_utf8_lossy(&body_bytes));

    // In a real mock IdP, we'd check username/password
    // Here we just generate a success response back to ACS

    let acs_url = state
        .config
        .auth
        .saml
        .acs_url
        .as_deref()
        .unwrap_or("https://localhost:8443/+CSCOE+/saml/sp/acs");

    // Generate Dummy SAMLResponse (Base64 encoded)
    // We aren't doing the complex XML signing here for Step 1, just returning "SUCCESS"
    // The SP side (handle_saml_acs) is currently lax and just checks for presence.
    let dummy_response = "DUMMY_SAML_RESPONSE_BASE64_ENCODED";

    let mut html = String::new();
    html.push_str("<html><body onload=\"document.forms[0].submit()\">");
    html.push_str(&format!("<form method=\"POST\" action=\"{}\">", acs_url));
    html.push_str(&format!(
        "<input type=\"hidden\" name=\"SAMLResponse\" value=\"{}\"/>",
        dummy_response
    ));
    html.push_str("</form></body></html>");

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(Full::new(Bytes::from(html)))?)
}
