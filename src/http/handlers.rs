use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::auth::{Authenticator, PasswordAuthenticator, SessionManager};
use crate::protocol::{ConfigAuth, ConfigAuthType};
use crate::xml::render_template;

/// Server state shared across handlers
pub struct ServerState {
    pub authenticator: Arc<dyn Authenticator>,
    pub session_manager: Arc<SessionManager>,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            authenticator: Arc::new(PasswordAuthenticator::new()),
            session_manager: Arc::new(SessionManager::new()),
        }
    }
}

/// Main HTTP request handler - MUST always return a Response, never error
pub async fn handle_request(
    req: Request<Incoming>,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
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
async fn handle_request_internal(
    req: Request<Incoming>,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>> {
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
        (&Method::GET, path) if !path.starts_with("/+CSCOE+") => {
            info!("Handling GET request - likely AnyConnect initial request");
            handle_auth_init().await
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
        (&Method::POST, path) if !path.starts_with("/+CSCOE+") => {
            handle_tunnel_group_post(req, state).await
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
async fn handle_tunnel_group_post(
    req: Request<Incoming>,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>> {
    // Read request body
    let body_bytes = req.into_body().collect().await?.to_bytes();

    // Parse XML request
    let config_auth: ConfigAuth = quick_xml::de::from_reader(body_bytes.as_ref())
        .context("Failed to parse config-auth XML")?;

    debug!("Parsed config-auth type: {:?}", config_auth.auth_type);

    match config_auth.auth_type {
        ConfigAuthType::Init => {
            // Client is initiating connection
            handle_auth_init().await
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
async fn handle_auth_init() -> Result<Response<Full<Bytes>>> {
    let xml = render_template(
        "auth_request_password.xml",
        &json!({
            "message": "Please enter your username and password",
            "banner": "Welcome to the AI4CE VPN"
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
async fn handle_xml_auth_submission(
    req: Request<Incoming>,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>> {
    // Read request body
    let body_bytes = req.into_body().collect().await?.to_bytes();

    info!(
        "XML auth submission body: {}",
        String::from_utf8_lossy(&body_bytes)
    );

    // Parse XML request
    let config_auth: ConfigAuth =
        quick_xml::de::from_reader(body_bytes.as_ref()).context("Failed to parse auth XML")?;

    // Handle as auth-reply
    handle_xml_auth_reply(config_auth, state).await
}

/// Handle form submission to /auth endpoint (form-encoded)
async fn handle_auth_form_submit(
    req: Request<Incoming>,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>> {
    // Read request body
    let body_bytes = req.into_body().collect().await?.to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec())?;

    info!("Form body received: {}", body_str);

    // Parse form data
    let form_data = parse_form_urlencoded(&body_str);
    debug!("Parsed form data: {:?}", form_data);

    let username = form_data
        .get("username")
        .context("Missing username in form")?;
    let password = form_data
        .get("password")
        .context("Missing password in form")?;

    info!("Form authentication attempt for user: {}", username);

    // Authenticate
    match state.authenticator.authenticate(username, password) {
        Ok(user_info) => {
            use crate::protocol::xml::render_template;
            use serde_json::json;

            let session = state.session_manager.create_session(user_info);

            let xml = render_template(
                "auth_complete.xml",
                &json!({
                    "session_id": session.session_id,
                    "session_token": session.session_token,

                }),
            )?;

            info!("Authentication successful for user: {}", username);

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/xml; charset=utf-8")
                .header("X-Transcend-Version", "1")
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .body(Full::new(Bytes::from(xml)))?)
        }
        Err(e) => {
            warn!("Authentication failed for user {}: {}", username, e);
            Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Full::new(Bytes::from("Authentication failed")))?)
        }
    }
}

/// Handle XML-based auth reply (from config-auth AuthReply)
async fn handle_xml_auth_reply(
    config_auth: ConfigAuth,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>> {
    let username = config_auth
        .auth
        .get(0)
        .and_then(|a| a.username.clone())
        .context("Missing username in XML auth")?;

    let password = config_auth
        .auth
        .get(0)
        .and_then(|a| a.password.clone())
        .context("Missing password in XML auth")?;

    info!("XML authentication attempt for user: {}", username);

    match state.authenticator.authenticate(&username, &password) {
        Ok(user_info) => {
            let session = state.session_manager.create_session(user_info);

            let xml = render_template(
                "auth_complete.xml",
                &json!({
                    "session_id": session.session_id,
                    "session_token": session.session_token,
                }),
            )?;

            info!("Authentication successful for user: {}", username);

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/xml; charset=utf-8")
                .header("X-Transcend-Version", "1")
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .body(Full::new(Bytes::from(xml)))?)
        }
        Err(e) => {
            warn!("Authentication failed for user {}: {}", username, e);
            Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Full::new(Bytes::from("Authentication failed")))?)
        }
    }
}

/// Handle HTTP CONNECT request (tunnel establishment)
async fn handle_connect(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
    // This will be fully implemented in Phase 5
    // For now, just acknowledge
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
