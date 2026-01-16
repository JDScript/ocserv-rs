use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use tracing::{debug, info};

use crate::protocol::{ConfigAuth, ConfigAuthType};

/// Main HTTP request handler
pub async fn handle_request(req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
    let method = req.method();
    let path = req.uri().path();

    info!("Received {} request to {}", method, path);
    debug!("Headers: {:?}", req.headers());

    match (method, path) {
        // Initial POST to tunnel group (e.g., /group-name or /)
        (&Method::POST, path) if !path.starts_with("/+CSCOE+") => {
            handle_tunnel_group_post(req).await
        }

        // HTTP CONNECT for tunnel establishment
        (&Method::CONNECT, "/CSCOSSLC/tunnel") => handle_connect(req).await,

        // Default 404
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))?),
    }
}

/// Handle POST to tunnel group endpoint
async fn handle_tunnel_group_post(req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
    // Read request body
    let body_bytes = req.into_body().collect().await?.to_bytes();

    // Parse XML request
    let config_auth: ConfigAuth = quick_xml::de::from_reader(body_bytes.as_ref())
        .context("Failed to parse config-auth XML")?;

    debug!("Parsed config-auth type: {:?}", config_auth.auth_type);

    match config_auth.auth_type {
        ConfigAuthType::Init => {
            // Client is initiating connection
            // For now, respond with password auth request
            // (SAML will be implemented in Phase 5)
            handle_auth_init().await
        }

        ConfigAuthType::AuthReply => {
            // Client is submitting credentials
            handle_auth_reply(config_auth).await
        }

        _ => Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("Invalid auth type")))?),
    }
}

/// Handle initial auth - respond with auth-request
async fn handle_auth_init() -> Result<Response<Full<Bytes>>> {
    // For Phase 2, we'll use password auth
    // SAML will be added in Phase 5
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request">
    <auth id="main">
        <title>Login</title>
        <message>Please enter your username and password</message>
        <form action="/auth" method="post">
            <input label="Username:" name="username" type="text"></input>
            <input label="Password:" name="password" type="password"></input>
        </form>
    </auth>
</config-auth>"#;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/xml; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("Pragma", "no-cache")
        .body(Full::new(Bytes::from(xml)))?)
}

/// Handle auth reply - validate credentials and return complete
async fn handle_auth_reply(config_auth: ConfigAuth) -> Result<Response<Full<Bytes>>> {
    // Extract username/password from auth reply
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

    info!("Authentication attempt for user: {}", username);

    // For Phase 2, we'll do simple validation
    // Real authentication will be implemented in Phase 4
    if !username.is_empty() && !password.is_empty() {
        // Generate session
        let session_id = "123456";
        let session_token = format!("TOKEN@{}@HASH", session_id);

        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete">
    <session-id>{}</session-id>
    <session-token>{}</session-token>
    <auth id="success">
        <message id="0" param1="" param2=""></message>
    </auth>
</config-auth>"#,
            session_id, session_token
        );

        info!("Authentication successful for user: {}", username);

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/xml; charset=utf-8")
            .header("Cache-Control", "no-store")
            .header("Pragma", "no-cache")
            .body(Full::new(Bytes::from(xml)))?)
    } else {
        // Authentication failed
        Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Full::new(Bytes::from("Authentication failed")))?)
    }
}

/// Handle HTTP CONNECT request (tunnel establishment)
async fn handle_connect(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
    // This will be fully implemented in Phase 6
    // For now, just acknowledge
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("X-CSTP-Version", "1")
        .body(Full::new(Bytes::new()))?)
}
