use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode};
use ocserv_rs::config::{AuthConfig, Config, PasswordAuthConfig, SamlAuthConfig, ServerConfig};
use ocserv_rs::http::handlers::{handle_request, ServerState};
use std::sync::Arc;

// Helper to create a test server state with SAML enabled
fn create_test_state() -> Arc<ServerState> {
    let config = Config {
        server: ServerConfig {
            listen: "0.0.0.0:8443".to_string(),
            cert_path: "server.crt".to_string(),
            key_path: "server.key".to_string(),
        },
        auth: AuthConfig {
            banner: Some("Test Banner".to_string()),
            password: PasswordAuthConfig {
                enabled: true,
                users: vec![],
            },
            saml: SamlAuthConfig {
                enabled: true,
                idp_metadata_url: Some("https://localhost:8443/dev/idp".to_string()),
                idp_entity_id: Some("mock-idp".to_string()),
                sp_entity_id: Some("test-sp".to_string()),
                acs_url: Some("https://localhost:8443/+CSCOE+/saml/sp/acs".to_string()),
                base_url: Some("https://localhost:8443".to_string()),
                dev_idp_enabled: true,
            },
        },
        network: ocserv_rs::config::NetworkConfig::default(),
    };
    let dummy_hash = "0000000000000000000000000000000000000000".to_string();
    Arc::new(ServerState::new(Arc::new(config), dummy_hash))
}

#[tokio::test]
async fn test_saml_init() -> Result<()> {
    let state = create_test_state();

    // 1. Initial Handshake (GET /)
    let req = Request::builder()
        .method(Method::GET)
        .uri("/")
        .body(Full::new(Bytes::new()))?;

    let resp = handle_request(req, state.clone()).await?;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.collect().await?.to_bytes();
    let body_str = String::from_utf8(body.to_vec())?;

    // Verify Aggregate Auth v2 and SSO URLs
    println!("Received XML Body: {}", body_str);
    assert!(body_str.contains("aggregate-auth-version=\"2\""));
    assert!(body_str.contains("<auth-method>single-sign-on-v2</auth-method>"));
    assert!(body_str
        .contains("<sso-v2-login>https://localhost:8443/+CSCOE+/saml/sp/login</sso-v2-login>"));

    Ok(())
}

#[tokio::test]
async fn test_saml_login_redirect() -> Result<()> {
    let state = create_test_state();

    // 2. Client hits SSO Login URL
    let req = Request::builder()
        .method(Method::GET)
        .uri("/+CSCOE+/saml/sp/login")
        .body(Full::new(Bytes::new()))?;

    let resp = handle_request(req, state.clone()).await?;
    assert_eq!(resp.status(), StatusCode::FOUND);

    let location = resp.headers().get("Location").unwrap().to_str()?;
    assert!(location.starts_with("https://localhost:8443/dev/idp"));
    assert!(location.contains("SAMLRequest="));

    Ok(())
}

#[tokio::test]
async fn test_mock_idp_flow() -> Result<()> {
    let state = create_test_state();

    // 3. Mock IdP Login (POST credentials)
    let req = Request::builder()
        .method(Method::POST)
        .uri("/dev/idp")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Full::new(Bytes::from("username=test&password=test")))?;

    let resp = handle_request(req, state.clone()).await?;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.collect().await?.to_bytes();
    let body_str = String::from_utf8(body.to_vec())?;

    // Verify auto-submit form to ACS
    assert!(body_str.contains("action=\"https://localhost:8443/+CSCOE+/saml/sp/acs\""));
    assert!(body_str.contains("name=\"SAMLResponse\""));

    Ok(())
}

#[tokio::test]
async fn test_saml_acs_success() -> Result<()> {
    let state = create_test_state();

    // 4. ACS Consumes Response
    let req = Request::builder()
        .method(Method::POST)
        .uri("/+CSCOE+/saml/sp/acs")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Full::new(Bytes::from(
            "SAMLResponse=DUMMY_SAML_RESPONSE_BASE64",
        )))?; // Dummy value matches handler for now

    let resp = handle_request(req, state.clone()).await?;
    assert_eq!(resp.status(), StatusCode::FOUND);

    // Verify Redirect to final login page
    assert_eq!(
        resp.headers().get("Location").unwrap().to_str()?,
        "/+CSCOE+/saml_ac_login.html"
    );

    // Verify Cookie Set
    let cookie = resp.headers().get("Set-Cookie").unwrap().to_str()?;
    assert!(cookie.contains("acSamlv2Token="));

    Ok(())
}
