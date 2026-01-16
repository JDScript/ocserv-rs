use ocserv_rs::protocol::*;

#[test]
fn test_xml_auth_init_parse() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <config-auth client="vpn" type="init">
        <version who="vpn">v5.01</version>
    </config-auth>"#;

    let config: ConfigAuth = quick_xml::de::from_str(xml).unwrap();
    assert_eq!(config.client, "vpn");
    assert_eq!(config.auth_type, ConfigAuthType::Init);
}

#[test]
fn test_xml_auth_reply_parse() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <config-auth client="vpn" type="auth-reply">
        <auth id="main">
            <username>testuser</username>
            <password>testpass</password>
        </auth>
    </config-auth>"#;

    let config: ConfigAuth = quick_xml::de::from_str(xml).unwrap();
    assert_eq!(config.auth_type, ConfigAuthType::AuthReply);
    assert_eq!(config.auth[0].id, Some("main".to_string()));
    assert_eq!(config.auth[0].username, Some("testuser".to_string()));
    assert_eq!(config.auth[0].password, Some("testpass".to_string()));
}

#[test]
fn test_xml_complete_serialize() {
    let config = ConfigAuth {
        client: "vpn".to_string(),
        auth_type: ConfigAuthType::Complete,
        aggregate_auth_version: None,
        version: vec![],
        auth: vec![Auth {
            id: Some("success".to_string()),
            ..Default::default()
        }],
        opaque: None,
        device_id: None,
        capabilities: None,
        session_id: Some("12345".to_string()),
        session_token: Some("TOKEN@12345@HASH".to_string()),
        config: None,
    };

    let xml = quick_xml::se::to_string(&config).unwrap();
    assert!(xml.contains("type=\"complete\""));
    assert!(xml.contains("<session-id>12345</session-id>"));
}
