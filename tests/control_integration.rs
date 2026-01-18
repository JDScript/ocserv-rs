use anyhow::Result;
use ocserv_rs::config::{Config, ControlConfig};
use ocserv_rs::control::{ControlCommand, ControlServer, UserSessionInfo};
use ocserv_rs::http::handlers::ServerState;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[tokio::test]
async fn test_control_interface() -> Result<()> {
    // Setup temporary socket path
    let mut socket_path = std::env::temp_dir();
    let rng: u32 = rand::random();
    socket_path.push(format!("ocserv_test_{}.sock", rng));
    let socket_path_str = socket_path.to_string_lossy().to_string();

    // Setup Mock Server State
    let config = Config::default();
    let state = Arc::new(ServerState::new(Arc::new(config), "mock_hash".to_string()));

    // Populate a fake session
    {
        use ocserv_rs::auth::UserInfo;
        use std::collections::HashMap;

        let user_info = UserInfo {
            username: "testuser".to_string(),
            groups: vec![],
            attributes: HashMap::new(),
        };

        // Create session
        let session = state.session_manager.create_session(user_info, None);

        // Register tunnel (simulate active connection)
        state.session_manager.register_tunnel(
            &session.session_token,
            "10.10.0.123".to_string(),
            "192.168.1.50:12345".parse().unwrap(),
            "OpenConnect v9.0".to_string(),
        );
    }

    // Start Control Server
    let control_config = ControlConfig {
        socket_path: socket_path_str.clone(),
        socket_group: None,
    };

    let server_handle = tokio::spawn(async move {
        let server = ControlServer::new(control_config, state);
        server.run().await
    });

    // Wait for server to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Connect Client
    let mut stream: UnixStream = UnixStream::connect(&socket_path).await?;

    // Send Command
    let cmd = ControlCommand::ShowUsers;
    let req_json = serde_json::to_string(&cmd)?;
    stream.write_all(req_json.as_bytes()).await?;
    stream.shutdown().await?; // EOF signals end of request for our simple server

    // Read Response
    let mut resp_buf = String::new();
    stream.read_to_string(&mut resp_buf).await?;

    // Verify Response
    let users: Vec<UserSessionInfo> = serde_json::from_str(&resp_buf)?;

    // Clean up socket file
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "testuser");
    assert_eq!(users[0].vpn_ip, Some("10.10.0.123".to_string()));
    assert_eq!(users[0].user_agent, Some("OpenConnect v9.0".to_string()));

    // Cleanup
    server_handle.abort();

    Ok(())
}
