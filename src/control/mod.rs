use crate::config::ControlConfig;
use crate::http::handlers::ServerState;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, warn};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "command", content = "args")]
pub enum ControlCommand {
    #[serde(rename = "show_users")]
    ShowUsers,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserSessionInfo {
    pub session_id: String,
    pub username: String,
    pub vpn_ip: Option<String>,
    pub remote_ip: Option<String>,
    pub user_agent: Option<String>,
    pub connected_at_rfc3339: Option<String>,
    pub connected_seconds: Option<u64>,
}

pub struct ControlServer {
    config: ControlConfig,
    state: Arc<ServerState>,
}

impl ControlServer {
    pub fn new(config: ControlConfig, state: Arc<ServerState>) -> Self {
        Self { config, state }
    }

    pub async fn run(self) -> Result<()> {
        // Remove existing socket if it exists
        if std::path::Path::new(&self.config.socket_path).exists() {
            std::fs::remove_file(&self.config.socket_path)
                .context("Failed to remove existing control socket")?;
        }

        // Create parent directory if it doesn't exist
        if let Some(parent) = std::path::Path::new(&self.config.socket_path).parent() {
            std::fs::create_dir_all(parent).context("Failed to create socket directory")?;
        }

        let listener = UnixListener::bind(&self.config.socket_path)
            .context("Failed to bind control socket")?;

        // Set ownership if configured
        if let Some(group) = &self.config.socket_group {
            // This requires standard Unix user/group handling, keeping it simple for now based on user/group mapping
            // But standard chmod is safer to start with.
            // Using nix crate would be ideal but avoiding extra deps if possible.
            // For now, let's just log.
            debug!("Socket group setting requested: {}", group);
            // TODO: set group permissions, maybe via std::os::unix::fs::chown
        }

        // Set generic permissions (e.g. 660 or 600)
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o660);
        if let Err(e) = std::fs::set_permissions(&self.config.socket_path, perms) {
            warn!("Failed to set socket permissions: {}", e);
        }

        info!("Control server listening on {}", self.config.socket_path);

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, state).await {
                            error!("Control client error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
    }
}

async fn handle_client(mut stream: UnixStream, state: Arc<ServerState>) -> Result<()> {
    // Read command (simple length-prefixed or json stream)
    // For simplicity, let's read the whole request as JSON until EOF (client closes write)
    // or better, one json object per request.

    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request: ControlCommand = match serde_json::from_slice(&buf[..n]) {
        Ok(req) => req,
        Err(e) => {
            let _ = stream.write_all(b"{\"error\": \"Invalid JSON\"}").await;
            return Err(e.into());
        }
    };

    match request {
        ControlCommand::ShowUsers => {
            // Collect data in a block to drop MutexGuard before async write
            let active_users = {
                let sessions = state.session_manager.sessions.lock().unwrap();
                let mut users = Vec::new();

                for session in sessions.values() {
                    // Filter only sessions with active VPN tunnel (vpn_ip is assigned)
                    if let Some(vpn_ip) = &session.vpn_ip {
                        users.push(UserSessionInfo {
                            session_id: session.session_id.clone(),
                            username: session.user_info.username.clone(),
                            vpn_ip: Some(vpn_ip.clone()),
                            remote_ip: session.remote_ip.map(|ip| ip.to_string()),
                            user_agent: session.user_agent.clone(),
                            connected_at_rfc3339: session.connected_at.map(|t| {
                                chrono::DateTime::<chrono::Utc>::from(
                                    std::time::SystemTime::now() - (std::time::Instant::now() - t),
                                )
                                .to_rfc3339()
                            }),
                            connected_seconds: session.connected_at.map(|t| t.elapsed().as_secs()),
                        });
                    }
                }
                users
            };

            let response = serde_json::to_string(&active_users)?;
            stream.write_all(response.as_bytes()).await?;
            stream.shutdown().await?;
        }
    }

    Ok(())
}
