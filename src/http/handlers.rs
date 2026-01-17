use crate::auth::{Authenticator, PasswordAuthenticator, SessionManager};
use crate::config::Config;
use crate::vpn::dtls::DtlsSessionStore;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub mod auth;
pub mod sso;

/// Server state shared across handlers
pub struct ServerState {
    pub authenticator: Arc<dyn Authenticator>,
    pub session_manager: Arc<SessionManager>,
    pub config: Arc<Config>,
    pub cert_hash: String,
    pub dtls_sessions: DtlsSessionStore,
}

impl ServerState {
    pub fn new(config: Arc<Config>, cert_hash: String) -> Self {
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
            cert_hash,
            dtls_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

