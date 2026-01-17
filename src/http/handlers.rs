use crate::auth::{AuthManager, SessionManager};
use crate::config::Config;
use crate::crypto::HpkeContext;
use crate::vpn::dtls::DtlsSessionStore;
use crate::vpn::ip_pool::SharedIpPool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

pub mod auth;
pub mod sso;

/// HPKE context storage (keyed by session token)
pub type HpkeStore = Arc<Mutex<HashMap<String, HpkeContext>>>;

/// Server state shared across handlers
pub struct ServerState {
    pub auth_manager: Arc<AuthManager>,
    pub session_manager: Arc<SessionManager>,
    pub config: Arc<Config>,
    pub cert_hash: String,
    pub dtls_sessions: DtlsSessionStore,
    pub ip_pool: SharedIpPool,
    /// HPKE contexts for SSO token encryption (keyed by pending SSO session ID)
    pub hpke_contexts: HpkeStore,
}

impl ServerState {
    pub fn new(config: Arc<Config>, cert_hash: String) -> Self {
        // Initialize AuthManager from config
        let auth_manager = Arc::new(AuthManager::from_config(&config.auth));

        // Initialize IP Pool from config
        let ip_pool =
            SharedIpPool::new(&config.network.ipv4_pool).expect("Failed to initialize IP pool");

        Self {
            auth_manager,
            session_manager: Arc::new(SessionManager::new()),
            config,
            cert_hash,
            dtls_sessions: Arc::new(RwLock::new(HashMap::new())),
            ip_pool,
            hpke_contexts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Store HPKE context for a pending SSO session
    pub fn store_hpke_context(&self, session_key: &str, ctx: HpkeContext) {
        self.hpke_contexts
            .lock()
            .unwrap()
            .insert(session_key.to_string(), ctx);
    }

    /// Get HPKE context for encryption (clones the context)
    pub fn get_hpke_context(&self, session_key: &str) -> Option<HpkeContext> {
        self.hpke_contexts.lock().unwrap().get(session_key).cloned()
    }
}
