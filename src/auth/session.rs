use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::UserInfo;

/// VPN session information
#[derive(Debug, Clone)]
pub struct VpnSession {
    pub session_id: String,
    pub session_token: String,
    pub hpke_ctx_id: Option<String>, // ID to lookup HPKE context for encryption
    pub user_info: UserInfo,
    pub created_at: std::time::Instant,
}

/// Session manager for tracking active VPN sessions
pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<String, VpnSession>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a new session for authenticated user
    pub fn create_session(&self, user_info: UserInfo, hpke_ctx_id: Option<String>) -> VpnSession {
        let session_id = rand::random::<u32>().to_string();
        let session_token = self.generate_session_token(&session_id, &user_info.username);

        let session = VpnSession {
            session_id: session_id.clone(),
            session_token,
            hpke_ctx_id,
            user_info,
            created_at: std::time::Instant::now(),
        };

        self.sessions
            .lock()
            .unwrap()
            .insert(session_id, session.clone());
        session
    }

    /// Get session by session ID
    pub fn get_session(&self, session_id: &str) -> Option<VpnSession> {
        self.sessions.lock().unwrap().get(session_id).cloned()
    }

    /// Get session by full session token (AnyConnect cookie format)
    pub fn get_session_by_token(&self, token: &str) -> Option<VpnSession> {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .values()
            .find(|s| s.session_token == token)
            .cloned()
    }

    /// Remove session
    pub fn remove_session(&self, session_id: &str) {
        self.sessions.lock().unwrap().remove(session_id);
    }

    /// Generate session token in AnyConnect format
    /// Format: <random_hex>@<session_id>@<random_hex>@<hash>
    fn generate_session_token(&self, _session_id: &str, _username: &str) -> String {
        // OpenConnect/AnyConnect HPKE implementation requires the decrypted token to be alphanumeric.
        // We generate a random 64-character hex string (256 bits of entropy).
        // This replaces the legacy @-separated format.
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        hex::encode(bytes).to_uppercase()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_session() {
        let manager = SessionManager::new();
        let user_info = UserInfo {
            username: "testuser".to_string(),
            groups: vec![],
            attributes: HashMap::new(),
        };

        let session = manager.create_session(user_info, None);
        assert!(!session.session_id.is_empty());
        assert!(!session.session_token.is_empty());
        // New token format is just random hex, doesn't necessarily contain session_id
        assert_eq!(session.session_token.len(), 64);
    }

    #[test]
    fn test_get_session() {
        let manager = SessionManager::new();
        let user_info = UserInfo {
            username: "testuser".to_string(),
            groups: vec![],
            attributes: HashMap::new(),
        };

        let session = manager.create_session(user_info, None);
        let retrieved = manager.get_session(&session.session_id);

        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().session_id, session.session_id);
    }
}
