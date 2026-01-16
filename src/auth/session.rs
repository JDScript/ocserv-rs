use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::UserInfo;

/// VPN session information
#[derive(Debug, Clone)]
pub struct VpnSession {
    pub session_id: String,
    pub session_token: String,
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
    pub fn create_session(&self, user_info: UserInfo) -> VpnSession {
        let session_id = rand::random::<u32>().to_string();
        let session_token = self.generate_session_token(&session_id, &user_info.username);

        let session = VpnSession {
            session_id: session_id.clone(),
            session_token,
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
    fn generate_session_token(&self, session_id: &str, username: &str) -> String {
        let r1 = format!("{:X}", rand::random::<u32>() & 0xFFFFFF);
        let r2 = format!("{:X}", rand::random::<u16>());

        // Generate hash (simplified - in production use proper HMAC)
        let hash_input = format!("{}{}", session_id, username);
        let hash = format!(
            "{:X}",
            hash_input
                .bytes()
                .fold(0u64, |acc, b| acc.wrapping_add(b as u64))
        );

        format!("{}@{}@{}@{}", r1, session_id, r2, hash)
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

        let session = manager.create_session(user_info);
        assert!(!session.session_id.is_empty());
        assert!(!session.session_token.is_empty());
        assert!(session.session_token.contains(&session.session_id));
    }

    #[test]
    fn test_get_session() {
        let manager = SessionManager::new();
        let user_info = UserInfo {
            username: "testuser".to_string(),
            groups: vec![],
            attributes: HashMap::new(),
        };

        let session = manager.create_session(user_info);
        let retrieved = manager.get_session(&session.session_id);

        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().session_id, session.session_id);
    }
}
