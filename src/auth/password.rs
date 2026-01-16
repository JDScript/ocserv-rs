use anyhow::{anyhow, Result};
use std::collections::HashMap;

use super::{Authenticator, UserInfo};
use crate::config::UserConfig;

/// Password-based authenticator with in-memory user database
pub struct PasswordAuthenticator {
    users: HashMap<String, String>,
}

impl PasswordAuthenticator {
    /// Create new password authenticator from user configs
    pub fn new(user_configs: Vec<UserConfig>) -> Self {
        let mut users = HashMap::new();
        for user in user_configs {
            users.insert(user.username, user.password);
        }
        Self { users }
    }

    /// Create authenticator with default test users (for backward compatibility)
    pub fn with_defaults() -> Self {
        let mut users = HashMap::new();
        users.insert("test".to_string(), "test".to_string());
        users.insert("admin".to_string(), "admin".to_string());
        users.insert("user1".to_string(), "pass1".to_string());
        Self { users }
    }
}

impl Authenticator for PasswordAuthenticator {
    fn authenticate(&self, username: &str, password: &str) -> Result<UserInfo> {
        match self.users.get(username) {
            Some(stored_password) if stored_password == password => Ok(UserInfo {
                username: username.to_string(),
                groups: vec![],
                attributes: HashMap::new(),
            }),
            Some(_) => Err(anyhow!("Invalid password")),
            None => Err(anyhow!("User not found")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UserConfig;

    #[test]
    fn test_password_auth_success() {
        let users = vec![UserConfig {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        }];
        let auth = PasswordAuthenticator::new(users);
        let result = auth.authenticate("testuser", "testpass");
        assert!(result.is_ok());
    }

    #[test]
    fn test_password_auth_invalid_password() {
        let users = vec![UserConfig {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        }];
        let auth = PasswordAuthenticator::new(users);
        let result = auth.authenticate("testuser", "wrongpass");
        assert!(result.is_err());
    }

    #[test]
    fn test_password_auth_user_not_found() {
        let auth = PasswordAuthenticator::new(vec![]);
        let result = auth.authenticate("nonexistent", "password");
        assert!(result.is_err());
    }
}
