use anyhow::{bail, Result};
use std::collections::HashMap;

use super::{Authenticator, UserInfo};

/// Simple password authenticator with in-memory user database
pub struct PasswordAuthenticator {
    users: HashMap<String, String>, // username -> password hash (plaintext for now)
}

impl PasswordAuthenticator {
    pub fn new() -> Self {
        let mut users = HashMap::new();

        // Add some test users (in production, load from config/database)
        users.insert("test".to_string(), "test".to_string());
        users.insert("admin".to_string(), "admin".to_string());
        users.insert("user1".to_string(), "pass1".to_string());

        Self { users }
    }

    pub fn add_user(&mut self, username: String, password: String) {
        self.users.insert(username, password);
    }
}

impl Authenticator for PasswordAuthenticator {
    fn authenticate(&self, username: &str, credential: &str) -> Result<UserInfo> {
        match self.users.get(username) {
            Some(stored_password) if stored_password == credential => Ok(UserInfo {
                username: username.to_string(),
                groups: vec!["users".to_string()],
                attributes: HashMap::new(),
            }),
            Some(_) => bail!("Invalid password for user: {}", username),
            None => bail!("User not found: {}", username),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_auth_success() {
        let auth = PasswordAuthenticator::new();
        let result = auth.authenticate("test", "test");
        assert!(result.is_ok());

        let user_info = result.unwrap();
        assert_eq!(user_info.username, "test");
    }

    #[test]
    fn test_password_auth_invalid_password() {
        let auth = PasswordAuthenticator::new();
        let result = auth.authenticate("test", "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_password_auth_user_not_found() {
        let auth = PasswordAuthenticator::new();
        let result = auth.authenticate("nonexistent", "password");
        assert!(result.is_err());
    }
}
