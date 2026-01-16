pub mod password;
pub mod session;

pub use password::*;
pub use session::*;

use anyhow::Result;

/// Authentication trait for different auth methods
pub trait Authenticator: Send + Sync {
    /// Authenticate user with provided credentials
    fn authenticate(&self, username: &str, credential: &str) -> Result<UserInfo>;
}

/// Authenticated user information
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub groups: Vec<String>,
    pub attributes: std::collections::HashMap<String, String>,
}
