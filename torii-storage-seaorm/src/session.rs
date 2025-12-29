use torii_core::session::SessionToken;
use torii_core::{Session, UserId};

use crate::entities::session;

/// Convert a database session model to a Session.
///
/// Note: The token field in the database stores the hash, not the plaintext.
/// When loading from storage, we create a "placeholder" token that contains the hash.
/// This allows verification via constant-time comparison, but the original
/// plaintext token is not recoverable (by design).
impl From<session::Model> for Session {
    fn from(value: session::Model) -> Self {
        // The database stores the hash in the 'token' column
        // We create a placeholder token - actual verification should use verify_hash
        Self {
            token: SessionToken::new(&value.token),
            token_hash: value.token.clone(),
            user_id: UserId::new(&value.user_id),
            user_agent: value.user_agent.to_owned(),
            ip_address: value.ip_address.to_owned(),
            created_at: value.created_at.to_owned(),
            updated_at: value.updated_at.to_owned(),
            expires_at: value.expires_at.to_owned(),
        }
    }
}
