//! JWT session provider implementation
//!
//! This module provides a stateless session provider using JSON Web Tokens (JWT).
//! JWTs are self-contained and don't require database lookups for validation.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};

use crate::{Error, JwtConfig, Session, SessionToken, UserId, error::SessionError};

use super::provider::SessionProvider;

/// JWT-based session provider
///
/// This provider creates and validates JWT tokens without requiring
/// any persistent storage. Sessions are entirely self-contained within
/// the JWT payload.
pub struct JwtSessionProvider {
    config: JwtConfig,
}

impl JwtSessionProvider {
    /// Create a new JWT session provider with the given configuration
    pub fn new(config: JwtConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl SessionProvider for JwtSessionProvider {
    async fn create_session(
        &self,
        user_id: &UserId,
        user_agent: Option<String>,
        ip_address: Option<String>,
        duration: Duration,
    ) -> Result<Session, Error> {
        let now = Utc::now();
        let expires_at = now + duration;

        // Create the session first
        let session = Session::builder()
            .user_id(user_id.clone())
            .user_agent(user_agent)
            .ip_address(ip_address)
            .created_at(now)
            .updated_at(now)
            .expires_at(expires_at)
            .build()?;

        // Generate JWT claims from the session
        let claims =
            session.to_jwt_claims(self.config.issuer.clone(), self.config.include_metadata);

        // Create the JWT token with the configured algorithm
        let jwt_token = SessionToken::new_jwt(&claims, &self.config)?;

        // Return a new session with the JWT token
        Ok(Session {
            token: jwt_token,
            ..session
        })
    }

    async fn get_session(&self, token: &SessionToken) -> Result<Session, Error> {
        // Verify the JWT using the configured algorithm and extract claims
        let claims = match token.verify_jwt(&self.config) {
            Ok(claims) => claims,
            Err(Error::Session(SessionError::InvalidToken(msg))) => {
                // Check if it's an expired token error from JWT validation
                if msg.contains("ExpiredSignature") {
                    return Err(Error::Session(SessionError::Expired));
                }
                return Err(Error::Session(SessionError::InvalidToken(msg)));
            }
            Err(e) => return Err(e),
        };

        // Check if token is expired
        let now = Utc::now();
        let exp = DateTime::from_timestamp(claims.exp, 0).unwrap_or(now);
        if now > exp {
            return Err(Error::Session(SessionError::Expired));
        }

        // Create session from JWT claims
        let session = Session::from_jwt_claims(token.clone(), &claims);

        Ok(session)
    }

    async fn delete_session(&self, _token: &SessionToken) -> Result<(), Error> {
        // JWTs are stateless, so we don't need to delete anything
        // Client should discard the token
        Ok(())
    }

    async fn cleanup_expired_sessions(&self) -> Result<(), Error> {
        // JWTs are self-expiring and stateless, nothing to clean up
        Ok(())
    }

    async fn delete_sessions_for_user(&self, _user_id: &UserId) -> Result<(), Error> {
        // Without a revocation list, we can't invalidate existing JWTs
        // This would require implementing a token blacklist
        tracing::warn!(
            "JwtSessionProvider doesn't support revoking all sessions for a user; tokens will remain valid until they expire"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HS256_SECRET: &[u8] = b"test_secret_key_for_hs256_jwt_tokens_not_for_production_use";

    #[tokio::test]
    async fn test_jwt_session_provider_create_and_get() {
        let config = JwtConfig::new_hs256(TEST_HS256_SECRET.to_vec())
            .with_issuer("test-issuer")
            .with_metadata(true);

        let provider = JwtSessionProvider::new(config);

        let user_id = UserId::new_random();
        let user_agent = Some("test-agent".to_string());
        let ip_address = Some("127.0.0.1".to_string());
        let duration = Duration::hours(1);

        // Create a session
        let session = provider
            .create_session(&user_id, user_agent.clone(), ip_address.clone(), duration)
            .await
            .unwrap();

        assert_eq!(session.user_id, user_id);
        assert_eq!(session.user_agent, user_agent);
        assert_eq!(session.ip_address, ip_address);

        // Retrieve the session
        let retrieved = provider.get_session(&session.token).await.unwrap();

        assert_eq!(retrieved.user_id, user_id);
        assert_eq!(retrieved.user_agent, user_agent);
        assert_eq!(retrieved.ip_address, ip_address);
    }

    #[tokio::test]
    async fn test_jwt_session_provider_expired_session() {
        let config = JwtConfig::new_hs256(TEST_HS256_SECRET.to_vec());
        let provider = JwtSessionProvider::new(config.clone());

        let user_id = UserId::new_random();

        // Create an already expired session
        let now = Utc::now();
        let session = Session::builder()
            .user_id(user_id.clone())
            .expires_at(now - Duration::minutes(5))
            .build()
            .unwrap();

        let claims = session.to_jwt_claims(None, false);
        let token = SessionToken::new_jwt(&claims, &config).unwrap();

        // Try to get the expired session
        let result = provider.get_session(&token).await;

        assert!(matches!(result, Err(Error::Session(SessionError::Expired))));
    }

    #[tokio::test]
    async fn test_jwt_session_provider_invalid_token() {
        let config = JwtConfig::new_hs256(TEST_HS256_SECRET.to_vec());
        let provider = JwtSessionProvider::new(config);

        // Create an invalid token
        let invalid_token = SessionToken::Jwt("invalid.jwt.token".to_string());

        let result = provider.get_session(&invalid_token).await;

        assert!(matches!(
            result,
            Err(Error::Session(SessionError::InvalidToken(_)))
        ));
    }
}
