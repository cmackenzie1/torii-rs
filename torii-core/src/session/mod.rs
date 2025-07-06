//! Session management
//!
//! This module contains the core session struct and related functionality.
//!
//! Sessions are used to track user sessions and are used to authenticate users. The core session struct is defined as follows:
//!
//! | Field        | Type             | Description                                            |
//! | ------------ | ---------------- | ------------------------------------------------------ |
//! | `id`         | `String`         | The unique identifier for the session.                 |
//! | `user_id`    | `String`         | The unique identifier for the user.                    |
//! | `user_agent` | `Option<String>` | The user agent of the client that created the session. |
//! | `ip_address` | `Option<String>` | The IP address of the client that created the session. |
//! | `created_at` | `DateTime`       | The timestamp when the session was created.            |
//! | `updated_at` | `DateTime`       | The timestamp when the session was last updated.       |
//! | `expires_at` | `DateTime`       | The timestamp when the session will expire.            |

pub mod jwt;
pub mod opaque;
pub mod provider;

use std::path::Path;

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::{TryRngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};

use crate::{
    Error,
    error::{SessionError, ValidationError},
    user::UserId,
};

// Re-export provider types for convenience
pub use jwt::JwtSessionProvider;
pub use opaque::OpaqueSessionProvider;
pub use provider::SessionProvider;

/// Generate a random string of the specified length
// TODO: Make this a try_generate_random_string?
// TODO: Add a time-based token generation method for happy B-Trees?
fn generate_random_string(length: usize) -> String {
    if length < 32 {
        panic!("Length must be at least 32");
    }
    let mut bytes = vec![0u8; length];
    OsRng.try_fill_bytes(&mut bytes).unwrap();
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

/// Session token type enum - either a simple opaque token or a JWT
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SessionToken {
    /// Opaque token - a token with at least 128 bits of entropy
    /// used for performing lookups in the session storage
    Opaque(String),
    /// JWT token - contains the session data within the token without
    /// any additional lookup in the session storage
    Jwt(String),
}

impl SessionToken {
    /// Create a new session token from an existing string
    pub fn new(token: &str) -> Self {
        // If the token looks like a JWT (contains two '.' separators), use JWT variant
        if token.chars().filter(|&c| c == '.').count() == 2 {
            SessionToken::Jwt(token.to_string())
        } else {
            SessionToken::Opaque(token.to_string())
        }
    }

    /// Create a new random opaque session token
    pub fn new_random() -> Self {
        SessionToken::Opaque(generate_random_string(32))
    }

    /// Create a new JWT session token with the specified algorithm
    pub fn new_jwt(claims: &JwtClaims, config: &JwtConfig) -> Result<Self, Error> {
        let header = Header::new(config.jwt_algorithm());

        let encoding_key = config.get_encoding_key()?;

        let token = encode(&header, claims, &encoding_key)
            .map_err(|e| SessionError::InvalidToken(format!("Failed to encode JWT: {e}")))?;

        Ok(SessionToken::Jwt(token))
    }

    /// Verify a JWT session token and return the claims
    pub fn verify_jwt(&self, config: &JwtConfig) -> Result<JwtClaims, Error> {
        match self {
            SessionToken::Jwt(token) => {
                let decoding_key = config.get_decoding_key()?;
                let validation = config.get_validation();

                let token_data =
                    decode::<JwtClaims>(token, &decoding_key, &validation).map_err(|e| {
                        SessionError::InvalidToken(format!("JWT validation failed: {e}"))
                    })?;

                Ok(token_data.claims)
            }
            SessionToken::Opaque(_) => Err(Error::Session(SessionError::InvalidToken(
                "Not a JWT token".to_string(),
            ))),
        }
    }

    /// Create a new JWT session token using RS256 algorithm
    pub fn new_jwt_rs256(claims: &JwtClaims, private_key: &[u8]) -> Result<Self, Error> {
        let config = JwtConfig::new_rs256(private_key.to_vec(), vec![]);
        Self::new_jwt(claims, &config)
    }

    /// Verify a JWT session token using RS256 algorithm and return the claims
    pub fn verify_jwt_rs256(&self, public_key: &[u8]) -> Result<JwtClaims, Error> {
        let config = JwtConfig::new_rs256(vec![], public_key.to_vec());
        self.verify_jwt(&config)
    }

    /// Create a new JWT session token using HS256 algorithm
    pub fn new_jwt_hs256(claims: &JwtClaims, secret_key: &[u8]) -> Result<Self, Error> {
        let config = JwtConfig::new_hs256(secret_key.to_vec());
        Self::new_jwt(claims, &config)
    }

    /// Verify a JWT session token using HS256 algorithm and return the claims
    pub fn verify_jwt_hs256(&self, secret_key: &[u8]) -> Result<JwtClaims, Error> {
        let config = JwtConfig::new_hs256(secret_key.to_vec());
        self.verify_jwt(&config)
    }

    /// Get the inner token string
    pub fn into_inner(self) -> String {
        match self {
            SessionToken::Opaque(token) => token,
            SessionToken::Jwt(token) => token,
        }
    }

    /// Get a reference to the token string
    pub fn as_str(&self) -> &str {
        match self {
            SessionToken::Opaque(token) => token,
            SessionToken::Jwt(token) => token,
        }
    }
}

impl Default for SessionToken {
    fn default() -> Self {
        Self::new_random()
    }
}

impl From<String> for SessionToken {
    fn from(s: String) -> Self {
        Self::new(&s)
    }
}

impl From<&str> for SessionToken {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

// TODO: wrap in secrecy string to prevent accidental leaks?
impl std::fmt::Display for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionToken::Opaque(token) => write!(f, "{token}"),
            SessionToken::Jwt(token) => write!(f, "{token}"),
        }
    }
}

/// JWT claims for session tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject - user ID
    pub sub: String,
    /// Issued at in seconds (as UTC timestamp)
    pub iat: i64,
    /// Expiration time in seconds (as UTC timestamp)
    pub exp: i64,
    /// Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Additional data (IP, user agent, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<JwtMetadata>,
}

/// JWT metadata for additional session data
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtMetadata {
    /// User agent string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
}

/// JWT algorithm type
#[derive(Debug, Clone)]
pub enum JwtAlgorithm {
    /// RS256 - RSA with SHA-256
    RS256 {
        /// Private key for signing JWTs (PEM format)
        private_key: Vec<u8>,
        /// Public key for verifying JWTs (PEM format)
        public_key: Vec<u8>,
    },
    /// HS256 - HMAC with SHA-256
    HS256 {
        /// Secret key for both signing and verifying
        secret_key: Vec<u8>,
    },
}

/// Configuration for JWT sessions
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// Algorithm and keys for JWT
    pub algorithm: JwtAlgorithm,
    /// Issuer claim
    pub issuer: Option<String>,
    /// Whether to include metadata (IP, user agent) in the JWT
    pub include_metadata: bool,
}

impl JwtConfig {
    /// Create a new JWT configuration with RS256 algorithm
    pub fn new_rs256(private_key: Vec<u8>, public_key: Vec<u8>) -> Self {
        Self {
            algorithm: JwtAlgorithm::RS256 {
                private_key,
                public_key,
            },
            issuer: None,
            include_metadata: false,
        }
    }

    /// Create a new JWT configuration with HS256 algorithm
    pub fn new_hs256(secret_key: Vec<u8>) -> Self {
        Self {
            algorithm: JwtAlgorithm::HS256 { secret_key },
            issuer: None,
            include_metadata: false,
        }
    }

    /// Create a new JWT configuration from RSA key files (PEM format)
    pub fn from_rs256_pem_files(
        private_key_path: impl AsRef<Path>,
        public_key_path: impl AsRef<Path>,
    ) -> Result<Self, Error> {
        use std::fs::read;

        let private_key = read(private_key_path).map_err(|e| {
            ValidationError::InvalidField(format!("Failed to read private key file: {e}"))
        })?;

        let public_key = read(public_key_path).map_err(|e| {
            ValidationError::InvalidField(format!("Failed to read public key file: {e}"))
        })?;

        Ok(Self::new_rs256(private_key, public_key))
    }

    /// Create a JWT configuration with a random HS256 secret key (for testing)
    #[cfg(test)]
    pub fn new_random_hs256() -> Self {
        use rand::TryRngCore;

        let mut secret_key = vec![0u8; 32];
        rand::rng().try_fill_bytes(&mut secret_key).unwrap();
        Self::new_hs256(secret_key)
    }

    /// Set the issuer claim
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Set whether to include metadata in the JWT
    pub fn with_metadata(mut self, include_metadata: bool) -> Self {
        self.include_metadata = include_metadata;
        self
    }

    /// Get the algorithm to use with jsonwebtoken
    pub fn jwt_algorithm(&self) -> Algorithm {
        match &self.algorithm {
            JwtAlgorithm::RS256 { .. } => Algorithm::RS256,
            JwtAlgorithm::HS256 { .. } => Algorithm::HS256,
        }
    }

    /// Get the encoding key for signing
    // TODO: Store the key in the config struct instead of creating a new key each time for performance
    pub fn get_encoding_key(&self) -> Result<EncodingKey, Error> {
        match &self.algorithm {
            JwtAlgorithm::RS256 { private_key, .. } => EncodingKey::from_rsa_pem(private_key)
                .map_err(|e| {
                    ValidationError::InvalidField(format!("Invalid RSA private key: {e}")).into()
                }),
            JwtAlgorithm::HS256 { secret_key } => Ok(EncodingKey::from_secret(secret_key)),
        }
    }

    /// Get the decoding key for verification
    pub fn get_decoding_key(&self) -> Result<DecodingKey, Error> {
        match &self.algorithm {
            JwtAlgorithm::RS256 { public_key, .. } => DecodingKey::from_rsa_pem(public_key)
                .map_err(|e| {
                    ValidationError::InvalidField(format!("Invalid RSA public key: {e}")).into()
                }),
            JwtAlgorithm::HS256 { secret_key } => Ok(DecodingKey::from_secret(secret_key)),
        }
    }

    /// Get the validation configuration for JWT verification
    pub fn get_validation(&self) -> Validation {
        Validation::new(self.jwt_algorithm())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// The unique identifier for the session.
    pub token: SessionToken,

    /// The unique identifier for the user.
    pub user_id: UserId,

    /// The user agent of the client that created the session.
    pub user_agent: Option<String>,

    /// The IP address of the client that created the session.
    pub ip_address: Option<String>,

    /// The timestamp when the session was created.
    pub created_at: DateTime<Utc>,

    /// The timestamp when the session was last updated.
    pub updated_at: DateTime<Utc>,

    /// The timestamp when the session will expire.
    pub expires_at: DateTime<Utc>,
}

impl Session {
    pub fn builder() -> SessionBuilder {
        SessionBuilder::default()
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Convert session to JWT claims
    pub fn to_jwt_claims(&self, issuer: Option<String>, include_metadata: bool) -> JwtClaims {
        let metadata = if include_metadata {
            Some(JwtMetadata {
                user_agent: self.user_agent.clone(),
                ip_address: self.ip_address.clone(),
            })
        } else {
            None
        };

        JwtClaims {
            sub: self.user_id.to_string(),
            iat: self.created_at.timestamp(),
            exp: self.expires_at.timestamp(),
            iss: issuer,
            metadata,
        }
    }

    /// Create a session from JWT claims
    pub fn from_jwt_claims(token: SessionToken, claims: &JwtClaims) -> Self {
        let now = Utc::now();
        let created_at = DateTime::from_timestamp(claims.iat, 0).unwrap_or(now);
        let expires_at = DateTime::from_timestamp(claims.exp, 0).unwrap_or(now);

        let (user_agent, ip_address) = if let Some(metadata) = &claims.metadata {
            (metadata.user_agent.clone(), metadata.ip_address.clone())
        } else {
            (None, None)
        };

        Self {
            token,
            user_id: UserId::new(&claims.sub),
            user_agent,
            ip_address,
            created_at,
            updated_at: now,
            expires_at,
        }
    }
}

#[derive(Default)]
pub struct SessionBuilder {
    token: Option<SessionToken>,
    user_id: Option<UserId>,
    user_agent: Option<String>,
    ip_address: Option<String>,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
}

impl SessionBuilder {
    pub fn token(mut self, token: SessionToken) -> Self {
        self.token = Some(token);
        self
    }

    pub fn user_id(mut self, user_id: UserId) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn user_agent(mut self, user_agent: Option<String>) -> Self {
        self.user_agent = user_agent;
        self
    }

    pub fn ip_address(mut self, ip_address: Option<String>) -> Self {
        self.ip_address = ip_address;
        self
    }

    pub fn created_at(mut self, created_at: DateTime<Utc>) -> Self {
        self.created_at = Some(created_at);
        self
    }

    pub fn updated_at(mut self, updated_at: DateTime<Utc>) -> Self {
        self.updated_at = Some(updated_at);
        self
    }

    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn build(self) -> Result<Session, Error> {
        let now = Utc::now();
        Ok(Session {
            token: self.token.unwrap_or_default(),
            user_id: self.user_id.ok_or(ValidationError::MissingField(
                "User ID is required".to_string(),
            ))?,
            user_agent: self.user_agent,
            ip_address: self.ip_address,
            created_at: self.created_at.unwrap_or(now),
            updated_at: self.updated_at.unwrap_or(now),
            expires_at: self.expires_at.unwrap_or(now + Duration::days(30)),
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    // Test secret for HS256
    const TEST_HS256_SECRET: &[u8] = b"this_is_a_test_secret_key_for_hs256_jwt_tokens_not_for_prod";

    // Test private key for RS256
    // DO NOT EVER USE THIS KEY FOR ANYTHING REAL
    const TEST_RS256_PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDBsFIR164UGIOZ
R2nT57RQ8AloqAmJXh5KdoKZjHi5uSRALSASp1Dk0tDjiiwqvfWiUItcVqZRqsx4
VuzjpkdoeWvwBoJ91K+DjFEAG7RjbNoaITgY8Ec5QjulpLTh9WDUeqUu4ZxPp9rF
H+S3uJK2sD1K2KOGRVcT0a+rIyXDOXr14J7XGbB5W7j2EvkKXZinzKcdMpsL4NBu
8ArJ8qV6lLBeKB+IbKrV0yUQGFAjTA8eoaSNaHJAZD0kubEdXEprB1SZpvaL3lZM
AcqS6ZATo8IfiXj7H7RSHLf3ORYxQTX4T01gSfmSfgEOdTySdCSuFmDrsjcR2nWe
Ly0QWM4jAgMBAAECggEAG9wzueWhtbn0TVB54aVjCP9grcFPTzHkE9w/GzzFmBq6
+FDlW6QzMm7mkCGYX8o03RT5Lsjh9z5PrKxS5R35CIc/+5Bxew25n1JIIRwFvbAd
y9i6ZnqYFsg2/IkYDFE3jT4E/keCgeyy6bGVkchcBijh8B8ASo3fzCCDGbqeXG8V
9WEhN+xrEwJ/5s3IYY0JSVrL4BzoQT/R9/+IsvUQw9aOECDXpFsRLjoze3JVXzYa
LklDJWe1z3i+4mR/Gwx1GLRL64bJFz0u8zUVSkY5T3SZLr7HGjlrtc/7DIctyx5w
h80nRDohVih69z1AViXSIzYRvJ3tIq8Gp5EvYjieZQKBgQDi1Y5hvn8+KO9+9mPK
lx/P92M1pUfSuALILctFWyFbY7XKYApJud0Nme81ASaNofINpka7tWOEBk8H0lyy
W9uELDYHtVxKU0Ch1Q0joeKb3vcF0wMBMdOiOef+AH4R9ZqF8Mbhc/lwb86vl1BL
1zFQZVpjg0Un57PMKefwl/yS5wKBgQDal8DTj1UaOGjsx667nUE1x6ILdRlHMIe1
lf1VqCkP8ykFMe3iDJE1/rW/ct8uO+ZEf/8nbjeCHcnrtdF14HEPdspCSGvXW87W
65Lsx0O7gdMKZEnN7BarTikpWJU3COcgQHGFsqjZ+07ujQWj8dPrNTd9dsYYFky8
OKtmXJQ/ZQKBgA5G/NBAKkgiUXi/T2an/nObkZ4FyjCELoClCT9TThUvgHi9dMhR
L420m67NZLzTbaXYSml0MFBWCVFntzfuujFmivwPOUDgXpgRDeOpQ9clwIyYTH8d
wMFcPbLqGwVMXS6DCjGUmCWwk+TPdFlhsRPrXTYYRBkP52w5UwT8vAQPAoGAZEMu
4trfggNVvSVp9AwRGQXUQcUYLxsHZDbD2EIlc3do3UUlg4WYJVgLLSEXVTGMUOcU
tZVMSJY5Q7BFvvePZDRsWTK2pDUsDlBHN+u+GYdWsXGGmLktPK3BG4HSD0g6GwT0
DQsBf9pRPgHZEHWfakciiJ2uBuZTlBG6LF1ScjECgYEA4DPQopjh/kS9j5NyUMDA
5Pvz2mppg0NR7RQjDGET3Lh4/lDgfFyJOlsRLF+kUgAOb4s3tPg+5hujTq2FpotK
JFQKh2GE6V1BMi+qJ9ipj0ESBv7rqPYC8ShUSr/SbkRU8jg2tOcvw+7KNtaMk6rv
wl6BPaq7Rv4JOPgimQGP3d4=
-----END PRIVATE KEY-----";

    const TEST_RS256_PUBLIC_KEY: &[u8] = b"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbBSEdeuFBiDmUdp0+e0
UPAJaKgJiV4eSnaCmYx4ubkkQC0gEqdQ5NLQ44osKr31olCLXFamUarMeFbs46ZH
aHlr8AaCfdSvg4xRABu0Y2zaGiE4GPBHOUI7paS04fVg1HqlLuGcT6faxR/kt7iS
trA9StijhkVXE9GvqyMlwzl69eCe1xmweVu49hL5Cl2Yp8ynHTKbC+DQbvAKyfKl
epSwXigfiGyq1dMlEBhQI0wPHqGkjWhyQGQ9JLmxHVxKawdUmab2i95WTAHKkumQ
E6PCH4l4+x+0Uhy39zkWMUE1+E9NYEn5kn4BDnU8knQkrhZg67I3Edp1ni8tEFjO
IwIDAQAB
-----END PUBLIC KEY-----";

    #[test]
    fn test_random_rs256_key_generation() {
        // Generate a random keypair
        let config = JwtConfig::new_rs256(
            TEST_RS256_PRIVATE_KEY.to_vec(),
            TEST_RS256_PUBLIC_KEY.to_vec(),
        );

        // Verify the keys are valid by creating and verifying a token
        let user_id = UserId::new_random();
        let session = Session::builder()
            .user_id(user_id.clone())
            .expires_at(Utc::now() + Duration::days(1))
            .build()
            .unwrap();

        let claims = session.to_jwt_claims(None, false);

        // Create JWT token
        let token = SessionToken::new_jwt(&claims, &config).unwrap();

        // Verify JWT token
        let verified_claims = token.verify_jwt(&config).unwrap();

        // Basic verification that keys work
        assert_eq!(verified_claims.sub, user_id.to_string());
    }

    #[test]
    fn test_session_token_simple() {
        let id = SessionToken::new_random();
        match &id {
            SessionToken::Opaque(token) => {
                assert_eq!(id.to_string(), token.to_string());
            }
            _ => panic!("Expected simple token"),
        }
    }

    #[test]
    fn test_session_builder() {
        let session = Session::builder()
            .user_id(UserId::new_random())
            .user_agent(Some("test".to_string()))
            .ip_address(Some("127.0.0.1".to_string()))
            .expires_at(Utc::now() + Duration::days(30))
            .build()
            .unwrap();

        assert!(!session.is_expired());
    }

    #[test]
    fn test_jwt_config_hs256() {
        let config = JwtConfig::new_hs256(TEST_HS256_SECRET.to_vec());

        match &config.algorithm {
            JwtAlgorithm::HS256 { secret_key } => {
                assert_eq!(secret_key, &TEST_HS256_SECRET.to_vec());
            }
            _ => panic!("Expected HS256 algorithm"),
        }

        assert_eq!(config.jwt_algorithm(), Algorithm::HS256);
    }

    #[test]
    fn test_jwt_config_random_hs256() {
        let config = JwtConfig::new_random_hs256();

        match &config.algorithm {
            JwtAlgorithm::HS256 { secret_key } => {
                assert_eq!(secret_key.len(), 32);
            }
            _ => panic!("Expected HS256 algorithm"),
        }
    }

    #[test]
    fn test_jwt_token_creation_and_verification_hs256() {
        let config = JwtConfig::new_hs256(TEST_HS256_SECRET.to_vec())
            .with_issuer("test-issuer-hs256")
            .with_metadata(true);

        let user_id = UserId::new_random();
        let session = Session::builder()
            .user_id(user_id.clone())
            .user_agent(Some("test-agent-hs256".to_string()))
            .ip_address(Some("127.0.0.2".to_string()))
            .expires_at(Utc::now() + Duration::days(1))
            .build()
            .unwrap();

        // Create JWT claims from session
        let claims = session.to_jwt_claims(config.issuer.clone(), config.include_metadata);

        // Create JWT token with HS256
        let token = SessionToken::new_jwt(&claims, &config).unwrap();

        // Verify JWT token with HS256
        let verified_claims = token.verify_jwt(&config).unwrap();

        assert_eq!(verified_claims.sub, user_id.to_string());
        assert_eq!(verified_claims.iss, Some("test-issuer-hs256".to_string()));
        assert!(verified_claims.metadata.is_some());
        let metadata = verified_claims.metadata.unwrap();
        assert_eq!(metadata.user_agent, Some("test-agent-hs256".to_string()));
        assert_eq!(metadata.ip_address, Some("127.0.0.2".to_string()));

        // Helper methods should also work
        let token2 = SessionToken::new_jwt_hs256(&claims, TEST_HS256_SECRET).unwrap();
        let verified_claims2 = token2.verify_jwt_hs256(TEST_HS256_SECRET).unwrap();
        assert_eq!(verified_claims2.sub, user_id.to_string());
    }
}
