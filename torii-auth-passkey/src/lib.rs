//! A passkey authentication plugin for Torii.
//!
//! This plugin provides passkey (WebAuthn) authentication capabilities to Torii applications.
//! It allows users to register and authenticate using passkeys (biometric authentication, security keys, etc).
//!
//! # Warning
//! This plugin is meant to be used as part of the Torii authentication framework and should not be
//! instantiated directly. Use Torii's plugin system to add passkey authentication to your application.
//!
//! # Features
//! - Passkey registration
//! - Passkey authentication
//! - Challenge-response based authentication flow
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use torii_core::error::{AuthError, PluginError, StorageError};
use torii_core::storage::PasskeyStorage;
use torii_core::{Error, Plugin, User, UserManager};
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// Unique identifier for a passkey challenge
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChallengeId(String);

impl ChallengeId {
    /// Create a new challenge ID from a string
    pub fn new(id: String) -> Self {
        Self(id)
    }

    /// Generate a new random challenge ID
    pub fn new_random() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Get the string representation of the challenge ID
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ChallengeId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ChallengeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Public-facing credential creation options for registering a new passkey
///
/// This is what is returned to the client when starting a passkey registration.
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyCredentialCreationOptions {
    /// The unique ID of the challenge
    pub challenge_id: ChallengeId,
    /// WebAuthn credential creation options to be passed to the client
    #[serde(rename = "publicKey")]
    pub options: serde_json::Value,
}

/// Public-facing credential request options for authenticating with a passkey
///
/// This is what is returned to the client when starting a passkey login.
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyCredentialRequestOptions {
    /// The unique ID of the challenge
    pub challenge_id: ChallengeId,
    /// WebAuthn credential request options to be passed to the client
    #[serde(rename = "publicKey")]
    pub options: serde_json::Value,
}

/// A request to register a new passkey
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyRegistrationRequest {
    /// The email address of the user
    pub email: String,
}

/// Client response to complete a passkey registration
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyRegistrationCompletion {
    /// The email address of the user
    pub email: String,
    /// The challenge ID from the initial registration request
    pub challenge_id: ChallengeId,
    /// The client's credential response
    pub response: RegisterPublicKeyCredential,
}

/// A request to authenticate with a passkey
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyLoginRequest {
    /// The email address of the user
    pub email: String,
}

/// Client response to complete a passkey login
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyLoginCompletion {
    /// The email address of the user
    pub email: String,
    /// The challenge ID from the initial login request
    pub challenge_id: ChallengeId,
    /// The client's credential response
    pub response: PublicKeyCredential,
}

/// Context for error messages to provide better diagnostics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyErrorContext {
    /// Error occurred during registration
    Registration,
    /// Error occurred during authentication
    Authentication,
    /// Error occurred during challenge processing
    Challenge,
    /// Error related to passkey storage
    Storage,
}

impl std::fmt::Display for PasskeyErrorContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registration => write!(f, "registration"),
            Self::Authentication => write!(f, "authentication"),
            Self::Challenge => write!(f, "challenge"),
            Self::Storage => write!(f, "storage"),
        }
    }
}

#[derive(Debug, Error)]
pub enum PasskeyError {
    #[error("[{context}] Webauthn error: {source}")]
    Webauthn {
        context: PasskeyErrorContext,
        #[source]
        source: WebauthnError,
    },

    #[error("[{context}] Invalid credentials")]
    InvalidCredentials { context: PasskeyErrorContext },

    #[error("[{context}] Passkey already exists")]
    PasskeyExists { context: PasskeyErrorContext },

    #[error("[{context}] Invalid challenge: {message}")]
    InvalidChallenge {
        context: PasskeyErrorContext,
        message: String,
    },

    #[error("[{context}] Invalid challenge response: {message}")]
    InvalidChallengeResponse {
        context: PasskeyErrorContext,
        message: String,
    },

    #[error("[{context}] Storage error: {message}")]
    StorageError {
        context: PasskeyErrorContext,
        message: String,
    },

    #[error("[{context}] User not found")]
    UserNotFound { context: PasskeyErrorContext },

    #[error("[{context}] Serialization error: {message}")]
    SerializationError {
        context: PasskeyErrorContext,
        message: String,
    },
}

impl From<PasskeyError> for Error {
    fn from(error: PasskeyError) -> Self {
        match error {
            PasskeyError::Webauthn { source, .. } => {
                Error::Plugin(PluginError::OperationFailed(source.to_string()))
            }
            PasskeyError::InvalidCredentials { .. } => Error::Auth(AuthError::InvalidCredentials),
            PasskeyError::PasskeyExists { .. } => Error::Auth(AuthError::UserAlreadyExists),
            PasskeyError::InvalidChallenge { .. } => Error::Auth(AuthError::InvalidCredentials),
            PasskeyError::InvalidChallengeResponse { .. } => {
                Error::Auth(AuthError::InvalidCredentials)
            }
            PasskeyError::StorageError { message, .. } => {
                Error::Storage(StorageError::Database(message))
            }
            PasskeyError::UserNotFound { .. } => Error::Auth(AuthError::UserNotFound),
            PasskeyError::SerializationError { message, .. } => {
                Error::Plugin(PluginError::OperationFailed(message))
            }
        }
    }
}

/// Trait defining passkey authentication functionality
#[async_trait]
pub trait PasskeyAuthPlugin: Plugin {
    /// Start a passkey registration and return the challenge to the client.
    /// The challenge is stored in the database for verification.
    async fn start_registration(
        &self,
        request: &PasskeyRegistrationRequest,
    ) -> Result<PasskeyCredentialCreationOptions, PasskeyError>;

    /// Complete a passkey registration and create a user in the user storage.
    /// Returns the user if the registration is successful.
    async fn complete_registration(
        &self,
        completion: &PasskeyRegistrationCompletion,
    ) -> Result<User, PasskeyError>;

    /// Start a passkey login and return the challenge to the client.
    /// The challenge is stored in the database for verification.
    async fn start_login(
        &self,
        request: &PasskeyLoginRequest,
    ) -> Result<PasskeyCredentialRequestOptions, PasskeyError>;

    /// Complete a passkey login.
    /// Returns the user if the login is successful.
    async fn complete_login(
        &self,
        completion: &PasskeyLoginCompletion,
    ) -> Result<User, PasskeyError>;
}

/// A plugin for managing passkey authentication.
///
/// This plugin provides functionality for registering and authenticating users using passkeys.
/// It allows users to start registration and login processes, and complete them using the provided
/// challenge responses.
pub struct PasskeyPlugin<M, S>
where
    M: UserManager,
    S: PasskeyStorage,
{
    webauthn: Webauthn,
    user_manager: Arc<M>,
    passkey_storage: Arc<S>,
}

impl<M, S> PasskeyPlugin<M, S>
where
    M: UserManager,
    S: PasskeyStorage,
{
    pub fn new(
        rp_id: &str,
        rp_origin: &str,
        user_manager: Arc<M>,
        passkey_storage: Arc<S>,
    ) -> Self {
        let rp_origin = Url::parse(rp_origin).expect("Failed to parse rp_origin");
        let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");
        let webauthn = builder.build().expect("Invalid configuration");

        Self {
            webauthn,
            user_manager,
            passkey_storage,
        }
    }
}

#[async_trait]
impl<M, S> PasskeyAuthPlugin for PasskeyPlugin<M, S>
where
    M: UserManager,
    S: PasskeyStorage,
{
    async fn start_registration(
        &self,
        request: &PasskeyRegistrationRequest,
    ) -> Result<PasskeyCredentialCreationOptions, PasskeyError> {
        let challenge_id = ChallengeId::new_random();

        // CCR is sent to the client, SKR is stored in the database for verification
        // We (currently) have no use for the user_unique_id after this point, but the API requires it
        // https://github.com/kanidm/webauthn-rs/issues/277
        let (ccr, skr) = self
            .webauthn
            .start_passkey_registration(Uuid::new_v4(), &request.email, &request.email, None)
            .map_err(|e| PasskeyError::Webauthn {
                context: PasskeyErrorContext::Registration,
                source: e,
            })?;

        // Serialize and store the challenge
        let skr_json =
            serde_json::to_string(&skr).map_err(|e| PasskeyError::SerializationError {
                context: PasskeyErrorContext::Registration,
                message: e.to_string(),
            })?;

        // Store the challenge with expiration
        self.passkey_storage
            .set_passkey_challenge(
                challenge_id.as_str(),
                &skr_json,
                chrono::Duration::minutes(5),
            )
            .await
            .map_err(|e| PasskeyError::StorageError {
                context: PasskeyErrorContext::Registration,
                message: e.to_string(),
            })?;

        // Serialize the client options
        let options_json =
            serde_json::to_value(&ccr).map_err(|e| PasskeyError::SerializationError {
                context: PasskeyErrorContext::Registration,
                message: e.to_string(),
            })?;

        Ok(PasskeyCredentialCreationOptions {
            challenge_id,
            options: options_json,
        })
    }

    async fn complete_registration(
        &self,
        completion: &PasskeyRegistrationCompletion,
    ) -> Result<User, PasskeyError> {
        // Check if the passkey already exists
        let passkey_exists = self
            .passkey_storage
            .get_passkey_by_credential_id(&completion.response.id)
            .await
            .map_err(|e| PasskeyError::StorageError {
                context: PasskeyErrorContext::Registration,
                message: e.to_string(),
            })?;

        if passkey_exists.is_some() {
            return Err(PasskeyError::PasskeyExists {
                context: PasskeyErrorContext::Registration,
            });
        }

        // Get the challenge from the database
        let passkey_challenge = self
            .passkey_storage
            .get_passkey_challenge(completion.challenge_id.as_str())
            .await
            .map_err(|e| PasskeyError::StorageError {
                context: PasskeyErrorContext::Challenge,
                message: e.to_string(),
            })?
            .ok_or(PasskeyError::InvalidChallenge {
                context: PasskeyErrorContext::Registration,
                message: "Challenge not found or expired".to_string(),
            })?;

        // Deserialize the challenge
        let passkey_challenge: PasskeyRegistration = serde_json::from_str(&passkey_challenge)
            .map_err(|e| PasskeyError::SerializationError {
                context: PasskeyErrorContext::Challenge,
                message: format!("Failed to deserialize challenge: {e}"),
            })?;

        // Finish the passkey registration
        let passkey = self
            .webauthn
            .finish_passkey_registration(&completion.response, &passkey_challenge)
            .map_err(|e| PasskeyError::Webauthn {
                context: PasskeyErrorContext::Registration,
                source: e,
            })?;

        // Get or create the user
        let user = self
            .user_manager
            .get_or_create_user_by_email(&completion.email)
            .await
            .map_err(|e| PasskeyError::StorageError {
                context: PasskeyErrorContext::Registration,
                message: e.to_string(),
            })?;

        // Serialize the passkey
        let passkey_json =
            serde_json::to_string(&passkey).map_err(|e| PasskeyError::SerializationError {
                context: PasskeyErrorContext::Registration,
                message: e.to_string(),
            })?;

        let cred_id = serde_json::to_string(&passkey.cred_id()).map_err(|e| {
            PasskeyError::SerializationError {
                context: PasskeyErrorContext::Registration,
                message: e.to_string(),
            }
        })?;

        // Add the passkey to the user
        self.passkey_storage
            .add_passkey(&user.id, &cred_id, &passkey_json)
            .await
            .map_err(|e| PasskeyError::StorageError {
                context: PasskeyErrorContext::Registration,
                message: e.to_string(),
            })?;

        Ok(user)
    }

    async fn start_login(
        &self,
        request: &PasskeyLoginRequest,
    ) -> Result<PasskeyCredentialRequestOptions, PasskeyError> {
        // Get the user by email
        let user = self
            .user_manager
            .get_user_by_email(&request.email)
            .await
            .map_err(|e| PasskeyError::StorageError {
                context: PasskeyErrorContext::Authentication,
                message: e.to_string(),
            })?
            .ok_or(PasskeyError::UserNotFound {
                context: PasskeyErrorContext::Authentication,
            })?;

        // Get the passkeys for the user
        let passkey_credentials =
            self.passkey_storage
                .get_passkeys(&user.id)
                .await
                .map_err(|e| PasskeyError::StorageError {
                    context: PasskeyErrorContext::Authentication,
                    message: e.to_string(),
                })?;

        if passkey_credentials.is_empty() {
            return Err(PasskeyError::InvalidCredentials {
                context: PasskeyErrorContext::Authentication,
            });
        }

        // Deserialize the passkeys into a vector of Passkey
        let allowed_credentials = passkey_credentials
            .iter()
            .filter_map(|cred| match serde_json::from_str::<Passkey>(cred) {
                Ok(pk) => Some(pk),
                Err(e) => {
                    tracing::error!(error = ?e, "Failed to deserialize passkey");
                    None
                }
            })
            .collect::<Vec<_>>();

        if allowed_credentials.is_empty() {
            return Err(PasskeyError::InvalidCredentials {
                context: PasskeyErrorContext::Authentication,
            });
        }

        // Start the passkey login
        let challenge_id = ChallengeId::new_random();
        let (rcr, rak) = self
            .webauthn
            .start_passkey_authentication(&allowed_credentials)
            .map_err(|e| PasskeyError::Webauthn {
                context: PasskeyErrorContext::Authentication,
                source: e,
            })?;

        // Serialize the authentication challenge
        let rak_json =
            serde_json::to_string(&rak).map_err(|e| PasskeyError::SerializationError {
                context: PasskeyErrorContext::Authentication,
                message: e.to_string(),
            })?;

        // Store the challenge in the database
        self.passkey_storage
            .set_passkey_challenge(
                challenge_id.as_str(),
                &rak_json,
                chrono::Duration::minutes(5),
            )
            .await
            .map_err(|e| PasskeyError::StorageError {
                context: PasskeyErrorContext::Authentication,
                message: e.to_string(),
            })?;

        // Serialize the client options
        let options_json =
            serde_json::to_value(&rcr).map_err(|e| PasskeyError::SerializationError {
                context: PasskeyErrorContext::Authentication,
                message: e.to_string(),
            })?;

        // Return the challenge
        Ok(PasskeyCredentialRequestOptions {
            challenge_id,
            options: options_json,
        })
    }

    async fn complete_login(
        &self,
        completion: &PasskeyLoginCompletion,
    ) -> Result<User, PasskeyError> {
        // Get the user by email
        let user = self
            .user_manager
            .get_user_by_email(&completion.email)
            .await
            .map_err(|e| PasskeyError::StorageError {
                context: PasskeyErrorContext::Authentication,
                message: e.to_string(),
            })?
            .ok_or(PasskeyError::UserNotFound {
                context: PasskeyErrorContext::Authentication,
            })?;

        // Get the challenge from the database
        let passkey_challenge = self
            .passkey_storage
            .get_passkey_challenge(completion.challenge_id.as_str())
            .await
            .map_err(|e| PasskeyError::StorageError {
                context: PasskeyErrorContext::Challenge,
                message: e.to_string(),
            })?
            .ok_or(PasskeyError::InvalidChallenge {
                context: PasskeyErrorContext::Authentication,
                message: "Challenge not found or expired".to_string(),
            })?;

        // Deserialize the challenge
        let passkey_challenge: PasskeyAuthentication = serde_json::from_str(&passkey_challenge)
            .map_err(|e| PasskeyError::SerializationError {
                context: PasskeyErrorContext::Challenge,
                message: format!("Failed to deserialize challenge: {e}"),
            })?;

        // Finish the passkey login
        self.webauthn
            .finish_passkey_authentication(&completion.response, &passkey_challenge)
            .map_err(|e| PasskeyError::Webauthn {
                context: PasskeyErrorContext::Authentication,
                source: e,
            })?;

        Ok(user)
    }
}

impl<M, S> Plugin for PasskeyPlugin<M, S>
where
    M: UserManager,
    S: PasskeyStorage,
{
    fn name(&self) -> String {
        "passkey".to_string()
    }
}
