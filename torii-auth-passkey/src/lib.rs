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

use serde::{Deserialize, Serialize};
use thiserror::Error;
use torii_core::error::{AuthError, PluginError, StorageError};
use torii_core::storage::PasskeyStorage;
use torii_core::{Error, Plugin, User, UserId};
use webauthn_rs::prelude::*;

#[derive(Debug, Error)]
pub enum PasskeyError {
    #[error("Webauthn error: {0}")]
    Webauthn(#[from] WebauthnError),

    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Passkey exists")]
    PasskeyExists,
    #[error("Invalid challenge")]
    InvalidChallenge,
    #[error("Invalid challenge response")]
    InvalidChallengeResponse,
    #[error("Invalid challenge response format")]
    InvalidChallengeResponseFormat,

    #[error("Storage error: {0}")]
    StorageError(String),
}

impl From<PasskeyError> for Error {
    fn from(error: PasskeyError) -> Self {
        match error {
            PasskeyError::Webauthn(e) => Error::Plugin(PluginError::OperationFailed(e.to_string())),
            PasskeyError::InvalidCredentials => Error::Auth(AuthError::InvalidCredentials),
            PasskeyError::PasskeyExists => Error::Auth(AuthError::UserAlreadyExists),
            PasskeyError::InvalidChallenge => Error::Auth(AuthError::InvalidCredentials),
            PasskeyError::InvalidChallengeResponse => Error::Auth(AuthError::InvalidCredentials),
            PasskeyError::InvalidChallengeResponseFormat => {
                Error::Auth(AuthError::InvalidCredentials)
            }
            PasskeyError::StorageError(e) => Error::Storage(StorageError::Database(e)),
        }
    }
}

/// A plugin for managing passkey authentication.
///
/// This plugin provides functionality for registering and authenticating users using passkeys.
/// It allows users to start registration and login processes, and complete them using the provided
/// challenge responses.
pub struct PasskeyPlugin<U: PasskeyStorage> {
    webauthn: Webauthn,
    user_storage: Arc<U>,
}

/// A challenge for a passkey authentication process.
///
/// This struct represents a challenge for a passkey authentication process. It contains the user ID,
/// the challenge ID, and the challenge response.
///
/// # Fields
/// - `user_id`: The ID of the user that the challenge belongs to.
/// - `challenge_id`: The ID of the challenge.
/// - `challenge`: The challenge response. This is typically a JSON object containing the challenge
///   response from the WebAuthn library.
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyChallenge {
    user_id: UserId,
    challenge_id: String,
    challenge: serde_json::Value,
}

impl PasskeyChallenge {
    pub fn new(user_id: UserId, challenge_id: String, challenge: serde_json::Value) -> Self {
        Self {
            user_id,
            challenge_id,
            challenge,
        }
    }

    /// Get the ID of the challenge.
    pub fn challenge_id(&self) -> &String {
        &self.challenge_id
    }

    /// Get the challenge response.
    pub fn challenge(&self) -> &serde_json::Value {
        &self.challenge
    }
}

impl<U: PasskeyStorage> PasskeyPlugin<U> {
    pub fn new(rp_id: &str, rp_origin: &str, user_storage: Arc<U>) -> Self {
        let rp_origin = Url::parse(rp_origin).expect("Failed to parse rp_origin");
        let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");
        let webauthn = builder.build().expect("Invalid configuration");

        Self {
            webauthn,
            user_storage,
        }
    }

    /// Start a passkey registration and return the challenge to the client.
    /// The challenge is stored in the database for verification.
    /// Returns a challenge that should be sent to the client.
    pub async fn start_registration(&self, email: &str) -> Result<PasskeyChallenge, PasskeyError> {
        let challenge_id = Uuid::new_v4();
        // CCR is sent to the client, SKR is stored in the database for verification
        // We (currently) have no use for the user_unique_id after this point, but the API requires it
        // https://github.com/kanidm/webauthn-rs/issues/277
        let (ccr, skr) = self
            .webauthn
            .start_passkey_registration(Uuid::new_v4(), email, email, None)
            .expect("Failed to start registration.");

        self.user_storage
            .set_passkey_challenge(
                &challenge_id.to_string(),
                &serde_json::to_string(&skr).unwrap_or_else(|e| {
                    tracing::error!(error = ?e, "Failed to serialize challenge");
                    "".to_string()
                }),
                chrono::Duration::minutes(5),
            )
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to set passkey challenge");
                PasskeyError::StorageError(e.to_string())
            })?;

        Ok(PasskeyChallenge::new(
            UserId::new_random(),
            challenge_id.to_string(),
            serde_json::to_value(&ccr).unwrap_or_else(|e| {
                tracing::error!(error = ?e, "Failed to serialize challenge");
                serde_json::Value::Null
            }),
        ))
    }

    /// Complete a passkey registration and create a user in the user storage.
    /// Returns the user if the registration is successful.
    pub async fn complete_registration(
        &self,
        email: &str,
        challenge_id: &str,
        challenge_response: &serde_json::Value,
    ) -> Result<User, PasskeyError> {
        let challenge_response: RegisterPublicKeyCredential =
            serde_json::from_value::<RegisterPublicKeyCredential>(challenge_response.clone())
                .map_err(|e| {
                    tracing::error!(error = ?e, "Failed to deserialize challenge response");
                    PasskeyError::InvalidChallengeResponseFormat
                })?;

        // Check if the passkey already exists
        let passkey_exists = self
            .user_storage
            .get_passkey_by_credential_id(&challenge_response.id)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to get passkey by credential id");
                PasskeyError::StorageError(e.to_string())
            })?;

        if passkey_exists.is_some() {
            return Err(PasskeyError::PasskeyExists);
        }

        // Get the challenge from the database
        let passkey_challenge = self
            .user_storage
            .get_passkey_challenge(challenge_id)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to get passkey challenge");
                PasskeyError::StorageError(e.to_string())
            })?
            .ok_or(PasskeyError::InvalidChallenge)?;

        // Deserialize the challenge into a PasskeyRegistration
        let passkey_challenge: PasskeyRegistration =
            serde_json::from_str::<PasskeyRegistration>(&passkey_challenge).map_err(|e| {
                tracing::error!(error = ?e, "Failed to deserialize passkey challenge");
                PasskeyError::InvalidChallengeResponseFormat
            })?;

        // Finish the passkey registration
        let passkey = self
            .webauthn
            .finish_passkey_registration(&challenge_response, &passkey_challenge)
            .expect("Failed to complete registration.");

        // Get or create the user
        let user = self
            .user_storage
            .get_or_create_user_by_email(email)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to get or create user by email");
                PasskeyError::StorageError(e.to_string())
            })?;

        // Add the passkey to the user
        self.user_storage
            .add_passkey(
                &user.id,
                &serde_json::to_string(&passkey.cred_id()).unwrap(),
                &serde_json::to_string(&passkey).unwrap(),
            )
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to add passkey");
                PasskeyError::StorageError(e.to_string())
            })?;

        Ok(user)
    }

    /// Start a passkey login and return the challenge to the client.
    /// The challenge is stored in the database for verification.
    /// Returns a challenge that should be sent to the client.
    pub async fn start_login(&self, email: &str) -> Result<PasskeyChallenge, PasskeyError> {
        let user = self
            .user_storage
            .get_user_by_email(email)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to get user by email");
                PasskeyError::StorageError(e.to_string())
            })?
            .ok_or(PasskeyError::InvalidCredentials)?;

        // Get the passkeys for the user
        let passkey_credentials = self
            .user_storage
            .get_passkeys(&user.id)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to get passkeys");
                PasskeyError::StorageError(e.to_string())
            })?;

        // Deserialize the passkeys into a vector of Passkey
        let allowed_credentials = passkey_credentials
            .iter()
            .map(|cred| serde_json::from_str::<Passkey>(cred).unwrap())
            .collect::<Vec<_>>();

        // Start the passkey login
        let challenge_id = Uuid::new_v4();
        let (rcr, rak) = self
            .webauthn
            .start_passkey_authentication(&allowed_credentials)
            .expect("Failed to start login.");

        // Store the challenge in the database
        self.user_storage
            .set_passkey_challenge(
                &challenge_id.to_string(),
                &serde_json::to_string(&rak).unwrap(),
                chrono::Duration::minutes(5),
            )
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to set passkey challenge");
                PasskeyError::StorageError(e.to_string())
            })?;

        // Return the challenge
        Ok(PasskeyChallenge::new(
            user.id,
            challenge_id.to_string(),
            serde_json::to_value(&rcr).unwrap(),
        ))
    }

    /// Complete a passkey login.
    /// Returns the user if the login is successful.
    pub async fn complete_login(
        &self,
        email: &str,
        challenge_id: &str,
        challenge_response: &serde_json::Value,
    ) -> Result<User, PasskeyError> {
        // Get the user by email
        let user = self
            .user_storage
            .get_user_by_email(email)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to get user by email");
                PasskeyError::StorageError(e.to_string())
            })?
            .ok_or(PasskeyError::InvalidCredentials)?;

        // Get the challenge from the database
        let passkey_challenge = self
            .user_storage
            .get_passkey_challenge(challenge_id)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to get passkey challenge");
                PasskeyError::StorageError(e.to_string())
            })?
            .ok_or(PasskeyError::InvalidChallenge)?;

        // Deserialize the challenge into a PasskeyAuthentication
        let passkey_challenge = serde_json::from_str::<PasskeyAuthentication>(&passkey_challenge)
            .map_err(|e| {
            tracing::error!(error = ?e, "Failed to deserialize passkey challenge");
            PasskeyError::InvalidChallengeResponseFormat
        })?;

        // Deserialize the challenge response into a PublicKeyCredential
        let challenge_response: PublicKeyCredential =
            serde_json::from_value(challenge_response.clone()).map_err(|e| {
                tracing::error!(error = ?e, "Failed to deserialize challenge response");
                PasskeyError::InvalidChallengeResponseFormat
            })?;

        // Finish the passkey login
        let _ = self
            .webauthn
            .finish_passkey_authentication(&challenge_response, &passkey_challenge)
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to complete login");
                PasskeyError::InvalidCredentials
            })?;

        Ok(user)
    }
}

impl<U: PasskeyStorage> Plugin for PasskeyPlugin<U> {
    fn name(&self) -> String {
        "passkey".to_string()
    }
}
