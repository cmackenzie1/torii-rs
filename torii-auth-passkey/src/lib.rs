use serde::{Deserialize, Serialize};
use thiserror::Error;
use torii_core::error::{AuthError, PluginError, StorageError};
use torii_core::storage::{PasskeyStorage, SessionStorage, Storage};
use torii_core::{Error, Plugin, Session, User, UserId};
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

pub struct PasskeyPlugin<U: PasskeyStorage, S: SessionStorage> {
    webauthn: Webauthn,
    storage: Storage<U, S>,
}

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

    pub fn challenge_id(&self) -> &String {
        &self.challenge_id
    }

    pub fn challenge(&self) -> &serde_json::Value {
        &self.challenge
    }
}

impl<U: PasskeyStorage, S: SessionStorage> PasskeyPlugin<U, S> {
    pub fn new(rp_id: &str, rp_origin: &str, storage: Storage<U, S>) -> Self {
        let rp_origin = Url::parse(rp_origin).expect("Failed to parse rp_origin");
        let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");
        let webauthn = builder.build().expect("Invalid configuration");

        Self { webauthn, storage }
    }

    /// Start a passkey registration and return the challenge to the client.
    /// The challenge is stored in the database for verification.
    /// Returns a tuple of the challenge
    pub async fn start_registration(&self, email: &str) -> Result<PasskeyChallenge, PasskeyError> {
        let challenge_id = Uuid::new_v4();
        let user_id = UserId::new_random();
        // CCR is sent to the client, SKR is stored in the database for verification
        let (ccr, skr) = self
            .webauthn
            .start_passkey_registration(user_id.as_uuid(), email, email, None)
            .expect("Failed to start registration.");

        self.storage
            .user_storage()
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
            user_id,
            challenge_id.to_string(),
            serde_json::to_value(&ccr).unwrap_or_else(|e| {
                tracing::error!(error = ?e, "Failed to serialize challenge");
                serde_json::Value::Null
            }),
        ))
    }

    /// Complete a passkey registration and create a user in the user storage.
    pub async fn complete_registration(
        &self,
        email: &str,
        challenge_id: &str,
        challenge_response: &serde_json::Value,
    ) -> Result<(User, Session), PasskeyError> {
        let challenge_response: RegisterPublicKeyCredential =
            serde_json::from_value::<RegisterPublicKeyCredential>(challenge_response.clone())
                .map_err(|e| {
                    tracing::error!(error = ?e, "Failed to deserialize challenge response");
                    PasskeyError::InvalidChallengeResponseFormat
                })?;

        // Check if the passkey already exists
        let passkey_exists = self
            .storage
            .user_storage()
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
            .storage
            .user_storage()
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
            .storage
            .user_storage()
            .get_or_create_user_by_email(email)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to get or create user by email");
                PasskeyError::StorageError(e.to_string())
            })?;

        // Add the passkey to the user
        self.storage
            .user_storage()
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

        let session = self
            .storage
            .session_storage()
            .create_session(&Session::builder().user_id(user.id.clone()).build().unwrap())
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to create session");
                PasskeyError::StorageError(e.to_string())
            })?;

        Ok((user, session))
    }

    pub async fn start_login(&self, email: &str) -> Result<PasskeyChallenge, PasskeyError> {
        let user = self
            .storage
            .user_storage()
            .get_user_by_email(email)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to get user by email");
                PasskeyError::StorageError(e.to_string())
            })?
            .ok_or(PasskeyError::InvalidCredentials)?;

        // Get the passkeys for the user
        let passkey_credentials = self
            .storage
            .user_storage()
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
        self.storage
            .user_storage()
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

    pub async fn complete_login(
        &self,
        email: &str,
        challenge_id: &str,
        challenge_response: &serde_json::Value,
    ) -> Result<(User, Session), PasskeyError> {
        // Get the user by email
        let user = self
            .storage
            .user_storage()
            .get_user_by_email(email)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to get user by email");
                PasskeyError::StorageError(e.to_string())
            })?
            .ok_or(PasskeyError::InvalidCredentials)?;

        // Get the challenge from the database
        let passkey_challenge = self
            .storage
            .user_storage()
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
        match self
            .webauthn
            .finish_passkey_authentication(&challenge_response, &passkey_challenge)
        {
            Ok(_) => {
                let session = self
                    .storage
                    .session_storage()
                    .create_session(&Session::builder().user_id(user.id.clone()).build().unwrap())
                    .await
                    .map_err(|e| {
                        tracing::error!(error = ?e, "Failed to create session");
                        PasskeyError::StorageError(e.to_string())
                    })?;

                Ok((user, session))
            }
            Err(e) => {
                tracing::error!(error = ?e, "Failed to complete login");
                Err(PasskeyError::InvalidCredentials)
            }
        }
    }
}

impl<U: PasskeyStorage, S: SessionStorage> Plugin for PasskeyPlugin<U, S> {
    fn name(&self) -> String {
        "passkey".to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sqlx::SqlitePool;
    use torii_storage_sqlite::SqliteStorage;

    use super::*;

    async fn setup_storage() -> Storage<SqliteStorage, SqliteStorage> {
        let _ = tracing_subscriber::fmt::try_init();
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();

        let user_storage = SqliteStorage::new(pool.clone());
        let session_storage = SqliteStorage::new(pool.clone());

        user_storage.migrate().await.unwrap();
        session_storage.migrate().await.unwrap();

        Storage::new(Arc::new(user_storage), Arc::new(session_storage))
    }
}
