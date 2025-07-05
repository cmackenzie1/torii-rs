use std::sync::Arc;
use crate::{
    User, UserId, Error,
    repositories::{UserRepository, PasskeyRepository, PasskeyCredential},
};

/// Service for passkey/WebAuthn authentication operations
pub struct PasskeyService<U: UserRepository, P: PasskeyRepository> {
    user_repository: Arc<U>,
    passkey_repository: Arc<P>,
}

impl<U: UserRepository, P: PasskeyRepository> PasskeyService<U, P> {
    /// Create a new PasskeyService with the given repositories
    pub fn new(user_repository: Arc<U>, passkey_repository: Arc<P>) -> Self {
        Self {
            user_repository,
            passkey_repository,
        }
    }

    /// Register a new passkey credential for a user
    pub async fn register_credential(
        &self,
        user_id: &UserId,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        name: Option<String>,
    ) -> Result<PasskeyCredential, Error> {
        self.passkey_repository
            .add_credential(user_id, credential_id, public_key, name)
            .await
    }

    /// Get all passkey credentials for a user
    pub async fn get_user_credentials(&self, user_id: &UserId) -> Result<Vec<PasskeyCredential>, Error> {
        self.passkey_repository
            .get_credentials_for_user(user_id)
            .await
    }

    /// Get a specific passkey credential
    pub async fn get_credential(&self, credential_id: &[u8]) -> Result<Option<PasskeyCredential>, Error> {
        self.passkey_repository
            .get_credential(credential_id)
            .await
    }

    /// Authenticate with a passkey credential
    pub async fn authenticate_credential(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<User>, Error> {
        // Get the credential
        let credential = self.passkey_repository
            .get_credential(credential_id)
            .await?;

        if let Some(cred) = credential {
            // Update last used timestamp
            self.passkey_repository
                .update_last_used(credential_id)
                .await?;

            // Get the user
            let user = self.user_repository
                .find_by_id(&cred.user_id)
                .await?;

            Ok(user)
        } else {
            Ok(None)
        }
    }

    /// Delete a passkey credential
    pub async fn delete_credential(&self, credential_id: &[u8]) -> Result<(), Error> {
        self.passkey_repository
            .delete_credential(credential_id)
            .await
    }

    /// Delete all passkey credentials for a user
    pub async fn delete_user_credentials(&self, user_id: &UserId) -> Result<(), Error> {
        self.passkey_repository
            .delete_all_for_user(user_id)
            .await
    }
}