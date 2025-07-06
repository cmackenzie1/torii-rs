use crate::{
    Error, User, UserId,
    repositories::{PasskeyCredential, PasskeyRepository, UserRepository},
    services::UserService,
};
use std::sync::Arc;

/// Service for passkey/WebAuthn authentication operations
pub struct PasskeyService<U: UserRepository, P: PasskeyRepository> {
    user_service: Arc<UserService<U>>,
    passkey_repository: Arc<P>,
}

impl<U: UserRepository, P: PasskeyRepository> PasskeyService<U, P> {
    /// Create a new PasskeyService with the given repositories
    pub fn new(user_repository: Arc<U>, passkey_repository: Arc<P>) -> Self {
        let user_service = Arc::new(UserService::new(user_repository));
        Self {
            user_service,
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
    pub async fn get_user_credentials(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<PasskeyCredential>, Error> {
        self.passkey_repository
            .get_credentials_for_user(user_id)
            .await
    }

    /// Get a specific passkey credential
    pub async fn get_credential(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<PasskeyCredential>, Error> {
        self.passkey_repository.get_credential(credential_id).await
    }

    /// Authenticate with a passkey credential
    pub async fn authenticate_credential(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<User>, Error> {
        // Get the credential
        let credential = self
            .passkey_repository
            .get_credential(credential_id)
            .await?;

        if let Some(cred) = credential {
            // Update last used timestamp
            self.passkey_repository
                .update_last_used(credential_id)
                .await?;

            // Get the user
            let user = self.user_service.get_user(&cred.user_id).await?;

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
        self.passkey_repository.delete_all_for_user(user_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repositories::{PasskeyCredential, PasskeyRepository, UserRepository};
    use crate::{User, UserId};
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // Mock implementations for testing
    #[derive(Debug, Clone)]
    struct MockUser {
        id: UserId,
        email: String,
        name: Option<String>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    }

    impl From<MockUser> for User {
        fn from(user: MockUser) -> Self {
            User {
                id: user.id,
                email: user.email,
                name: user.name,
                email_verified_at: None,
                created_at: user.created_at,
                updated_at: user.updated_at,
            }
        }
    }

    #[derive(Default)]
    struct MockUserRepository {
        users: Arc<Mutex<HashMap<UserId, MockUser>>>,
    }

    #[async_trait]
    impl UserRepository for MockUserRepository {
        async fn create(&self, new_user: crate::storage::NewUser) -> Result<User, Error> {
            let user = MockUser {
                id: UserId::new_random(),
                email: new_user.email,
                name: new_user.name,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            self.users
                .lock()
                .await
                .insert(user.id.clone(), user.clone());
            Ok(user.into())
        }

        async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, Error> {
            Ok(self.users.lock().await.get(id).cloned().map(Into::into))
        }

        async fn find_by_email(&self, email: &str) -> Result<Option<User>, Error> {
            Ok(self
                .users
                .lock()
                .await
                .values()
                .find(|u| u.email == email)
                .cloned()
                .map(Into::into))
        }

        async fn find_or_create_by_email(&self, email: &str) -> Result<User, Error> {
            if let Some(user) = self.find_by_email(email).await? {
                Ok(user)
            } else {
                let new_user = crate::storage::NewUser::builder()
                    .email(email.to_string())
                    .build()
                    .unwrap();
                self.create(new_user).await
            }
        }

        async fn update(&self, _user: &User) -> Result<User, Error> {
            unimplemented!()
        }

        async fn delete(&self, _id: &UserId) -> Result<(), Error> {
            unimplemented!()
        }

        async fn mark_email_verified(&self, _user_id: &UserId) -> Result<(), Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockPasskeyRepository {
        credentials: Arc<Mutex<HashMap<Vec<u8>, PasskeyCredential>>>,
        user_credentials: Arc<Mutex<HashMap<UserId, Vec<Vec<u8>>>>>,
    }

    #[async_trait]
    impl PasskeyRepository for MockPasskeyRepository {
        async fn add_credential(
            &self,
            user_id: &UserId,
            credential_id: Vec<u8>,
            public_key: Vec<u8>,
            name: Option<String>,
        ) -> Result<PasskeyCredential, Error> {
            let credential = PasskeyCredential {
                credential_id: credential_id.clone(),
                user_id: user_id.clone(),
                public_key,
                name,
                created_at: Utc::now(),
                last_used_at: None,
            };

            self.credentials
                .lock()
                .await
                .insert(credential_id.clone(), credential.clone());
            self.user_credentials
                .lock()
                .await
                .entry(user_id.clone())
                .or_insert_with(Vec::new)
                .push(credential_id);

            Ok(credential)
        }

        async fn get_credential(
            &self,
            credential_id: &[u8],
        ) -> Result<Option<PasskeyCredential>, Error> {
            Ok(self.credentials.lock().await.get(credential_id).cloned())
        }

        async fn get_credentials_for_user(
            &self,
            user_id: &UserId,
        ) -> Result<Vec<PasskeyCredential>, Error> {
            let credentials = self.credentials.lock().await;
            let user_creds = self.user_credentials.lock().await;

            if let Some(cred_ids) = user_creds.get(user_id) {
                let mut result = Vec::new();
                for cred_id in cred_ids {
                    if let Some(cred) = credentials.get(cred_id) {
                        result.push(cred.clone());
                    }
                }
                Ok(result)
            } else {
                Ok(Vec::new())
            }
        }

        async fn update_last_used(&self, credential_id: &[u8]) -> Result<(), Error> {
            if let Some(cred) = self.credentials.lock().await.get_mut(credential_id) {
                cred.last_used_at = Some(Utc::now());
            }
            Ok(())
        }

        async fn delete_credential(&self, credential_id: &[u8]) -> Result<(), Error> {
            self.credentials.lock().await.remove(credential_id);
            // Also remove from user credentials
            let mut user_creds = self.user_credentials.lock().await;
            for (_, cred_ids) in user_creds.iter_mut() {
                cred_ids.retain(|id| id != credential_id);
            }
            Ok(())
        }

        async fn delete_all_for_user(&self, user_id: &UserId) -> Result<(), Error> {
            let mut user_creds = self.user_credentials.lock().await;
            if let Some(cred_ids) = user_creds.remove(user_id) {
                let mut credentials = self.credentials.lock().await;
                for cred_id in cred_ids {
                    credentials.remove(&cred_id);
                }
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_register_credential() {
        let user_repo = Arc::new(MockUserRepository::default());
        let passkey_repo = Arc::new(MockPasskeyRepository::default());
        let service = PasskeyService::new(user_repo, passkey_repo);

        let user_id = UserId::new_random();
        let credential_id = vec![1, 2, 3, 4];
        let public_key = vec![5, 6, 7, 8];
        let name = Some("My Passkey".to_string());

        let result = service
            .register_credential(
                &user_id,
                credential_id.clone(),
                public_key.clone(),
                name.clone(),
            )
            .await;
        assert!(result.is_ok());

        let credential = result.unwrap();
        assert_eq!(credential.credential_id, credential_id);
        assert_eq!(credential.user_id, user_id);
        assert_eq!(credential.public_key, public_key);
        assert_eq!(credential.name, name);
    }

    #[tokio::test]
    async fn test_get_user_credentials() {
        let user_repo = Arc::new(MockUserRepository::default());
        let passkey_repo = Arc::new(MockPasskeyRepository::default());
        let service = PasskeyService::new(user_repo, passkey_repo);

        let user_id = UserId::new_random();
        let credential_id = vec![1, 2, 3, 4];
        let public_key = vec![5, 6, 7, 8];

        // First register a credential
        service
            .register_credential(&user_id, credential_id.clone(), public_key, None)
            .await
            .unwrap();

        // Then get credentials for user
        let result = service.get_user_credentials(&user_id).await;
        assert!(result.is_ok());

        let credentials = result.unwrap();
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].credential_id, credential_id);
    }

    #[tokio::test]
    async fn test_get_credential() {
        let user_repo = Arc::new(MockUserRepository::default());
        let passkey_repo = Arc::new(MockPasskeyRepository::default());
        let service = PasskeyService::new(user_repo, passkey_repo);

        let user_id = UserId::new_random();
        let credential_id = vec![1, 2, 3, 4];
        let public_key = vec![5, 6, 7, 8];

        // First register a credential
        service
            .register_credential(&user_id, credential_id.clone(), public_key, None)
            .await
            .unwrap();

        // Then get the specific credential
        let result = service.get_credential(&credential_id).await;
        assert!(result.is_ok());

        let credential = result.unwrap();
        assert!(credential.is_some());
        assert_eq!(credential.unwrap().credential_id, credential_id);
    }

    #[tokio::test]
    async fn test_get_credential_not_found() {
        let user_repo = Arc::new(MockUserRepository::default());
        let passkey_repo = Arc::new(MockPasskeyRepository::default());
        let service = PasskeyService::new(user_repo, passkey_repo);

        let result = service.get_credential(&[9, 9, 9]).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_authenticate_credential() {
        let user_repo = Arc::new(MockUserRepository::default());
        let passkey_repo = Arc::new(MockPasskeyRepository::default());
        let service = PasskeyService::new(user_repo.clone(), passkey_repo);

        let credential_id = vec![1, 2, 3, 4];
        let public_key = vec![5, 6, 7, 8];

        // First create a user and register a credential
        let new_user = crate::storage::NewUser::builder()
            .email("test@example.com".to_string())
            .build()
            .unwrap();
        let user = user_repo.create(new_user).await.unwrap();
        service
            .register_credential(&user.id, credential_id.clone(), public_key, None)
            .await
            .unwrap();

        // Then authenticate with the credential
        let result = service.authenticate_credential(&credential_id).await;
        assert!(result.is_ok());

        let auth_user = result.unwrap();
        assert!(auth_user.is_some());
        assert_eq!(auth_user.unwrap().email, "test@example.com");
    }

    #[tokio::test]
    async fn test_authenticate_credential_not_found() {
        let user_repo = Arc::new(MockUserRepository::default());
        let passkey_repo = Arc::new(MockPasskeyRepository::default());
        let service = PasskeyService::new(user_repo, passkey_repo);

        let result = service.authenticate_credential(&[9, 9, 9]).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_delete_credential() {
        let user_repo = Arc::new(MockUserRepository::default());
        let passkey_repo = Arc::new(MockPasskeyRepository::default());
        let service = PasskeyService::new(user_repo, passkey_repo);

        let user_id = UserId::new_random();
        let credential_id = vec![1, 2, 3, 4];
        let public_key = vec![5, 6, 7, 8];

        // First register a credential
        service
            .register_credential(&user_id, credential_id.clone(), public_key, None)
            .await
            .unwrap();

        // Verify it exists
        let result = service.get_credential(&credential_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());

        // Delete it
        let result = service.delete_credential(&credential_id).await;
        assert!(result.is_ok());

        // Verify it's gone
        let result = service.get_credential(&credential_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_delete_user_credentials() {
        let user_repo = Arc::new(MockUserRepository::default());
        let passkey_repo = Arc::new(MockPasskeyRepository::default());
        let service = PasskeyService::new(user_repo, passkey_repo);

        let user_id = UserId::new_random();
        let credential_id1 = vec![1, 2, 3, 4];
        let credential_id2 = vec![5, 6, 7, 8];
        let public_key = vec![9, 10, 11, 12];

        // Register two credentials for the user
        service
            .register_credential(&user_id, credential_id1.clone(), public_key.clone(), None)
            .await
            .unwrap();
        service
            .register_credential(&user_id, credential_id2.clone(), public_key, None)
            .await
            .unwrap();

        // Verify both exist
        let result = service.get_user_credentials(&user_id).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);

        // Delete all credentials for the user
        let result = service.delete_user_credentials(&user_id).await;
        assert!(result.is_ok());

        // Verify they're gone
        let result = service.get_user_credentials(&user_id).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }
}
