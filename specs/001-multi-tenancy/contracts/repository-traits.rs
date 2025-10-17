// Repository Trait Extensions for Multi-Tenancy
// This file defines the extended repository interfaces that support tenant-scoped operations

use async_trait::async_trait;
use chrono::{DateTime, Utc, Duration};

// Extended User Repository with tenant support
#[async_trait]
pub trait UserRepository: Send + Sync {
    // Existing methods (backward compatibility)
    async fn create(&self, user: NewUser) -> Result<User, Error>;
    async fn get(&self, id: &UserId) -> Result<Option<User>, Error>;
    async fn get_by_email(&self, email: &str) -> Result<Option<User>, Error>;
    async fn update(&self, user: &User) -> Result<User, Error>;
    async fn delete(&self, id: &UserId) -> Result<(), Error>;
    async fn mark_email_verified(&self, user_id: &UserId) -> Result<(), Error>;

    // New tenant-scoped methods
    async fn create_in_tenant(&self, tenant_id: &TenantId, user: NewUser) -> Result<User, Error>;
    async fn get_in_tenant(&self, tenant_id: &TenantId, id: &UserId) -> Result<Option<User>, Error>;
    async fn get_by_email_in_tenant(&self, tenant_id: &TenantId, email: &str) -> Result<Option<User>, Error>;
    async fn list_in_tenant(&self, tenant_id: &TenantId) -> Result<Vec<User>, Error>;
    async fn update_in_tenant(&self, tenant_id: &TenantId, user: &User) -> Result<User, Error>;
    async fn delete_in_tenant(&self, tenant_id: &TenantId, id: &UserId) -> Result<(), Error>;
    async fn mark_email_verified_in_tenant(&self, tenant_id: &TenantId, user_id: &UserId) -> Result<(), Error>;
    
    // Tenant management
    async fn migrate_user_to_tenant(&self, user_id: &UserId, from_tenant: &TenantId, to_tenant: &TenantId) -> Result<(), Error>;
    async fn count_users_in_tenant(&self, tenant_id: &TenantId) -> Result<i64, Error>;
}

// Extended Session Repository with tenant support
#[async_trait]
pub trait SessionRepository: Send + Sync {
    // Existing methods (backward compatibility)
    async fn create(&self, session: &Session) -> Result<(), Error>;
    async fn get(&self, token: &SessionToken) -> Result<Option<Session>, Error>;
    async fn update(&self, session: &Session) -> Result<(), Error>;
    async fn delete(&self, token: &SessionToken) -> Result<(), Error>;
    async fn delete_expired(&self) -> Result<u64, Error>;
    async fn list_for_user(&self, user_id: &UserId) -> Result<Vec<Session>, Error>;

    // New tenant-scoped methods
    async fn create_in_tenant(&self, tenant_id: &TenantId, session: &Session) -> Result<(), Error>;
    async fn get_in_tenant(&self, tenant_id: &TenantId, token: &SessionToken) -> Result<Option<Session>, Error>;
    async fn update_in_tenant(&self, tenant_id: &TenantId, session: &Session) -> Result<(), Error>;
    async fn delete_in_tenant(&self, tenant_id: &TenantId, token: &SessionToken) -> Result<(), Error>;
    async fn delete_expired_in_tenant(&self, tenant_id: &TenantId) -> Result<u64, Error>;
    async fn list_for_user_in_tenant(&self, tenant_id: &TenantId, user_id: &UserId) -> Result<Vec<Session>, Error>;
    async fn list_in_tenant(&self, tenant_id: &TenantId) -> Result<Vec<Session>, Error>;
    
    // Tenant management
    async fn count_sessions_in_tenant(&self, tenant_id: &TenantId) -> Result<i64, Error>;
    async fn delete_all_in_tenant(&self, tenant_id: &TenantId) -> Result<u64, Error>;
}

// Extended OAuth Repository with tenant support
#[async_trait]
pub trait OAuthRepository: Send + Sync {
    // Existing methods (backward compatibility)
    async fn find_by_provider_account(&self, provider: &str, subject: &str) -> Result<Option<OAuthAccount>, Error>;
    async fn create_account(&self, account: &OAuthAccount) -> Result<(), Error>;
    async fn link_account(&self, user_id: &UserId, provider: &str, subject: &str) -> Result<(), Error>;
    async fn unlink_account(&self, user_id: &UserId, provider: &str) -> Result<(), Error>;
    async fn list_for_user(&self, user_id: &UserId) -> Result<Vec<OAuthAccount>, Error>;

    // New tenant-scoped methods
    async fn find_by_provider_account_in_tenant(
        &self, 
        tenant_id: &TenantId, 
        provider: &str, 
        subject: &str
    ) -> Result<Option<OAuthAccount>, Error>;
    async fn create_account_in_tenant(&self, tenant_id: &TenantId, account: &OAuthAccount) -> Result<(), Error>;
    async fn link_account_in_tenant(
        &self, 
        tenant_id: &TenantId, 
        user_id: &UserId, 
        provider: &str, 
        subject: &str
    ) -> Result<(), Error>;
    async fn unlink_account_in_tenant(
        &self, 
        tenant_id: &TenantId, 
        user_id: &UserId, 
        provider: &str
    ) -> Result<(), Error>;
    async fn list_for_user_in_tenant(&self, tenant_id: &TenantId, user_id: &UserId) -> Result<Vec<OAuthAccount>, Error>;
    async fn list_in_tenant(&self, tenant_id: &TenantId) -> Result<Vec<OAuthAccount>, Error>;

    // PKCE support (existing)
    async fn store_pkce_verifier(&self, csrf_state: &str, pkce_verifier: &str, expires_in: Duration) -> Result<(), Error>;
    async fn get_pkce_verifier(&self, csrf_state: &str) -> Result<Option<String>, Error>;
    async fn delete_pkce_verifier(&self, csrf_state: &str) -> Result<(), Error>;
}

// Extended Passkey Repository with tenant support
#[async_trait]
pub trait PasskeyRepository: Send + Sync {
    // Existing methods (backward compatibility)
    async fn store_credential(&self, user_id: &UserId, credential: &PasskeyCredential) -> Result<(), Error>;
    async fn get_credential(&self, credential_id: &[u8]) -> Result<Option<PasskeyCredential>, Error>;
    async fn list_for_user(&self, user_id: &UserId) -> Result<Vec<PasskeyCredential>, Error>;
    async fn delete_credential(&self, credential_id: &[u8]) -> Result<(), Error>;
    async fn update_last_used(&self, credential_id: &[u8]) -> Result<(), Error>;

    // New tenant-scoped methods
    async fn store_credential_in_tenant(
        &self, 
        tenant_id: &TenantId, 
        user_id: &UserId, 
        credential: &PasskeyCredential
    ) -> Result<(), Error>;
    async fn get_credential_in_tenant(
        &self, 
        tenant_id: &TenantId, 
        credential_id: &[u8]
    ) -> Result<Option<PasskeyCredential>, Error>;
    async fn list_for_user_in_tenant(
        &self, 
        tenant_id: &TenantId, 
        user_id: &UserId
    ) -> Result<Vec<PasskeyCredential>, Error>;
    async fn delete_credential_in_tenant(
        &self, 
        tenant_id: &TenantId, 
        credential_id: &[u8]
    ) -> Result<(), Error>;
    async fn update_last_used_in_tenant(
        &self, 
        tenant_id: &TenantId, 
        credential_id: &[u8]
    ) -> Result<(), Error>;
    async fn list_in_tenant(&self, tenant_id: &TenantId) -> Result<Vec<PasskeyCredential>, Error>;

    // Challenge management (existing)
    async fn store_challenge(&self, challenge_id: &str, challenge: &str, expires_in: Duration) -> Result<(), Error>;
    async fn get_challenge(&self, challenge_id: &str) -> Result<Option<String>, Error>;
    async fn delete_challenge(&self, challenge_id: &str) -> Result<(), Error>;
}

// Extended Token Repository with tenant support
#[async_trait]
pub trait TokenRepository: Send + Sync {
    // Existing methods (backward compatibility)
    async fn store_token(&self, token: &SecureToken) -> Result<(), Error>;
    async fn get_token(&self, token: &str) -> Result<Option<SecureToken>, Error>;
    async fn use_token(&self, token: &str) -> Result<Option<SecureToken>, Error>;
    async fn delete_token(&self, token: &str) -> Result<(), Error>;
    async fn delete_expired(&self) -> Result<u64, Error>;
    async fn list_for_user(&self, user_id: &UserId, purpose: TokenPurpose) -> Result<Vec<SecureToken>, Error>;

    // New tenant-scoped methods
    async fn store_token_in_tenant(&self, tenant_id: &TenantId, token: &SecureToken) -> Result<(), Error>;
    async fn get_token_in_tenant(&self, tenant_id: &TenantId, token: &str) -> Result<Option<SecureToken>, Error>;
    async fn use_token_in_tenant(&self, tenant_id: &TenantId, token: &str) -> Result<Option<SecureToken>, Error>;
    async fn delete_token_in_tenant(&self, tenant_id: &TenantId, token: &str) -> Result<(), Error>;
    async fn delete_expired_in_tenant(&self, tenant_id: &TenantId) -> Result<u64, Error>;
    async fn list_for_user_in_tenant(
        &self, 
        tenant_id: &TenantId, 
        user_id: &UserId, 
        purpose: TokenPurpose
    ) -> Result<Vec<SecureToken>, Error>;
    async fn list_in_tenant(&self, tenant_id: &TenantId, purpose: Option<TokenPurpose>) -> Result<Vec<SecureToken>, Error>;
}

// Extended Password Repository with tenant support
#[async_trait]
pub trait PasswordRepository: Send + Sync {
    // Existing methods (backward compatibility)
    async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Error>;
    async fn get_password_hash(&self, user_id: &UserId) -> Result<Option<String>, Error>;
    async fn remove_password_hash(&self, user_id: &UserId) -> Result<(), Error>;

    // New tenant-scoped methods
    async fn set_password_hash_in_tenant(
        &self, 
        tenant_id: &TenantId, 
        user_id: &UserId, 
        hash: &str
    ) -> Result<(), Error>;
    async fn get_password_hash_in_tenant(
        &self, 
        tenant_id: &TenantId, 
        user_id: &UserId
    ) -> Result<Option<String>, Error>;
    async fn remove_password_hash_in_tenant(
        &self, 
        tenant_id: &TenantId, 
        user_id: &UserId
    ) -> Result<(), Error>;
}

// Extended Repository Provider with tenant support
#[async_trait]
pub trait RepositoryProvider: Send + Sync + 'static {
    type User: UserRepository;
    type Session: SessionRepository;
    type Password: PasswordRepository;
    type OAuth: OAuthRepository;
    type Passkey: PasskeyRepository;
    type Token: TokenRepository;

    // Existing methods
    fn user(&self) -> &Self::User;
    fn session(&self) -> &Self::Session;
    fn password(&self) -> &Self::Password;
    fn oauth(&self) -> &Self::OAuth;
    fn passkey(&self) -> &Self::Passkey;
    fn token(&self) -> &Self::Token;
    async fn migrate(&self) -> Result<(), Error>;
    async fn health_check(&self) -> Result<(), Error>;

    // New tenant-specific methods
    async fn migrate_to_multi_tenant(&self) -> Result<(), Error>;
    async fn create_tenant_indexes(&self) -> Result<(), Error>;
    async fn validate_tenant_isolation(&self, tenant_id: &TenantId) -> Result<bool, Error>;
}
