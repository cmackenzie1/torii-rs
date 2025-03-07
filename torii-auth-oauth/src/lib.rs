pub mod providers;

use std::sync::Arc;

use oauth2::TokenResponse;

use providers::{Provider, UserInfo};
use torii_core::error::AuthError;
use torii_core::{
    events::{Event, EventBus},
    storage::OAuthStorage,
};
use torii_core::{Error, NewUser, Plugin, User, UserId};

/// A struct containing the necessary information to complete an OAuth2 authorization flow.
///
/// # Fields
/// - `url`: The authorization URL that the user should be redirected to in order to authenticate
/// - `csrf_state`: A randomly generated state value that should be stored and verified when the user returns
///   from the authorization flow to prevent CSRF attacks
/// - `pkce_verifier`: The PKCE verifier code that should be stored and used when exchanging the authorization
///   code for tokens
///
/// # Usage
/// 1. Generate an `AuthorizationUrl` using the OAuth provider's `get_authorization_url()` method
/// 2. Store both the `csrf_state` and `pkce_verifier` values securely (e.g. in the user's session)
/// 3. Redirect the user to the `url` to begin the OAuth flow
/// 4. When the user returns to your redirect URI, verify that the state parameter matches the stored `csrf_state`
/// 5. Use the stored `pkce_verifier` when calling the provider's `exchange_code()` method
pub struct AuthorizationUrl {
    /// The authorization URL to redirect the user to
    url: String,
    /// The CSRF state. This is typically set as a cookie in the user's browser to use when the user returns
    /// from the authorization flow
    csrf_state: String,
}

impl AuthorizationUrl {
    pub fn new(url: &str, csrf_state: &str) -> Self {
        Self {
            url: url.to_string(),
            csrf_state: csrf_state.to_string(),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn csrf_state(&self) -> &str {
        &self.csrf_state
    }
}

pub struct OAuthPlugin<U: OAuthStorage> {
    /// The provider.
    provider: Provider,
    /// The storage instance.
    user_storage: Arc<U>,
    /// The event bus.
    event_bus: Option<EventBus>,
}

impl<U> Plugin for OAuthPlugin<U>
where
    U: OAuthStorage,
{
    fn name(&self) -> String {
        self.provider.name().to_string()
    }
}

pub struct OAuthPluginBuilder<U: OAuthStorage> {
    provider: Provider,
    user_storage: Arc<U>,
    event_bus: Option<EventBus>,
}

impl<U> OAuthPluginBuilder<U>
where
    U: OAuthStorage,
{
    pub fn new(provider: Provider, user_storage: Arc<U>) -> Self {
        Self {
            provider,
            event_bus: None,
            user_storage,
        }
    }

    pub fn event_bus(mut self, event_bus: EventBus) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    pub fn build(self) -> OAuthPlugin<U> {
        OAuthPlugin {
            provider: self.provider,
            event_bus: self.event_bus,
            user_storage: self.user_storage,
        }
    }
}

impl<U> OAuthPlugin<U>
where
    U: OAuthStorage,
{
    pub fn builder(provider: Provider, user_storage: Arc<U>) -> OAuthPluginBuilder<U> {
        OAuthPluginBuilder::new(provider, user_storage)
    }

    pub fn new(provider: Provider, user_storage: Arc<U>) -> Self {
        Self {
            provider,
            event_bus: None,
            user_storage,
        }
    }

    pub fn with_event_bus(mut self, event_bus: EventBus) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    /// Create a new OAuth plugin for Google
    pub fn google(
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        user_storage: Arc<U>,
    ) -> Self {
        OAuthPluginBuilder::new(
            Provider::google(client_id, client_secret, redirect_uri),
            user_storage,
        )
        .build()
    }

    /// Create a new OAuth plugin for GitHub
    pub fn github(
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        user_storage: Arc<U>,
    ) -> Self {
        OAuthPluginBuilder::new(
            Provider::github(client_id, client_secret, redirect_uri),
            user_storage,
        )
        .build()
    }
}

impl<U> OAuthPlugin<U>
where
    U: OAuthStorage,
{
    /// Begin the authentication process by generating a new CSRF state and redirecting the user to the provider's authorization URL.
    ///
    /// This method is the first step in the oauth authorization code flow. It will:
    /// 1. Generate a CSRF token for security
    /// 2. Generate the authorization URL to redirect the user to
    ///
    /// # Returns
    /// Returns an `AuthFlowBegin` containing:
    /// * The CSRF state to prevent cross-site request forgery
    /// * The authorization URI to redirect the user to
    ///
    /// # Errors
    /// Returns an error if:
    /// * The provider metadata discovery fails
    /// * The HTTP client cannot be created
    pub async fn get_authorization_url(&self) -> Result<AuthorizationUrl, Error> {
        let (authorization_url, pkce_verifier) = self.provider.get_authorization_url()?;

        // Store the PKCE verifier in the storage using the CSRF state as the key
        self.user_storage
            .store_pkce_verifier(
                &authorization_url.csrf_state,
                &pkce_verifier,
                chrono::Duration::minutes(5),
            )
            .await
            .map_err(|_| Error::Auth(AuthError::InvalidCredentials))?;

        Ok(authorization_url)
    }

    /// Creates or retrieves an existing user based on oauth account information
    ///
    /// # Arguments
    /// * `storage` - The storage instance for the oauth provider
    /// * `email` - The email address of the user
    /// * `subject` - The subject of the oauth account
    ///
    /// # Returns
    /// Returns a [`User`] struct containing the user's information.
    pub async fn get_or_create_user(&self, email: String, subject: String) -> Result<User, Error> {
        // Check if user exists in database by provider and subject
        let oauth_account = self
            .user_storage
            .get_oauth_account_by_provider_and_subject(&self.provider.name(), &subject)
            .await
            .map_err(|_| Error::Auth(AuthError::InvalidCredentials))?;

        if let Some(oauth_account) = oauth_account {
            tracing::info!(
                user_id = ?oauth_account.user_id,
                "User already exists in database"
            );

            let user = self
                .user_storage
                .get_user(&oauth_account.user_id)
                .await
                .map_err(|_| Error::Auth(AuthError::InvalidCredentials))?
                .ok_or(Error::Auth(AuthError::UserNotFound))?;

            return Ok(user);
        }

        // Create new user
        let user = self
            .user_storage
            .create_user(
                &NewUser::builder()
                    .id(UserId::new_random())
                    .email(email)
                    .build()
                    .unwrap(),
            )
            .await
            .map_err(|_| Error::Auth(AuthError::InvalidCredentials))?;

        // Create link between user and provider
        self.user_storage
            .create_oauth_account(&self.provider.name(), &subject, &user.id)
            .await
            .map_err(|_| Error::Auth(AuthError::InvalidCredentials))?;

        tracing::info!(
            user_id = ?user.id,
            provider = ?self.provider.name(),
            subject = ?subject,
            "Successfully created link between user and provider"
        );

        self.emit_event(&Event::UserCreated(user.clone())).await?;

        Ok(user)
    }

    /// Complete the authentication process by exchanging the authorization code for an access token and user information.
    ///
    /// This method is the second step in the oauth authorization code flow. It will:
    /// 1. Exchange the authorization code for an access token and user information
    /// 2. Create a new user if they don't exist
    /// 3. Create a link between the user and the provider
    ///
    /// # Arguments
    /// * `code` - The authorization code
    /// * `csrf_state` - The CSRF state
    ///
    /// # Returns
    /// Returns a [`User`] struct containing the user's information.
    pub async fn exchange_code(&self, code: String, csrf_state: String) -> Result<User, Error> {
        let pkce_verifier = self
            .user_storage
            .get_pkce_verifier(&csrf_state)
            .await
            .map_err(|_| Error::Auth(AuthError::InvalidCredentials))?
            .ok_or(Error::Auth(AuthError::InvalidCredentials))?;

        tracing::debug!(
            pkce_verifier = ?pkce_verifier,
            csrf_state = ?csrf_state,
            "Exchanging code for token"
        );

        let token_response = self.provider.exchange_code(&code, &pkce_verifier).await?;

        let access_token = token_response.access_token();

        tracing::debug!(
            access_token = ?access_token,
            "Getting user info"
        );

        let user_info = self.provider.get_user_info(access_token.secret()).await?;

        tracing::debug!(
            user_info = ?user_info,
            "Got user info"
        );

        let email = match &user_info {
            UserInfo::Google(user_info) => user_info.email.clone(),
            UserInfo::Github(user_info) => {
                user_info.email.clone().expect("No email found for user")
            }
        };

        let subject = match &user_info {
            UserInfo::Google(user_info) => user_info.sub.clone(),
            UserInfo::Github(user_info) => user_info.id.to_string(),
        };

        tracing::debug!(
            email = ?email,
            subject = ?subject,
            "Getting or creating user"
        );

        let user = self
            .get_or_create_user(email, subject)
            .await
            .map_err(|_| Error::Auth(AuthError::InvalidCredentials))?;

        Ok(user)
    }

    async fn emit_event(&self, event: &Event) -> Result<(), Error> {
        if let Some(event_bus) = &self.event_bus {
            event_bus.emit(event).await?;
        }
        Ok(())
    }
}
