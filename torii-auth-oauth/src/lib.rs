pub mod providers;

use oauth2::TokenResponse;

use providers::{Provider, UserInfo};
use torii_core::error::AuthError;
use torii_core::{Error, NewUser, Plugin, Session, SessionStorage, User, UserId, storage::Storage};
use torii_core::{
    events::{Event, EventBus},
    storage::OAuthStorage,
};

pub struct AuthorizationUrl {
    url: String,
    csrf_state: String,
    pkce_verifier: String,
}

impl AuthorizationUrl {
    pub fn new(url: String, csrf_state: String, pkce_verifier: String) -> Self {
        Self {
            url,
            csrf_state,
            pkce_verifier,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn csrf_state(&self) -> &str {
        &self.csrf_state
    }

    pub fn pkce_verifier(&self) -> &str {
        &self.pkce_verifier
    }
}

pub struct OAuthPlugin<U: OAuthStorage, S: SessionStorage> {
    /// The provider.
    provider: Provider,
    /// The storage instance.
    storage: Storage<U, S>,
    /// The event bus.
    event_bus: Option<EventBus>,
}

impl<U, S> Plugin for OAuthPlugin<U, S>
where
    U: OAuthStorage,
    S: SessionStorage,
{
    fn name(&self) -> String {
        self.provider.name()
    }
}

pub struct OAuthPluginBuilder<U: OAuthStorage, S: SessionStorage> {
    provider: Provider,

    event_bus: Option<EventBus>,
    storage: Storage<U, S>,
}

impl<U, S> OAuthPluginBuilder<U, S>
where
    U: OAuthStorage,
    S: SessionStorage,
{
    pub fn new(provider: Provider, storage: Storage<U, S>) -> Self {
        Self {
            provider,
            event_bus: None,
            storage,
        }
    }

    pub fn event_bus(mut self, event_bus: EventBus) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    pub fn build(self) -> OAuthPlugin<U, S> {
        OAuthPlugin {
            provider: self.provider,
            event_bus: self.event_bus,
            storage: self.storage,
        }
    }
}

/// The start of the oauth authentication flow for authorization code grant. This is the first step in the flow and is used to start the flow by redirecting the user to the provider's authorization URL.
///
/// See the [`OAuthPlugin::begin_auth`] method for the core authentication flow.
#[derive(Debug)]
pub struct AuthFlowBegin {
    /// The CSRF state. This value is used to prevent CSRF attacks and may be stored in a cookie.
    pub csrf_state: String,

    /// The authorization uri. This is the uri that the user will be redirected to begin the authorization flow with the external provider.
    pub authorization_uri: String,
}

#[derive(Debug)]
pub struct AuthFlowCallback {
    /// The CSRF state. This value is used to prevent CSRF attacks and must match the CSRF state in the [`AuthFlowBegin`] struct.
    pub csrf_state: String,

    /// The authorization code. This value is used to exchange for an access token and user information.
    pub code: String,
}

impl<U, S> OAuthPlugin<U, S>
where
    U: OAuthStorage,
    S: SessionStorage,
{
    pub fn builder(provider: Provider, storage: Storage<U, S>) -> OAuthPluginBuilder<U, S> {
        OAuthPluginBuilder::new(provider, storage)
    }

    pub fn new(provider: Provider, storage: Storage<U, S>) -> Self {
        Self {
            provider,
            event_bus: None,
            storage,
        }
    }

    pub fn with_event_bus(mut self, event_bus: EventBus) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    pub fn google(
        client_id: String,
        client_secret: String,
        redirect_uri: String,
        storage: Storage<U, S>,
    ) -> Self {
        OAuthPluginBuilder::new(
            Provider::google(client_id, client_secret, redirect_uri),
            storage,
        )
        .build()
    }

    pub fn github(
        client_id: String,
        client_secret: String,
        redirect_uri: String,
        storage: Storage<U, S>,
    ) -> Self {
        OAuthPluginBuilder::new(
            Provider::github(client_id, client_secret, redirect_uri),
            storage,
        )
        .build()
    }
}

impl<U, S> OAuthPlugin<U, S>
where
    U: OAuthStorage,
    S: SessionStorage,
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
        let authorization_url = self.provider.get_authorization_url()?;

        self.storage
            .user_storage()
            .store_pkce_verifier(
                &authorization_url.csrf_state,
                &authorization_url.pkce_verifier,
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
            .storage
            .user_storage()
            .get_oauth_account_by_provider_and_subject(&self.provider.name(), &subject)
            .await
            .map_err(|_| Error::Auth(AuthError::InvalidCredentials))?;

        if let Some(oauth_account) = oauth_account {
            tracing::info!(
                user_id = ?oauth_account.user_id,
                "User already exists in database"
            );

            let user = self
                .storage
                .user_storage()
                .get_user(&oauth_account.user_id)
                .await
                .map_err(|_| Error::Auth(AuthError::InvalidCredentials))?
                .ok_or(Error::Auth(AuthError::UserNotFound))?;

            return Ok(user);
        }

        // Create new user
        let user = self
            .storage
            .user_storage()
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
        self.storage
            .user_storage()
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
    /// Returns a tuple containing:
    /// * A [`User`] struct containing the user's information
    /// * A [`Session`] struct containing the session information
    pub async fn exchange_code(
        &self,
        code: String,
        csrf_state: String,
    ) -> Result<(User, Session), Error> {
        let pkce_verifier = self
            .storage
            .user_storage()
            .get_pkce_verifier(&csrf_state)
            .await
            .map_err(|_| Error::Auth(AuthError::InvalidCredentials))?
            .ok_or(Error::Auth(AuthError::InvalidCredentials))?;

        tracing::debug!(
            pkce_verifier = ?pkce_verifier,
            csrf_state = ?csrf_state,
            "Exchanging code for token"
        );

        let token_response = self.provider.exchange_code(code, pkce_verifier).await?;

        let access_token = token_response.access_token();

        tracing::debug!(
            access_token = ?access_token,
            "Getting user info"
        );

        let user_info = self
            .provider
            .get_user_info(access_token.secret().to_string())
            .await?;

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

        let session = self
            .storage
            .session_storage()
            .create_session(&Session::builder().user_id(user.id.clone()).build().unwrap())
            .await
            .map_err(|_| Error::Auth(AuthError::InvalidCredentials))?;

        tracing::debug!(
            session = ?session,
            "Created session"
        );

        self.emit_event(&Event::SessionCreated(
            session.user_id.clone(),
            session.clone(),
        ))
        .await?;

        Ok((user, session))
    }

    async fn emit_event(&self, event: &Event) -> Result<(), Error> {
        if let Some(event_bus) = &self.event_bus {
            event_bus.emit(event).await?;
        }
        Ok(())
    }
}
