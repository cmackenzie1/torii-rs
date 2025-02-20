use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{Duration, Utc};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, RedirectUrl, Scope,
    TokenResponse,
};
use torii_core::{
    events::{Event, EventBus},
    storage::OAuthStorage,
    AuthPlugin, AuthResponse, Credentials,
};
use torii_core::{storage::Storage, Error, NewUser, Plugin, Session, SessionStorage, User, UserId};
use uuid::Uuid;

/// The core oauth plugin struct, responsible for handling oauth authentication flow.
///
/// See the [`OAuthPlugin`] struct for the core plugin struct.
///
/// See the [`AuthFlowBegin`] and [`AuthFlowCallback`] structs for the core authentication flow.
///
/// # Examples
/// ```rust
/// // Using the builder pattern
/// use std::env;
/// use torii_auth_oauth::OAuthPlugin;
/// let plugin = OAuthPlugin::builder("google")
///     .client_id(env::var("GOOGLE_CLIENT_ID")?)
///     .client_secret(env::var("GOOGLE_CLIENT_SECRET")?)
///     .redirect_uri("http://localhost:8080/callback")
///     .build();
///
/// // Using preset for Google
/// let plugin = OAuthPlugin::google(
///     env::var("GOOGLE_CLIENT_ID")?,
///     env::var("GOOGLE_CLIENT_SECRET")?,
///     "http://localhost:8080/callback".to_string(),
/// );
/// ```
pub struct OAuthPlugin<U: OAuthStorage, S: SessionStorage> {
    /// The provider name. i.e. "google"
    pub provider: String,
    /// The issuer URL for the oauth provider
    pub issuer_url: String,
    /// The scopes to request from the provider
    pub scopes: Vec<String>,

    /// The client id.
    client_id: String,

    /// The client secret.
    client_secret: String,

    /// The redirect uri.
    redirect_uri: String,

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
        self.provider.clone()
    }
}

pub struct OAuthPluginBuilder<U: OAuthStorage, S: SessionStorage> {
    provider: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    issuer_url: String,
    scopes: Vec<String>,
    event_bus: Option<EventBus>,
    storage: Storage<U, S>,
}

impl<U, S> OAuthPluginBuilder<U, S>
where
    U: OAuthStorage,
    S: SessionStorage,
{
    pub fn new(provider: &str, storage: Storage<U, S>) -> Self {
        Self {
            provider: provider.to_string(),
            client_id: String::new(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            issuer_url: String::new(),
            scopes: vec!["email".to_string(), "profile".to_string()],
            event_bus: None,
            storage,
        }
    }

    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = client_id.into();
        self
    }

    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = client_secret.into();
        self
    }

    pub fn redirect_uri(mut self, redirect_uri: impl Into<String>) -> Self {
        self.redirect_uri = redirect_uri.into();
        self
    }

    pub fn issuer_url(mut self, issuer_url: impl Into<String>) -> Self {
        self.issuer_url = issuer_url.into();
        self
    }

    pub fn add_scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    pub fn event_bus(mut self, event_bus: EventBus) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    pub fn build(self) -> OAuthPlugin<U, S> {
        OAuthPlugin {
            provider: self.provider,
            client_id: self.client_id,
            client_secret: self.client_secret,
            redirect_uri: self.redirect_uri,
            issuer_url: self.issuer_url,
            scopes: self.scopes,
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

    /// The nonce key. This value is used to prevent replay attacks and may be stored in a cookie.
    pub nonce_key: String,

    /// The authorization uri. This is the uri that the user will be redirected to begin the authorization flow with the external provider.
    pub authorization_uri: String,
}

#[derive(Debug)]
pub struct AuthFlowCallback {
    /// The CSRF state. This value is used to prevent CSRF attacks and must match the CSRF state in the [`AuthFlowBegin`] struct.
    pub csrf_state: String,

    /// The nonce key. This value is used to prevent replay attacks and must match the nonce key in the [`AuthFlowBegin`] struct.
    pub nonce_key: String,

    /// The authorization code. This value is used to exchange for an access token and user information.
    pub code: String,
}

impl<U, S> OAuthPlugin<U, S>
where
    U: OAuthStorage,
    S: SessionStorage,
{
    pub fn builder(provider: &str, storage: Storage<U, S>) -> OAuthPluginBuilder<U, S> {
        OAuthPluginBuilder::new(provider, storage)
    }

    pub fn new(
        provider: String,
        client_id: String,
        client_secret: String,
        redirect_uri: String,
        issuer_url: String,
        scopes: Vec<String>,
        storage: Storage<U, S>,
    ) -> Self {
        Self {
            provider,
            client_id,
            client_secret,
            redirect_uri,
            issuer_url,
            scopes,
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
        OAuthPluginBuilder::new("google", storage)
            .client_id(client_id)
            .client_secret(client_secret)
            .redirect_uri(redirect_uri)
            .issuer_url("https://accounts.google.com")
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
    /// 1. Generate a CSRF token and nonce for security
    /// 2. Store the nonce in the database for later verification
    /// 3. Generate the authorization URL to redirect the user to
    ///
    /// # Arguments
    /// * `pool` - The database connection pool for storing the nonce
    /// * `redirect_uri` - The URI where the provider should redirect back to after authentication
    ///
    /// # Returns
    /// Returns an `AuthFlowBegin` containing:
    /// * The CSRF state to prevent cross-site request forgery
    /// * A nonce key for preventing replay attacks
    /// * The authorization URI to redirect the user to
    ///
    /// # Errors
    /// Returns an error if:
    /// * The provider metadata discovery fails
    /// * The nonce cannot be stored in the database
    /// * The HTTP client cannot be created
    pub async fn begin_auth(&self, redirect_uri: String) -> Result<AuthFlowBegin, Error> {
        let http_client = openidconnect::reqwest::ClientBuilder::new()
            .build()
            .map_err(|_| Error::InternalServerError)?;

        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(self.issuer_url.clone()).unwrap(),
            &http_client,
        )
        .await
        .map_err(|_| Error::InternalServerError)?;

        let oauth_client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri).unwrap());

        let (auth_url, csrf_token, nonce) = oauth_client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            // Set the desired scopes.
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .url();

        tracing::info!(
            redirect_uri = auth_url.to_string(),
            "Redirecting to provider"
        );

        // Store nonce in database
        let nonce_key = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + Duration::hours(1);
        self.storage
            .user_storage()
            .save_nonce(&nonce_key, &nonce.secret().to_string(), &expires_at)
            .await
            .map_err(|_| Error::InternalServerError)?;

        tracing::info!(nonce_key = nonce_key.clone(), "Stored nonce in database");

        Ok(AuthFlowBegin {
            csrf_state: csrf_token.secret().to_string(),
            nonce_key: nonce_key.to_string(),
            authorization_uri: auth_url.to_string(),
        })
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
            .get_oauth_account_by_provider_and_subject(&self.provider, &subject)
            .await
            .map_err(|_| Error::InternalServerError)?;

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
                .map_err(|_| Error::InternalServerError)?
                .ok_or(Error::UserNotFound)?;

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
            .map_err(|_| Error::InternalServerError)?;

        // Create link between user and provider
        self.storage
            .user_storage()
            .create_oauth_account(&self.provider, &subject, &user.id)
            .await
            .map_err(|_| Error::InternalServerError)?;

        tracing::info!(
            user_id = ?user.id,
            provider = ?self.provider,
            subject = ?subject,
            "Successfully created link between user and provider"
        );

        tracing::info!(
            user_id = ?user.id,
            provider = ?self.provider,
            subject = ?subject,
            "Successfully created session for authenticated user"
        );

        self.emit_event(&Event::UserCreated(user.clone())).await?;

        Ok(user)
    }

    /// Complete the authentication process by exchanging the authorization code for an access token and user information.
    ///
    /// This method is the second step in the oauth authorization code flow. It will:
    /// 1. Exchange the authorization code for an access token and user information
    /// 2. Verify the nonce
    /// 3. Verify the id token
    /// 4. Create a new user if they don't exist
    /// 5. Create a link between the user and the provider
    ///
    /// # Arguments
    /// * `pool` - The database connection pool for storing the nonce
    /// * `auth_flow` - The callback data containing the CSRF state, nonce key, and authorization code
    ///
    /// # Returns
    /// Returns a [`User`] struct containing the user's information.
    pub async fn callback(
        &self,
        code: String,
        nonce_key: String,
    ) -> Result<(User, Session), Error> {
        // Create http client for async requests
        // TODO: move to builder
        let http_client = openidconnect::reqwest::ClientBuilder::new()
            .build()
            .map_err(|_| Error::InternalServerError)?;

        // Discover endpoints using async discover
        // TODO: Move to builder / init
        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new("https://accounts.google.com".to_string()).unwrap(),
            &http_client,
        )
        .await
        .map_err(|_| Error::InternalServerError)?;

        // Create client from provider metadata
        // TODO: Move to builder / init
        let oauth_client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        )
        .set_redirect_uri(RedirectUrl::new(self.redirect_uri.clone()).unwrap());

        // Exchange code for token response
        let token_response = oauth_client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|_| Error::InternalServerError)?
            .request_async(&http_client)
            .await
            .map_err(|e| {
                tracing::error!(
                    error = ?e,
                    "Error exchanging code for token response"
                );
                Error::InternalServerError
            })?;

        tracing::info!("Successfully exchanged code for token response");

        // Get id token from token response
        let id_token = token_response.id_token().ok_or(Error::InvalidCredentials)?;

        tracing::info!("Successfully got id token from token response");

        // Get nonce from database
        tracing::info!(
            nonce_key = ?nonce_key,
            "Attempting to get nonce from database"
        );
        let nonce = self
            .storage
            .user_storage()
            .get_nonce(&nonce_key)
            .await
            .map_err(|_| Error::InternalServerError)?;

        let nonce = match nonce {
            Some(nonce) => nonce.to_string(),
            None => return Err(Error::InvalidCredentials),
        };

        // Verify id token
        let id_token_verifier = oauth_client.id_token_verifier();
        let claims = id_token
            .claims(&id_token_verifier, &Nonce::new(nonce))
            .map_err(|_| Error::InvalidCredentials)?;

        tracing::info!(claims = ?claims, "Verified id token");

        let subject = claims.subject().to_string();
        let email = claims.email().ok_or(Error::InvalidCredentials)?.to_string();
        let name = claims
            .name()
            .ok_or(Error::InvalidCredentials)?
            .get(None)
            .ok_or(Error::InvalidCredentials)?
            .to_string();

        tracing::info!(
            subject = ?subject,
            email = ?email,
            name = ?name,
            "User claims"
        );

        let user = self
            .get_or_create_user(email, subject)
            .await
            .map_err(|_| Error::InternalServerError)?;

        let session = self
            .storage
            .session_storage()
            .create_session(&Session::builder().user_id(user.id.clone()).build().unwrap())
            .await
            .map_err(|_| Error::InternalServerError)?;

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

#[async_trait]
impl<U, S> AuthPlugin for OAuthPlugin<U, S>
where
    U: OAuthStorage,
    S: SessionStorage,
{
    fn auth_method(&self) -> &str {
        &self.provider
    }

    async fn authenticate(&self, credentials: &Credentials) -> Result<AuthResponse, Error> {
        match credentials {
            Credentials::OAuth {
                provider,
                token,
                nonce_key,
            } => {
                if provider != &self.provider {
                    return Err(Error::InvalidCredentials);
                }

                let (user, session) = self
                    .callback(token.to_string(), nonce_key.to_string())
                    .await?;

                Ok(AuthResponse {
                    user,
                    session,
                    metadata: HashMap::new(),
                })
            }
            _ => return Err(Error::InvalidCredentials),
        }
    }

    async fn validate_session(&self, session: &Session) -> Result<bool, Error> {
        let session = self
            .storage
            .session_storage()
            .get_session(&session.id)
            .await
            .map_err(|_| Error::InternalServerError)?;

        match session {
            Some(session) => Ok(!session.is_expired()),
            _ => Ok(false),
        }
    }

    async fn logout(&self, session: &Session) -> Result<(), Error> {
        self.storage
            .session_storage()
            .delete_session(&session.id)
            .await
            .map_err(|_| Error::InternalServerError)?;

        Ok(())
    }
}
