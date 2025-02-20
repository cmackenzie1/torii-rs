use std::{collections::HashMap, time::Duration};

use async_trait::async_trait;
use oauth2::{
    basic::BasicClient, reqwest, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};

use torii_core::{
    events::{Event, EventBus},
    storage::OAuthStorage,
    AuthPlugin, AuthResponse, Credentials,
};
use torii_core::{storage::Storage, Error, NewUser, Plugin, Session, SessionStorage, User, UserId};

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
#[derive(Clone)]
pub struct OAuthConfig {
    /// The provider name. i.e. "google"
    pub provider: String,
    /// The scopes to request from the provider
    pub scopes: Vec<String>,
    /// The client id.
    pub client_id: String,
    /// The client secret.
    pub client_secret: String,
    /// The redirect uri.
    pub redirect_uri: String,
    /// The authorization url.
    pub auth_url: String,
    /// The token url.
    pub token_url: String,
}

pub struct OAuthPlugin<U: OAuthStorage, S: SessionStorage> {
    /// The plugin configuration
    config: OAuthConfig,
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
        self.config.provider.clone()
    }
}

pub struct OAuthPluginBuilder<U: OAuthStorage, S: SessionStorage> {
    provider: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    auth_url: String,
    token_url: String,
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
            auth_url: String::new(),
            token_url: String::new(),
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

    pub fn auth_url(mut self, auth_url: impl Into<String>) -> Self {
        self.auth_url = auth_url.into();
        self
    }

    pub fn token_url(mut self, token_url: impl Into<String>) -> Self {
        self.token_url = token_url.into();
        self
    }

    pub fn add_scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    pub fn add_scopes(mut self, scopes: impl Into<Vec<String>>) -> Self {
        self.scopes.extend(scopes.into());
        self
    }

    pub fn event_bus(mut self, event_bus: EventBus) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    pub fn build(self) -> OAuthPlugin<U, S> {
        OAuthPlugin {
            config: OAuthConfig {
                provider: self.provider,
                client_id: self.client_id,
                client_secret: self.client_secret,
                redirect_uri: self.redirect_uri,
                auth_url: self.auth_url,
                token_url: self.token_url,
                scopes: self.scopes,
            },
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

    pub fn new(config: OAuthConfig, storage: Storage<U, S>) -> Self {
        Self {
            config,
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
            .auth_url("https://accounts.google.com/o/oauth2/v2/auth")
            .token_url("https://www.googleapis.com/oauth2/v3/token")
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
    pub async fn begin_auth(&self) -> Result<AuthFlowBegin, Error> {
        // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
        // token URL.
        let client = BasicClient::new(ClientId::new(self.config.client_id.clone()))
            .set_client_secret(ClientSecret::new(self.config.client_secret.clone()))
            .set_auth_uri(AuthUrl::new(self.config.auth_url.clone()).expect("Invalid auth URL"))
            .set_token_uri(TokenUrl::new(self.config.token_url.clone()).expect("Invalid token URL"))
            // Set the URL the user will be redirected to after the authorization process.
            .set_redirect_uri(
                RedirectUrl::new(self.config.redirect_uri.clone()).expect("Invalid redirect URI"),
            );

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Generate the full authorization URL.
        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            // Set the desired scopes.
            .add_scopes(
                self.config
                    .scopes
                    .iter()
                    .map(|s| Scope::new(s.clone()))
                    .collect::<Vec<_>>(),
            )
            // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge)
            .url();

        self.storage
            .user_storage()
            .store_pkce_verifier(
                &csrf_token.secret().to_string(),
                &pkce_verifier.secret().to_string(),
                Duration::from_secs(60 * 5),
            )
            .await
            .map_err(|_| Error::InternalServerError)?;

        Ok(AuthFlowBegin {
            csrf_state: csrf_token.secret().to_string(),
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
            .get_oauth_account_by_provider_and_subject(&self.config.provider, &subject)
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
            .create_oauth_account(&self.config.provider, &subject, &user.id)
            .await
            .map_err(|_| Error::InternalServerError)?;

        tracing::info!(
            user_id = ?user.id,
            provider = ?self.config.provider,
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
        csrf_state: String,
    ) -> Result<(User, Session), Error> {
        // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
        // token URL.
        let client = BasicClient::new(ClientId::new(self.config.client_id.clone()))
            .set_client_secret(ClientSecret::new(self.config.client_secret.clone()))
            .set_auth_uri(AuthUrl::new(self.config.auth_url.clone()).expect("Invalid auth URL"))
            .set_token_uri(TokenUrl::new(self.config.token_url.clone()).expect("Invalid token URL"))
            // Set the URL the user will be redirected to after the authorization process.
            .set_redirect_uri(
                RedirectUrl::new(self.config.redirect_uri.clone()).expect("Invalid redirect URI"),
            );

        let http_client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");

        let pkce_verifier = self
            .storage
            .user_storage()
            .get_pkce_verifier(&csrf_state)
            .await
            .map_err(|_| Error::InternalServerError)?
            .ok_or(Error::InvalidCredentials)?;

        // Now you can trade it for an access token.
        let token_result = client
            .exchange_code(AuthorizationCode::new(code))
            // Set the PKCE code verifier.
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(&http_client)
            .await
            .map_err(|_| Error::InternalServerError)?;

        tracing::info!(
            token = ?token_result,
            "Token result"
        );

        let access_token = token_result.access_token();

        // Get user info from Google's userinfo endpoint
        let user_info_response = http_client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(access_token.secret())
            .send()
            .await
            .map_err(|_| Error::InternalServerError)?
            .json::<serde_json::Value>()
            .await
            .map_err(|_| Error::InternalServerError)?;

        tracing::info!(user_info_response = ?user_info_response, "User info response");
        let email = user_info_response["email"]
            .as_str()
            .ok_or(Error::InternalServerError)?
            .to_string();

        let subject = user_info_response["id"]
            .as_str()
            .ok_or(Error::InternalServerError)?
            .to_string();

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
        &self.config.provider
    }

    async fn authenticate(&self, credentials: &Credentials) -> Result<AuthResponse, Error> {
        match credentials {
            Credentials::OAuth {
                provider,
                token,
                nonce_key,
            } => {
                if provider != &self.config.provider {
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
