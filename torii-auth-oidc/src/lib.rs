use async_trait::async_trait;
use chrono::{Duration, Utc};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, RedirectUrl, Scope,
    TokenResponse,
};
use torii_core::{Error, NewUser, Plugin, Session, SessionStorage, User, UserId, UserStorage};
use torii_storage_sqlite::{OIDCAccount, OIDCStorage};
use uuid::Uuid;

/// The core OIDC plugin struct, responsible for handling OIDC authentication flow.
///
/// See the [`OIDCPlugin`] struct for the core plugin struct.
///
/// See the [`AuthFlowBegin`] and [`AuthFlowCallback`] structs for the core authentication flow.
pub struct OIDCPlugin {
    /// The provider name. i.e. "google" or "github"
    provider: String,

    /// The client id.
    client_id: String,

    /// The client secret.
    client_secret: String,

    /// The redirect uri.
    redirect_uri: String,
}

/// The start of the OIDC authentication flow for authorization code grant. This is the first step in the flow and is used to start the flow by redirecting the user to the provider's authorization URL.
///
/// See the [`OIDCPlugin::begin_auth`] method for the core authentication flow.
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

impl OIDCPlugin {
    pub fn new(
        provider: String,
        client_id: String,
        client_secret: String,
        redirect_uri: String,
    ) -> Self {
        Self {
            provider,
            client_id,
            client_secret,
            redirect_uri,
        }
    }
}

impl OIDCPlugin {
    /// Begin the authentication process by generating a new CSRF state and redirecting the user to the provider's authorization URL.
    ///
    /// This method is the first step in the OIDC authorization code flow. It will:
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
    pub async fn begin_auth<U: OIDCStorage, S: SessionStorage>(
        &self,
        user_storage: &U,
        _session_storage: &S,
        redirect_uri: String,
    ) -> Result<AuthFlowBegin, Error> {
        let http_client = openidconnect::reqwest::ClientBuilder::new()
            .build()
            .map_err(|_| Error::InternalServerError)?;

        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new("https://accounts.google.com".to_string()).unwrap(),
            &http_client,
        )
        .await
        .map_err(|_| Error::InternalServerError)?;

        let oidc_client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri).unwrap());

        let (auth_url, csrf_token, nonce) = oidc_client
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
        user_storage
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

    /// Complete the authentication process by exchanging the authorization code for an access token and user information.
    ///
    /// This method is the second step in the OIDC authorization code flow. It will:
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
    pub async fn callback<U: OIDCStorage, S: SessionStorage>(
        &self,
        user_storage: &U,
        session_storage: &S,
        auth_flow: &AuthFlowCallback,
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
        let oidc_client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        )
        .set_redirect_uri(RedirectUrl::new(self.redirect_uri.clone()).unwrap());

        // Exchange code for token response
        let token_response = oidc_client
            .exchange_code(AuthorizationCode::new(auth_flow.code.to_string()))
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
        let id_token = token_response
            .id_token()
            .ok_or_else(|| Error::InvalidCredentials)?;

        tracing::info!("Successfully got id token from token response");

        // Get nonce from database
        tracing::info!(
            nonce_key = ?auth_flow.nonce_key,
            "Attempting to get nonce from database"
        );
        let nonce = user_storage
            .get_nonce(&auth_flow.nonce_key)
            .await
            .map_err(|_| Error::InternalServerError)?;

        let nonce = match nonce {
            Some(nonce) => nonce.to_string(),
            None => return Err(Error::InvalidCredentials),
        };

        // Verify id token
        let id_token_verifier = oidc_client.id_token_verifier();
        let claims = id_token
            .claims(&id_token_verifier, &Nonce::new(nonce))
            .map_err(|_| Error::InvalidCredentials)?;

        tracing::info!(claims = ?claims, "Verified id token");

        let subject = claims.subject().to_string();
        let email = claims.email().ok_or_else(|| Error::InvalidCredentials)?;
        let name = claims
            .name()
            .ok_or_else(|| Error::InvalidCredentials)?
            .get(None)
            .unwrap();

        tracing::info!(
            subject = ?subject,
            email = ?email,
            name = ?name,
            "User claims"
        );

        // Check if user exists in database by email
        let oidc_account = user_storage
            .get_oidc_account_by_provider_and_subject(&self.provider, &subject)
            .await
            .map_err(|_| Error::InternalServerError)?;

        if let Some(oidc_account) = oidc_account {
            tracing::info!(
                user_id = ?oidc_account.user_id,
                "User already exists in database"
            );

            let user = user_storage
                .get_user(&oidc_account.user_id)
                .await
                .map_err(|_| Error::InternalServerError)?
                .ok_or_else(|| Error::UserNotFound)?;

            // The user has already been created, so we can return them immediately
            return Ok((
                user.clone(),
                session_storage
                    .create_session(&Session::builder().user_id(user.id.clone()).build().unwrap())
                    .await
                    .map_err(|_| Error::InternalServerError)?,
            ));
        }

        // Create user if they don't exist
        let user = user_storage
            .create_user(&NewUser {
                id: UserId::new_random(),
                email: email.to_string(),
            })
            .await
            .map_err(|_| Error::InternalServerError)?;

        // Create link between user and provider
        user_storage
            .create_oidc_account(&OIDCAccount {
                user_id: user.id.to_string(),
                provider: self.provider.clone(),
                subject: subject.clone(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
            .await
            .map_err(|_| Error::InternalServerError)?;

        tracing::info!(
            user_id = ?user.id,
            provider = ?self.provider,
            subject = ?subject,
            "Successfully created link between user and provider"
        );

        // Create a new session
        let session = Session::builder().user_id(user.id.clone()).build().unwrap();

        let session = user_storage
            .create_session(&session)
            .await
            .map_err(|_| Error::InternalServerError)?;

        tracing::info!(
            user_id = ?user.id,
            session_id = ?session.id,
            provider = ?self.provider,
            subject = ?subject,
            "Successfully created session for authenticated user"
        );

        Ok((user, session))
    }
}

#[async_trait]
impl<U: UserStorage, S: SessionStorage> Plugin<U, S> for OIDCPlugin {
    fn name(&self) -> &'static str {
        "oidc"
    }

    async fn setup(&self, _user_storage: &U, _session_storage: &S) -> Result<(), Error> {
        Ok(())
    }
}
