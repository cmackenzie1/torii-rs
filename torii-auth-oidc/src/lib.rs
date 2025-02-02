use async_trait::async_trait;
use chrono::{Duration, Utc};
use migrations::CreateOidcTables;
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, RedirectUrl, Scope,
    TokenResponse,
};
use sqlx::{Pool, Row, Sqlite};
use torii_core::{migration::PluginMigration, Error, Plugin, User};
use uuid::Uuid;
mod migrations;

pub struct OIDCPlugin {
    provider: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

#[derive(Debug)]
pub struct AuthFlowBegin {
    pub csrf_state: String,
    pub nonce_key: String,
    pub redirect_uri: String,
}

#[derive(Debug)]
pub struct AuthFlowCallback {
    pub csrf_state: String,
    pub nonce_key: String,
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

    /// Begin the authentication process by generating a new CSRF state and redirecting the user to the provider's authorization URL.
    pub async fn begin_auth(
        &self,
        pool: &Pool<Sqlite>,
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
        sqlx::query("INSERT INTO nonces (id, value, expires_at) VALUES (?, ?, ?)")
            .bind(nonce_key.clone())
            .bind(nonce.secret().to_string())
            .bind(Utc::now() + Duration::hours(1))
            .execute(pool)
            .await
            .map_err(|_| Error::InternalServerError)?;

        tracing::info!(nonce_key = nonce_key.clone(), "Stored nonce in database");

        Ok(AuthFlowBegin {
            csrf_state: csrf_token.secret().to_string(),
            nonce_key: nonce_key.to_string(),
            redirect_uri: auth_url.to_string(),
        })
    }

    /// Complete the authentication process by exchanging the authorization code for an access token and user information.
    pub async fn callback(
        &self,
        pool: &Pool<Sqlite>,
        auth_flow: &AuthFlowCallback,
    ) -> Result<User, Error> {
        let mut tx = pool.begin().await.map_err(|_| Error::InternalServerError)?;

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
        let nonce = sqlx::query("SELECT value FROM nonces WHERE id = ? AND expires_at > ? LIMIT 1")
            .bind(auth_flow.nonce_key.to_string())
            .bind(Utc::now())
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(
                    nonce_key = auth_flow.nonce_key.clone(),
                    error = ?e,
                    "Unable to get nonce from database"
                );
                Error::InternalServerError
            })?;

        let nonce: String = match nonce {
            Some(nonce) => nonce.get("value"),
            None => {
                tracing::error!("Nonce not found in database");
                return Err(Error::InvalidCredentials);
            }
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
        let user = sqlx::query(
            r#"SELECT id, name, email, email_verified_at, created_at, updated_at
            FROM users
            WHERE id = (
                SELECT user_id
                FROM oidc_accounts
                WHERE provider = ? AND subject = ?
                LIMIT 1
            )"#,
        )
        .bind(&self.provider)
        .bind(&subject)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| Error::InternalServerError)?;

        let user = match user {
            Some(user) => {
                tracing::info!(user.email = ?email, "User found in database");
                user
            }
            None => {
                tracing::info!("User not found in database, creating user");
                // User does not exist, create user
                sqlx::query("INSERT INTO users (id, email, name) VALUES (?, ?, ?)")
                    .bind(Uuid::new_v4().to_string())
                    .bind(email.as_str())
                    .bind(name.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| {
                        tracing::error!(
                            error = ?e,
                            "Unable to create user in database"
                        );
                        Error::InternalServerError
                    })?;

                sqlx::query(
                    r#"SELECT id, name, email, email_verified_at, created_at, updated_at FROM users WHERE email = ?"#,
                )
                .bind(email.as_str())
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::error!(
                        error = ?e,
                        "Unable to get user from database"
                    );
                    Error::InternalServerError
                })?
            }
        };

        let user = User {
            id: user.get("id"),
            name: user.get("name"),
            email: user.get("email"),
            email_verified_at: user.get("email_verified_at"),
            created_at: user.get("created_at"),
            updated_at: user.get("updated_at"),
        };
        tracing::info!(user = ?user, "User created in database");

        // Create link between user and provider
        sqlx::query("INSERT INTO oidc_accounts (user_id, provider, subject) VALUES (?, ?, ?)")
            .bind(&user.id)
            .bind(&self.provider)
            .bind(&subject)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(
                    error = ?e,
                    "Unable to create link between user and provider"
                );
                Error::InternalServerError
            })?;

        tracing::info!(
            user_id = ?user.id,
            provider = ?self.provider,
            subject = ?subject,
            "Successfully created link between user and provider"
        );

        Ok(user)
    }
}

#[async_trait]
impl Plugin for OIDCPlugin {
    fn name(&self) -> &'static str {
        "oidc"
    }

    async fn setup(&self, _pool: &Pool<Sqlite>) -> Result<(), Error> {
        Ok(())
    }

    fn migrations(&self) -> Vec<Box<dyn PluginMigration>> {
        vec![Box::new(CreateOidcTables)]
    }
}
