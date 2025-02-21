use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, StandardTokenResponse, TokenUrl,
    basic::{BasicClient, BasicTokenType},
};
use serde::Deserialize;
use torii_core::Error;

use super::{AuthorizationUrl, UserInfo};

/// An OAuth provider for Github.
///
/// This provider is limited to the scopes `read:user` and `user:email`.
pub struct Github {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

const GITHUB_AUTH_URL: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const DEFAULT_SCOPES: &str = "read:user user:email";

/// A limited subset of the user info response from Github.
#[derive(Debug, Clone, Deserialize)]
pub struct GithubUserInfo {
    pub login: String,
    pub id: u64,
    pub avatar_url: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// A limited subset of the user emails response from Github.
#[derive(Debug, Clone, Deserialize)]
pub struct GithubUserEmail {
    pub email: String,
    pub primary: bool,
    pub verified: bool,
}

impl Github {
    pub fn new(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_uri,
        }
    }

    pub fn get_authorization_url(&self) -> Result<AuthorizationUrl, Error> {
        let client = BasicClient::new(ClientId::new(self.client_id.clone()))
            .set_client_secret(ClientSecret::new(self.client_secret.clone()))
            .set_auth_uri(AuthUrl::new(GITHUB_AUTH_URL.to_string()).expect("Invalid auth URL"))
            .set_redirect_uri(
                RedirectUrl::new(self.redirect_uri.clone()).expect("Invalid redirect URI"),
            );

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_state) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new(DEFAULT_SCOPES.to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        Ok(AuthorizationUrl {
            url: auth_url.to_string(),
            csrf_state: csrf_state.secret().to_string(),
            pkce_verifier: pkce_verifier.secret().to_string(),
        })
    }

    pub async fn get_user_info(&self, access_token: String) -> Result<UserInfo, Error> {
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| Error::InternalServerError)?;

        // Get user info
        let user_info = http_client
            .get("https://api.github.com/user")
            .bearer_auth(&access_token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "torii-auth")
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to get user info from GitHub API");
                Error::InternalServerError
            })?
            .error_for_status()
            .map_err(|e| {
                tracing::error!(error = ?e, status = ?e.status(), "GitHub API returned error status");
                Error::InternalServerError
            })?
            .json::<GithubUserInfo>()
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to parse GitHub user info response");
                Error::InternalServerError
            })?;

        // Get user emails
        let emails = http_client
            .get("https://api.github.com/user/emails")
            .bearer_auth(&access_token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "torii-auth")
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to get emails from GitHub API");
                Error::InternalServerError
            })?
            .error_for_status()
            .map_err(|e| {
                tracing::error!(error = ?e, "GitHub API returned error status for emails");
                Error::InternalServerError
            })?
            .json::<Vec<GithubUserEmail>>()
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to parse GitHub user emails response");
                Error::InternalServerError
            })?;

        let email = emails
            .into_iter()
            .find(|email| email.primary && email.verified)
            .map(|email| email.email);

        Ok(UserInfo::Github(GithubUserInfo { email, ..user_info }))
    }

    pub async fn exchange_code(
        &self,
        code: String,
        pkce_verifier: String,
    ) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, Error> {
        let client = BasicClient::new(ClientId::new(self.client_id.clone()))
            .set_client_secret(ClientSecret::new(self.client_secret.clone()))
            .set_token_uri(TokenUrl::new(GITHUB_TOKEN_URL.to_string()).expect("Invalid token URL"))
            .set_redirect_uri(
                RedirectUrl::new(self.redirect_uri.clone()).expect("Invalid redirect URI"),
            );

        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");

        let token_response = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(&http_client)
            .await
            .map_err(|_| Error::InternalServerError)?;

        Ok(token_response)
    }
}
