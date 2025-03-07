use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, StandardTokenResponse, TokenUrl,
    basic::{BasicClient, BasicTokenType},
};
use serde::Deserialize;
use torii_core::{Error, error::AuthError};

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

    pub fn get_authorization_url(&self) -> Result<(AuthorizationUrl, String), Error> {
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

        Ok((
            AuthorizationUrl {
                url: auth_url.to_string(),
                csrf_state: csrf_state.secret().to_string(),
            },
            pkce_verifier.secret().to_string(),
        ))
    }

    pub async fn get_user_info(&self, access_token: &str) -> Result<UserInfo, Error> {
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| Error::Auth(AuthError::InvalidCredentials))?;

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
                Error::Auth(AuthError::InvalidCredentials)
            })?
            .error_for_status()
            .map_err(|e| {
                tracing::error!(error = ?e, status = ?e.status(), "GitHub API returned error status");
                Error::Auth(AuthError::InvalidCredentials)
            })?
            .json::<GithubUserInfo>()
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to parse GitHub user info response");
                Error::Auth(AuthError::InvalidCredentials)
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
                Error::Auth(AuthError::InvalidCredentials)
            })?
            .error_for_status()
            .map_err(|e| {
                tracing::error!(error = ?e, "GitHub API returned error status for emails");
                Error::Auth(AuthError::InvalidCredentials)
            })?
            .json::<Vec<GithubUserEmail>>()
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Failed to parse GitHub user emails response");
                Error::Auth(AuthError::InvalidCredentials)
            })?;

        let email = emails
            .into_iter()
            .find(|email| email.primary && email.verified)
            .map(|email| email.email);

        Ok(UserInfo::Github(GithubUserInfo { email, ..user_info }))
    }

    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
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
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_string()))
            .request_async(&http_client)
            .await
            .map_err(|_| Error::Auth(AuthError::InvalidCredentials))?;

        Ok(token_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_github_get_authorization_url() {
        let github = Github::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost:8080/callback".to_string(),
        );

        let (auth_url, pkce_verifier) = github.get_authorization_url().unwrap();
        assert!(auth_url.url.contains("github.com"));
        assert!(auth_url.url.contains("client_id=client_id"));
        assert!(auth_url.url.contains("scope=read%3Auser+user%3Aemail"));
        assert!(!auth_url.csrf_state.is_empty());
        assert!(!pkce_verifier.is_empty());
    }

    #[test]
    fn test_github_user_info_deserialization() {
        let json = r#"{
            "login": "octocat",
            "id": 1,
            "avatar_url": "https://github.com/images/error/octocat_happy.gif",
            "name": "monalisa octocat",
            "email": "octocat@github.com",
            "created_at": "2008-01-14T04:33:35Z",
            "updated_at": "2008-01-14T04:33:35Z"
        }"#;

        let user_info: GithubUserInfo = serde_json::from_str(json).unwrap();
        assert_eq!(user_info.login, "octocat");
        assert_eq!(user_info.id, 1);
        assert_eq!(user_info.name.as_deref(), Some("monalisa octocat"));
        assert_eq!(user_info.email.as_deref(), Some("octocat@github.com"));
    }

    #[test]
    fn test_github_user_email_deserialization() {
        let json = r#"{
            "email": "octocat@github.com",
            "primary": true,
            "verified": true
        }"#;

        let email: GithubUserEmail = serde_json::from_str(json).unwrap();
        assert_eq!(email.email, "octocat@github.com");
        assert!(email.primary);
        assert!(email.verified);
    }
}
