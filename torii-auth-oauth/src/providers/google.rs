use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, StandardTokenResponse, TokenUrl,
    basic::{BasicClient, BasicTokenType},
};
use serde::Deserialize;
use torii_core::{Error, error::AuthError};

use super::{AuthorizationUrl, UserInfo};

pub struct Google {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const DEFAULT_SCOPES: &str = "openid email profile";

/// A limited subset of the user info response from Google.
#[derive(Debug, Clone, Deserialize)]
pub struct GoogleUserInfo {
    pub email: String,
    pub name: String,
    pub picture: String,
    pub sub: String,
}

impl Google {
    pub fn new(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_uri,
        }
    }
    pub fn get_authorization_url(&self) -> Result<(AuthorizationUrl, String), Error> {
        // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
        // token URL.
        let client = BasicClient::new(ClientId::new(self.client_id.clone()))
            .set_client_secret(ClientSecret::new(self.client_secret.clone()))
            .set_auth_uri(AuthUrl::new(GOOGLE_AUTH_URL.to_string()).expect("Invalid auth URL"))
            .set_token_uri(TokenUrl::new(GOOGLE_TOKEN_URL.to_string()).expect("Invalid token URL"))
            .set_redirect_uri(
                RedirectUrl::new(self.redirect_uri.clone()).expect("Invalid redirect URI"),
            );

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (auth_url, csrf_state) = client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge)
            .add_scopes(
                DEFAULT_SCOPES
                    .split_whitespace()
                    .map(|s| Scope::new(s.to_string()))
                    .collect::<Vec<_>>(),
            )
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
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");

        // Get user info from Google's userinfo endpoint
        let user_info = http_client
            .get("https://openidconnect.googleapis.com/v1/userinfo")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(
                    error = ?e,
                    "Error getting user info"
                );
                Error::Auth(AuthError::InvalidCredentials)
            })?
            .json::<GoogleUserInfo>()
            .await
            .map_err(|e| {
                tracing::error!(
                    error = ?e,
                    "Error parsing user info"
                );
                Error::Auth(AuthError::InvalidCredentials)
            })?;

        Ok(UserInfo::Google(user_info))
    }

    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
    ) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, Error> {
        let client = BasicClient::new(ClientId::new(self.client_id.clone()))
            .set_client_secret(ClientSecret::new(self.client_secret.clone()))
            .set_auth_uri(AuthUrl::new(GOOGLE_AUTH_URL.to_string()).expect("Invalid auth URL"))
            .set_token_uri(TokenUrl::new(GOOGLE_TOKEN_URL.to_string()).expect("Invalid token URL"))
            .set_redirect_uri(
                RedirectUrl::new(self.redirect_uri.clone()).expect("Invalid redirect URI"),
            );

        let http_client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
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
    async fn test_google_get_authorization_url() {
        let google = Google::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost:8080/callback".to_string(),
        );

        let (auth_url, pkce_verifier) = google.get_authorization_url().unwrap();
        assert!(auth_url.url.contains("accounts.google.com"));
        assert!(auth_url.url.contains("client_id=client_id"));
        assert!(auth_url.url.contains("scope=openid+email+profile"));
        assert!(!auth_url.csrf_state.is_empty());
        assert!(!pkce_verifier.is_empty());
    }
}
