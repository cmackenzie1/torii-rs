use oauth2::{EmptyExtraTokenFields, StandardTokenResponse, basic::BasicTokenType};
use torii_core::Error;

use crate::AuthorizationUrl;

mod github;
mod google;

pub enum Provider {
    Google(google::Google),
    Github(github::Github),
}

impl Provider {
    pub fn name(&self) -> &str {
        match self {
            Self::Google(_) => "google",
            Self::Github(_) => "github",
        }
    }

    pub fn google(client_id: &str, client_secret: &str, redirect_uri: &str) -> Self {
        Self::Google(google::Google::new(
            client_id.to_string(),
            client_secret.to_string(),
            redirect_uri.to_string(),
        ))
    }

    pub fn github(client_id: &str, client_secret: &str, redirect_uri: &str) -> Self {
        Self::Github(github::Github::new(
            client_id.to_string(),
            client_secret.to_string(),
            redirect_uri.to_string(),
        ))
    }

    pub fn get_authorization_url(&self) -> Result<(AuthorizationUrl, String), Error> {
        match self {
            Self::Google(google) => google.get_authorization_url(),
            Self::Github(github) => github.get_authorization_url(),
        }
    }

    pub async fn get_user_info(&self, access_token: &str) -> Result<UserInfo, Error> {
        match self {
            Self::Google(google) => google.get_user_info(access_token).await,
            Self::Github(github) => github.get_user_info(access_token).await,
        }
    }

    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
    ) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, Error> {
        let token_response = match self {
            Self::Google(google) => google.exchange_code(code, pkce_verifier).await,
            Self::Github(github) => github.exchange_code(code, pkce_verifier).await,
        }?;

        Ok(token_response)
    }
}

#[derive(Debug, Clone)]
pub enum UserInfo {
    Google(google::GoogleUserInfo),
    Github(github::GithubUserInfo),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_name() {
        let google = Provider::google(
            "client_id",
            "client_secret",
            "http://localhost:8080/callback",
        );
        assert_eq!(google.name(), "google");

        let github = Provider::github(
            "client_id",
            "client_secret",
            "http://localhost:8080/callback",
        );
        assert_eq!(github.name(), "github");
    }

    #[tokio::test]
    async fn test_provider_get_authorization_url() {
        let google = Provider::google(
            "client_id",
            "client_secret",
            "http://localhost:8080/callback",
        );
        let (auth_url, _) = google.get_authorization_url().unwrap();
        assert!(auth_url.url().contains("accounts.google.com"));

        let github = Provider::github(
            "client_id",
            "client_secret",
            "http://localhost:8080/callback",
        );
        let (auth_url, _) = github.get_authorization_url().unwrap();
        assert!(auth_url.url().contains("github.com"));
    }
}
