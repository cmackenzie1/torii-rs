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
    pub fn name(&self) -> String {
        match self {
            Self::Google(_) => "google".to_string(),
            Self::Github(_) => "github".to_string(),
        }
    }

    pub fn google(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        Self::Google(google::Google::new(client_id, client_secret, redirect_uri))
    }

    pub fn github(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        Self::Github(github::Github::new(client_id, client_secret, redirect_uri))
    }

    pub fn get_authorization_url(&self) -> Result<AuthorizationUrl, Error> {
        match self {
            Self::Google(google) => google.get_authorization_url(),
            Self::Github(github) => github.get_authorization_url(),
        }
    }

    pub async fn get_user_info(&self, access_token: String) -> Result<UserInfo, Error> {
        match self {
            Self::Google(google) => google.get_user_info(access_token).await,
            Self::Github(github) => github.get_user_info(access_token).await,
        }
    }

    pub async fn exchange_code(
        &self,
        code: String,
        pkce_verifier: String,
    ) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, Error> {
        let token_response = match self {
            Self::Google(google) => google.exchange_code(code, pkce_verifier).await,
            Self::Github(github) => github.exchange_code(code, pkce_verifier).await,
        }?;

        tracing::debug!(
            token_response = ?token_response,
            "Exchanged code for token"
        );

        Ok(token_response)
    }
}

#[derive(Debug, Clone)]
pub enum UserInfo {
    Google(google::GoogleUserInfo),
    Github(github::GithubUserInfo),
}
