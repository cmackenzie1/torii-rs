use torii::{Torii, ToriiError};
use torii_core::RepositoryProvider;

async fn start_oauth_flow<R: RepositoryProvider>(
    torii: &Torii<R>,
    provider: &str
) -> Result<String, ToriiError> {
    // Get the authorization URL for the provider
    let auth_url = torii.get_oauth_authorization_url(provider).await?;

    // Store the CSRF state in your session/cookies
    let csrf_state = auth_url.csrf_state;

    // Return the URL to redirect the user to
    Ok(auth_url.url)
}
