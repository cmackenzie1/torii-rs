use torii::{Torii, ToriiError};

async fn handle_oauth_callback(
    torii: &Torii<impl torii_core::storage::UserStorage + torii_core::storage::OAuthStorage>,
    provider: &str,
    code: &str,
    state: &str
) -> Result<(), ToriiError> {
    // Exchange the code for tokens and authenticate the user
    let (user, session) = torii.exchange_oauth_code(
        provider,
        code,
        state,
        Some("Browser User Agent".to_string()),
        Some("127.0.0.1".to_string())
    ).await?;

    println!("OAuth user authenticated: {}", user.id);
    println!("Session token: {}", session.token);

    Ok(())
}