use torii::{Torii, ToriiError};
use torii_core::RepositoryProvider;

async fn handle_oauth_callback<R: RepositoryProvider>(
    torii: &Torii<R>,
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
    let token = session.token.as_ref().expect("freshly created session should have token");
    println!("Session token: {}", token);

    Ok(())
}
