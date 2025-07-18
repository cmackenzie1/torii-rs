use torii::{Torii, ToriiError};
use torii_core::RepositoryProvider;

async fn login_user(
    torii: &Torii<impl RepositoryProvider>,
    email: &str,
    password: &str
) -> Result<(), ToriiError> {
    // Authenticate user - optional user_agent and ip_address for tracking
    let (user, session) = torii.password().authenticate(
        email,
        password,
        Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()),
        Some("127.0.0.1".to_string())
    ).await?;

    // The session token can be stored in a cookie or returned to the client
    println!("User authenticated: {}", user.id);
    println!("Session token: {}", session.token);

    Ok(())
}