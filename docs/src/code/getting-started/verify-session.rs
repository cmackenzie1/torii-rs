use torii::{Torii, SessionToken, ToriiError};
use torii_core::RepositoryProvider;

async fn verify_session(
    torii: &Torii<impl RepositoryProvider>,
    session_token: &str
) -> Result<(), ToriiError> {
    // Parse the session token
    let token = SessionToken::new(session_token);

    // Verify and get session data (works for both JWT and opaque tokens)
    let session = torii.get_session(&token).await?;

    // Get the user associated with this session
    let user = torii.get_user(&session.user_id).await?
        .ok_or_else(|| ToriiError::AuthError("User not found".to_string()))?;

    println!("Session verified for user: {}", user.id);
    Ok(())
}