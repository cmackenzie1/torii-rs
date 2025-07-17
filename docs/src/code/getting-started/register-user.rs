use torii::{Torii, ToriiError};
use torii_core::RepositoryProvider;

async fn register_user(
    torii: &Torii<impl RepositoryProvider>,
    email: &str,
    password: &str
) -> Result<(), ToriiError> {
    // Register a new user
    let user = torii.register_user_with_password(email, password).await?;

    println!("User registered: {}", user.id);
    Ok(())
}