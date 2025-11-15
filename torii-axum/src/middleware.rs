use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::CookieJar;
use torii::{SessionToken, Torii, User};
use torii_core::RepositoryProvider;

use crate::error::AuthError;

/// Trait for application states that contain a Torii instance.
///
/// Your application state must implement this trait to use Torii middleware.
///
/// # Example
///
/// ```rust
/// use std::sync::Arc;
/// use torii::Torii;
/// use torii_axum::HasTorii;
///
/// #[derive(Clone)]
/// struct AppState<R> {
///     pub torii: Arc<Torii<R>>,
///     pub database: Arc<sqlx::PgPool>,
///     // ... other state fields
/// }
///
/// impl<R> HasTorii<R> for AppState<R>
/// where
///     R: RepositoryProvider,
/// {
///     fn torii(&self) -> &Torii<R> {
///         &self.torii
///     }
/// }
/// ```
pub trait HasTorii<R>
where
    R: RepositoryProvider,
{
    /// Returns a reference to the Torii instance.
    fn torii(&self) -> &Torii<R>;
}

// Blanket implementation for Arc<Torii<R>> - allows using Torii directly as state
impl<R> HasTorii<R> for Arc<Torii<R>>
where
    R: RepositoryProvider,
{
    fn torii(&self) -> &Torii<R> {
        self
    }
}

pub async fn auth_middleware<S, R>(
    State(state): State<S>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Response
where
    S: HasTorii<R>,
    R: RepositoryProvider,
{
    request.extensions_mut().insert(None::<User>);

    // Try Bearer token first, then fall back to cookie
    let session_token = if let Some(token) = extract_bearer_token(&request) {
        Some(SessionToken::new(&token))
    } else {
        jar.get("session_id")
            .and_then(|cookie| cookie.value().parse::<String>().ok())
            .map(|session_id| SessionToken::new(&session_id))
    };

    if let Some(session_token) = session_token {
        match state.torii().get_session(&session_token).await {
            Ok(session) => match state.torii().get_user(&session.user_id).await {
                Ok(Some(user)) => {
                    request.extensions_mut().insert(user.clone());
                    request.extensions_mut().insert(Some(user));
                }
                Ok(None) => {
                    tracing::warn!("User not found for session: {:?}", session.user_id);
                }
                Err(e) => {
                    tracing::error!("Error getting user: {:?}", e);
                }
            },
            Err(e) => {
                tracing::debug!("Invalid session: {:?}", e);
            }
        }
    }

    next.run(request).await
}

fn extract_bearer_token(request: &Request) -> Option<String> {
    request
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
        .map(|token| token.to_string())
}

pub async fn require_auth<S, R>(
    State(state): State<S>,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Result<Response, AuthError>
where
    S: HasTorii<R>,
    R: RepositoryProvider,
{
    // Try Bearer token first, then fall back to cookie
    let session_token = if let Some(token) = extract_bearer_token(&request) {
        SessionToken::new(&token)
    } else {
        let session_id = jar
            .get("session_id")
            .and_then(|cookie| cookie.value().parse::<String>().ok())
            .ok_or(AuthError::Unauthorized)?;
        SessionToken::new(&session_id)
    };

    let _session = state
        .torii()
        .get_session(&session_token)
        .await
        .map_err(|_| AuthError::InvalidSession)?;

    Ok(next.run(request).await)
}
