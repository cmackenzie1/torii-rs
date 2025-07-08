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

pub struct AuthState<R: RepositoryProvider> {
    pub torii: Arc<Torii<R>>,
}

impl<R: RepositoryProvider> Clone for AuthState<R> {
    fn clone(&self) -> Self {
        Self {
            torii: self.torii.clone(),
        }
    }
}

pub async fn auth_middleware<R>(
    State(state): State<AuthState<R>>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Response
where
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
        match state.torii.get_session(&session_token).await {
            Ok(session) => match state.torii.get_user(&session.user_id).await {
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

pub async fn require_auth<R>(
    State(state): State<AuthState<R>>,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Result<Response, AuthError>
where
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
        .torii
        .get_session(&session_token)
        .await
        .map_err(|_| AuthError::InvalidSession)?;

    Ok(next.run(request).await)
}
