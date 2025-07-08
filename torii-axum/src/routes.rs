use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{delete, get, post},
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use torii::Torii;
use torii_core::RepositoryProvider;

use crate::{
    error::{AuthError, Result},
    extractors::{AuthUser, OptionalAuthUser, SessionTokenFromCookie},
    middleware::{AuthState, auth_middleware},
    types::*,
};

pub fn create_router<R>(torii: Arc<Torii<R>>, cookie_config: CookieConfig) -> Router
where
    R: RepositoryProvider + 'static,
{
    let state = AuthState { torii };

    let public_routes = Router::new()
        .route("/health", get(health_handler))
        .route("/session", get(get_session_handler))
        .route("/user", get(get_user_handler));

    let auth_routes = Router::new()
        .route("/logout", post(logout_handler).delete(logout_handler))
        .route("/session", delete(logout_handler));

    #[allow(unused_mut)]
    let mut router = Router::new().merge(public_routes).merge(auth_routes).layer(
        axum::middleware::from_fn_with_state(state.clone(), auth_middleware::<R>),
    );

    #[cfg(feature = "password")]
    {
        router = router.merge(password_routes());
    }

    #[cfg(feature = "magic-link")]
    {
        router = router.merge(magic_link_routes());
    }

    router
        .with_state(state)
        .layer(axum::Extension(cookie_config))
}

async fn health_handler<R>(State(state): State<AuthState<R>>) -> Result<impl IntoResponse>
where
    R: RepositoryProvider,
{
    state
        .torii
        .health_check()
        .await
        .map_err(|e| AuthError::InternalError(e.to_string()))?;

    Ok(Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    }))
}

async fn get_session_handler<R>(
    State(state): State<AuthState<R>>,
    SessionTokenFromCookie(session_token): SessionTokenFromCookie,
) -> Result<impl IntoResponse>
where
    R: RepositoryProvider,
{
    let session_token = session_token.ok_or(AuthError::Unauthorized)?;

    let session = state
        .torii
        .get_session(&session_token)
        .await
        .map_err(|_| AuthError::SessionNotFound)?;

    Ok(Json(SessionResponse { session }))
}

async fn get_user_handler(OptionalAuthUser(user): OptionalAuthUser) -> Result<impl IntoResponse> {
    match user {
        Some(user) => Ok(Json(UserResponse { user }).into_response()),
        None => Err(AuthError::Unauthorized),
    }
}

async fn logout_handler<R>(
    State(state): State<AuthState<R>>,
    jar: CookieJar,
    SessionTokenFromCookie(session_token): SessionTokenFromCookie,
) -> Result<impl IntoResponse>
where
    R: RepositoryProvider,
{
    if let Some(session_token) = session_token {
        let _ = state.torii.delete_session(&session_token).await;
    }

    let jar = jar.remove(Cookie::from("session_id"));

    Ok((
        jar,
        Json(MessageResponse {
            message: "Successfully logged out".to_string(),
        }),
    ))
}

#[cfg(feature = "password")]
fn password_routes<R>() -> Router<AuthState<R>>
where
    R: RepositoryProvider + 'static,
{
    Router::new()
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/password", post(change_password_handler))
}

#[cfg(feature = "password")]
async fn register_handler<R>(
    State(state): State<AuthState<R>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<impl IntoResponse>
where
    R: RepositoryProvider,
{
    let user = state
        .torii
        .register_user_with_password(&payload.email, &payload.password)
        .await?;

    Ok((StatusCode::CREATED, Json(UserResponse { user })))
}

#[cfg(feature = "password")]
async fn login_handler<R>(
    State(state): State<AuthState<R>>,
    axum::Extension(cookie_config): axum::Extension<CookieConfig>,
    connection_info: ConnectionInfo,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse>
where
    R: RepositoryProvider,
{
    let (user, session) = state
        .torii
        .login_user_with_password(
            &payload.email,
            &payload.password,
            connection_info.user_agent,
            connection_info.ip,
        )
        .await?;

    let same_site = match cookie_config.same_site {
        CookieSameSite::Strict => SameSite::Strict,
        CookieSameSite::Lax => SameSite::Lax,
        CookieSameSite::None => SameSite::None,
    };

    let cookie = Cookie::build((cookie_config.name, session.token.to_string()))
        .path(cookie_config.path)
        .http_only(cookie_config.http_only)
        .secure(cookie_config.secure)
        .same_site(same_site);

    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie.to_string())],
        Json(AuthResponse { user, session }),
    ))
}

#[cfg(feature = "password")]
async fn change_password_handler<R>(
    State(state): State<AuthState<R>>,
    AuthUser(user): AuthUser,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse>
where
    R: RepositoryProvider,
{
    state
        .torii
        .change_user_password(&user.id, &payload.old_password, &payload.new_password)
        .await?;

    Ok(Json(MessageResponse {
        message: "Password changed successfully".to_string(),
    }))
}

#[cfg(feature = "magic-link")]
fn magic_link_routes<R>() -> Router<AuthState<R>>
where
    R: RepositoryProvider + 'static,
{
    Router::new()
        .route("/magic-link", post(request_magic_link_handler))
        .route("/magic-link/verify", post(verify_magic_link_handler))
}

#[cfg(feature = "magic-link")]
async fn request_magic_link_handler<R>(
    State(state): State<AuthState<R>>,
    Json(payload): Json<MagicLinkRequest>,
) -> Result<impl IntoResponse>
where
    R: RepositoryProvider,
{
    let token = state.torii.generate_magic_token(&payload.email).await?;

    Ok(Json(MagicLinkResponse {
        message: "Magic link sent to your email".to_string(),
        token: Some(token.token),
    }))
}

#[cfg(feature = "magic-link")]
async fn verify_magic_link_handler<R>(
    State(state): State<AuthState<R>>,
    axum::Extension(cookie_config): axum::Extension<CookieConfig>,
    connection_info: ConnectionInfo,
    Json(payload): Json<VerifyMagicTokenRequest>,
) -> Result<impl IntoResponse>
where
    R: RepositoryProvider,
{
    let (user, session) = state
        .torii
        .verify_magic_token(
            &payload.token,
            connection_info.user_agent,
            connection_info.ip,
        )
        .await?;

    let same_site = match cookie_config.same_site {
        CookieSameSite::Strict => SameSite::Strict,
        CookieSameSite::Lax => SameSite::Lax,
        CookieSameSite::None => SameSite::None,
    };

    let cookie = Cookie::build((cookie_config.name, session.token.to_string()))
        .path(cookie_config.path)
        .http_only(cookie_config.http_only)
        .secure(cookie_config.secure)
        .same_site(same_site);

    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie.to_string())],
        Json(AuthResponse { user, session }),
    ))
}
