use std::net::SocketAddr;

use axum::{
    Extension, RequestPartsExt,
    extract::{ConnectInfo, FromRequestParts},
    http::{StatusCode, request::Parts},
};
use axum_extra::{TypedHeader, extract::CookieJar, headers::UserAgent};
use torii::{SessionToken, User};

use crate::{error::AuthError, types::ConnectionInfo};

impl<S> FromRequestParts<S> for ConnectionInfo
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let user_agent = parts
            .extract::<Option<TypedHeader<UserAgent>>>()
            .await
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid user agent header"))?
            .map(|ua| ua.to_string());

        let ip = parts
            .extract::<ConnectInfo<SocketAddr>>()
            .await
            .ok()
            .map(|addr| addr.ip().to_string());

        Ok(ConnectionInfo { ip, user_agent })
    }
}

pub struct AuthUser(pub User);

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Extension(user): Extension<User> =
            parts.extract().await.map_err(|_| AuthError::Unauthorized)?;

        Ok(AuthUser(user))
    }
}

pub struct OptionalAuthUser(pub Option<User>);

impl<S> FromRequestParts<S> for OptionalAuthUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let user = parts.extensions.get::<User>().cloned();

        Ok(OptionalAuthUser(user))
    }
}

pub struct SessionTokenFromCookie(pub Option<SessionToken>);

impl<S> FromRequestParts<S> for SessionTokenFromCookie
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let jar = parts
            .extract::<CookieJar>()
            .await
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid cookie header"))?;

        let session_token = jar
            .get("session_id")
            .and_then(|cookie| cookie.value().parse::<String>().ok())
            .map(|token| SessionToken::new(&token));

        Ok(SessionTokenFromCookie(session_token))
    }
}

pub struct SessionTokenFromBearer(pub Option<SessionToken>);

impl<S> FromRequestParts<S> for SessionTokenFromBearer
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let session_token = parts
            .headers
            .get("Authorization")
            .and_then(|header| header.to_str().ok())
            .and_then(|header| header.strip_prefix("Bearer "))
            .map(SessionToken::new);

        Ok(SessionTokenFromBearer(session_token))
    }
}

pub struct SessionTokenFromRequest(pub Option<SessionToken>);

impl<S> FromRequestParts<S> for SessionTokenFromRequest
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Try Bearer token first, then fall back to cookie
        if let Some(token) = parts
            .headers
            .get("Authorization")
            .and_then(|header| header.to_str().ok())
            .and_then(|header| header.strip_prefix("Bearer "))
        {
            return Ok(SessionTokenFromRequest(Some(SessionToken::new(token))));
        }

        // Fall back to cookie
        let jar = parts
            .extract::<CookieJar>()
            .await
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid cookie header"))?;

        let session_token = jar
            .get("session_id")
            .and_then(|cookie| cookie.value().parse::<String>().ok())
            .map(|token| SessionToken::new(&token));

        Ok(SessionTokenFromRequest(session_token))
    }
}
