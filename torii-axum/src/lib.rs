//! # Torii Axum Integration
//!
//! This crate provides Axum routes and middleware for the Torii authentication framework.
//! It offers a simple way to add authentication to your Axum application with support for
//! multiple authentication methods.
//!
//! ## Features
//!
//! - **Core Authentication**: Session management, user info, health checks
//! - **Password Authentication** (feature = "password"): Registration, login, password changes
//! - **Magic Link Authentication** (feature = "magic-link"): Passwordless email authentication
//! - **OAuth** (feature = "oauth"): Coming soon
//! - **Passkey** (feature = "passkey"): Coming soon
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use axum::{Router, routing::get};
//! use torii::{Torii, SeaORMRepositoryProvider};
//! use torii_axum::{routes, require_auth, CookieConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Set up Torii with your storage backend
//!     let repositories = Arc::new(SeaORMRepositoryProvider::new(pool));
//!     let torii = Arc::new(Torii::new(repositories));
//!
//!     // Create auth routes with custom cookie configuration
//!     let auth_routes = routes(torii.clone())
//!         .with_cookie_config(CookieConfig::development());
//!
//!     // Create your application router
//!     let app = Router::new()
//!         .nest("/auth", auth_routes)
//!         .route("/protected", get(protected_handler))
//!         .layer(require_auth(torii));
//!
//!     // Run your server
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     axum::serve(listener, app).await.unwrap();
//! }
//!
//! async fn protected_handler() -> &'static str {
//!     "This route requires authentication!"
//! }
//! ```

mod error;
mod extractors;
mod middleware;
mod routes;
mod types;

pub use error::{AuthError, Result};
pub use extractors::{
    AuthUser, OptionalAuthUser, SessionTokenFromBearer, SessionTokenFromCookie,
    SessionTokenFromRequest,
};
pub use middleware::{AuthState, auth_middleware, require_auth};
pub use routes::create_router;
pub use types::{
    AuthResponse, ChangePasswordRequest, ConnectionInfo, CookieConfig, CookieSameSite,
    HealthResponse, LoginRequest, MagicLinkRequest, MagicLinkResponse, MessageResponse,
    PasswordResetRequest, PasswordResetResponse, RegisterRequest, ResetPasswordRequest,
    SessionResponse, UserResponse, VerifyMagicTokenRequest, VerifyResetTokenRequest,
    VerifyResetTokenResponse,
};

use axum::Router;
use std::sync::Arc;
use torii::Torii;
use torii_core::RepositoryProvider;

/// Create authentication routes for your Axum application.
///
/// This function creates a router with all available authentication endpoints
/// based on the features enabled in your Cargo.toml.
///
/// # Arguments
///
/// * `torii` - An Arc-wrapped Torii instance configured with your storage backend
///
/// # Returns
///
/// A Router that can be nested into your application at any path (e.g., "/auth")
///
/// # Example
///
/// ```rust,no_run
/// let auth_routes = torii_axum::routes(torii);
/// let app = Router::new().nest("/auth", auth_routes);
/// ```
pub fn routes<R>(torii: Arc<Torii<R>>) -> AuthRouterBuilder<R>
where
    R: RepositoryProvider + 'static,
{
    AuthRouterBuilder {
        torii,
        cookie_config: CookieConfig::default(),
    }
}

/// Builder for configuring authentication routes
pub struct AuthRouterBuilder<R: RepositoryProvider> {
    torii: Arc<Torii<R>>,
    cookie_config: CookieConfig,
}

impl<R: RepositoryProvider + 'static> AuthRouterBuilder<R> {
    /// Set custom cookie configuration
    pub fn with_cookie_config(mut self, config: CookieConfig) -> Self {
        self.cookie_config = config;
        self
    }

    /// Build the router with the configured options
    pub fn build(self) -> Router {
        create_router(self.torii, self.cookie_config)
    }
}

impl<R: RepositoryProvider + 'static> From<AuthRouterBuilder<R>> for Router {
    fn from(builder: AuthRouterBuilder<R>) -> Self {
        builder.build()
    }
}
