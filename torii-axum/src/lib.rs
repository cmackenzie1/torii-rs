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
//! use torii_axum::{routes, HasTorii, auth_middleware, CookieConfig};
//!
//! // Define your application state with a torii field
//! #[derive(Clone)]
//! struct AppState {
//!     torii: Arc<Torii<SeaORMRepositoryProvider>>,
//!     // Add other state fields as needed
//!     // database: Arc<sqlx::PgPool>,
//! }
//!
//! // Implement HasTorii for your state
//! impl HasTorii<SeaORMRepositoryProvider> for AppState {
//!     fn torii(&self) -> &Arc<Torii<SeaORMRepositoryProvider>> {
//!         &self.torii
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     // Set up Torii with your storage backend
//!     let repositories = Arc::new(SeaORMRepositoryProvider::new(pool));
//!     let torii = Arc::new(Torii::new(repositories));
//!
//!     // Create your application state
//!     let state = AppState { torii: torii.clone() };
//!
//!     // Create auth routes with custom cookie configuration
//!     let auth_routes = routes(torii)
//!         .with_cookie_config(CookieConfig::development())
//!         .build();
//!
//!     // Create your application router
//!     let app = Router::new()
//!         .nest("/auth", auth_routes)
//!         .route("/protected", get(protected_handler))
//!         .with_state(state.clone())
//!         .layer(axum::middleware::from_fn_with_state(
//!             state,
//!             auth_middleware::<AppState, SeaORMRepositoryProvider>
//!         ));
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
pub use middleware::{HasTorii, auth_middleware, require_auth};
pub use routes::create_router;
pub use types::{
    AuthResponse, ChangePasswordRequest, ConnectionInfo, CookieConfig, CookieSameSite,
    HealthResponse, LinkConfig, LoginRequest, MagicLinkRequest, MagicLinkResponse, MessageResponse,
    PasswordResetRequest, PasswordResetResponse, RegisterRequest, ResetPasswordRequest,
    SessionResponse, UserResponse, VerifyMagicTokenRequest, VerifyResetTokenResponse,
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
        link_config: None,
    }
}

/// Builder for configuring authentication routes
pub struct AuthRouterBuilder<R: RepositoryProvider> {
    torii: Arc<Torii<R>>,
    cookie_config: CookieConfig,
    link_config: Option<LinkConfig>,
}

impl<R: RepositoryProvider + 'static> AuthRouterBuilder<R> {
    /// Set custom cookie configuration
    pub fn with_cookie_config(mut self, config: CookieConfig) -> Self {
        self.cookie_config = config;
        self
    }

    /// Set link configuration for email verification URLs.
    ///
    /// This is required when the `magic-link` or `password` features are enabled.
    /// The configuration specifies the hostname and path prefix used to construct
    /// verification URLs sent in emails.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use torii_axum::{routes, LinkConfig};
    ///
    /// let auth_routes = routes(torii)
    ///     .with_link_config(LinkConfig::new("https://example.com"))
    ///     .build();
    /// ```
    pub fn with_link_config(mut self, config: LinkConfig) -> Self {
        self.link_config = Some(config);
        self
    }

    /// Build the router with the configured options.
    ///
    /// # Panics
    ///
    /// Panics if `magic-link` or `password` features are enabled but `LinkConfig`
    /// is not provided via `with_link_config()`.
    pub fn build(self) -> Router {
        #[cfg(any(feature = "magic-link", feature = "password"))]
        if self.link_config.is_none() {
            panic!(
                "LinkConfig is required when magic-link or password features are enabled. \
                 Use .with_link_config(LinkConfig::new(\"https://example.com\"))"
            );
        }

        create_router(self.torii, self.cookie_config, self.link_config)
    }
}

impl<R: RepositoryProvider + 'static> From<AuthRouterBuilder<R>> for Router {
    fn from(builder: AuthRouterBuilder<R>) -> Self {
        builder.build()
    }
}
