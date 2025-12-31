//! Builder pattern for constructing Torii instances
//!
//! This module provides a type-safe builder for creating [`Torii`] instances with
//! compile-time validation of storage configuration.
//!
//! # Example
//!
//! ```rust,no_run
//! use torii::ToriiBuilder;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Build with SQLite and auto-migration
//!     let torii = ToriiBuilder::new()
//!         .with_sqlite("sqlite::memory:")
//!         .await?
//!         .apply_migrations(true)
//!         .build()
//!         .await?;
//!
//!     // Or build without auto-migration and run manually
//!     let torii = ToriiBuilder::new()
//!         .with_sqlite("sqlite::memory:")
//!         .await?
//!         .build()
//!         .await?;
//!     torii.migrate().await?;
//!
//!     Ok(())
//! }
//! ```

use std::sync::Arc;

use chrono::Duration;
use torii_core::{BruteForceProtectionConfig, RepositoryProvider};

use crate::{JwtConfig, SessionConfig, SessionProviderType, Torii};

#[cfg(feature = "mailer")]
use crate::MailerConfig;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur when building a Torii instance.
#[derive(Debug, thiserror::Error)]
pub enum ToriiBuilderError {
    /// Failed to connect to storage backend
    #[error("Storage connection failed: {0}")]
    StorageConnection(String),

    /// Failed to run database migrations
    #[error("Migration failed: {0}")]
    Migration(String),

    /// Invalid configuration provided
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// Failed to configure mailer
    #[cfg(feature = "mailer")]
    #[error("Mailer configuration failed: {0}")]
    MailerConfiguration(String),
}

// ============================================================================
// Type-State Markers
// ============================================================================

/// Marker type indicating no storage has been configured yet.
///
/// This is the initial state of [`ToriiBuilder`].
pub struct NoStorage;

/// Marker type indicating storage has been configured.
///
/// Contains the repository provider that will be used by Torii.
pub struct WithStorage<R: RepositoryProvider> {
    repositories: Arc<R>,
}

// ============================================================================
// Builder Implementation
// ============================================================================

/// A type-safe builder for constructing [`Torii`] instances.
///
/// The builder uses a type-state pattern to ensure that storage is configured
/// before building. This provides compile-time guarantees that the builder
/// is used correctly.
///
/// # Type States
///
/// - [`NoStorage`]: Initial state, storage must be configured
/// - [`WithStorage<R>`]: Storage configured, ready to build or add more configuration
///
/// # Example
///
/// ```rust,no_run
/// use torii::ToriiBuilder;
/// use chrono::Duration;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let torii = ToriiBuilder::new()
///         .with_sqlite("sqlite::memory:")
///         .await?
///         .with_session_expiry(Duration::days(7))
///         .apply_migrations(true)
///         .build()
///         .await?;
///
///     Ok(())
/// }
/// ```
pub struct ToriiBuilder<Storage> {
    storage: Storage,
    session_config: SessionConfig,
    brute_force_config: BruteForceProtectionConfig,
    apply_migrations: bool,
    #[cfg(feature = "mailer")]
    mailer_config: Option<MailerConfig>,
    // PhantomData not needed since we store Storage directly
}

impl Default for ToriiBuilder<NoStorage> {
    fn default() -> Self {
        Self::new()
    }
}

impl ToriiBuilder<NoStorage> {
    /// Create a new builder with default configuration.
    ///
    /// # Defaults
    ///
    /// - Session provider: Opaque (database-backed)
    /// - Session expiry: 30 days
    /// - Brute force protection: Enabled (5 attempts, 15 min lockout)
    /// - Apply migrations: false
    /// - Mailer: None
    pub fn new() -> Self {
        Self {
            storage: NoStorage,
            session_config: SessionConfig::default(),
            brute_force_config: BruteForceProtectionConfig::default(),
            apply_migrations: false,
            #[cfg(feature = "mailer")]
            mailer_config: None,
        }
    }
}

// ============================================================================
// Storage Configuration Methods (NoStorage -> WithStorage)
// ============================================================================

#[cfg(feature = "sqlite")]
impl ToriiBuilder<NoStorage> {
    /// Configure SQLite storage by connecting to the given URL.
    ///
    /// This will establish a connection to the SQLite database at the given URL.
    ///
    /// # Arguments
    ///
    /// * `url` - SQLite connection URL (e.g., "sqlite::memory:" or "sqlite://path/to/db.sqlite")
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use torii::ToriiBuilder;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let torii = ToriiBuilder::new()
    ///     .with_sqlite("sqlite::memory:")
    ///     .await?
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn with_sqlite(
        self,
        url: &str,
    ) -> Result<ToriiBuilder<WithStorage<crate::sqlite::SqliteRepositoryProvider>>, ToriiBuilderError>
    {
        let storage = crate::sqlite::SqliteStorage::connect(url)
            .await
            .map_err(|e| ToriiBuilderError::StorageConnection(e.to_string()))?;

        let repositories = Arc::new(storage.into_repository_provider());

        Ok(ToriiBuilder {
            storage: WithStorage { repositories },
            session_config: self.session_config,
            brute_force_config: self.brute_force_config,
            apply_migrations: self.apply_migrations,
            #[cfg(feature = "mailer")]
            mailer_config: self.mailer_config,
        })
    }

    /// Configure SQLite storage with an existing connection pool.
    ///
    /// Use this when you already have a SQLite connection pool and want to
    /// share it with Torii.
    ///
    /// # Arguments
    ///
    /// * `pool` - An existing SQLite connection pool
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use torii::ToriiBuilder;
    /// use sqlx::SqlitePool;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let pool = SqlitePool::connect("sqlite::memory:").await?;
    ///
    /// let torii = ToriiBuilder::new()
    ///     .with_sqlite_pool(pool)
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_sqlite_pool(
        self,
        pool: sqlx::SqlitePool,
    ) -> ToriiBuilder<WithStorage<crate::sqlite::SqliteRepositoryProvider>> {
        let repositories = Arc::new(crate::sqlite::SqliteRepositoryProvider::new(pool));

        ToriiBuilder {
            storage: WithStorage { repositories },
            session_config: self.session_config,
            brute_force_config: self.brute_force_config,
            apply_migrations: self.apply_migrations,
            #[cfg(feature = "mailer")]
            mailer_config: self.mailer_config,
        }
    }
}

#[cfg(feature = "postgres")]
impl ToriiBuilder<NoStorage> {
    /// Configure PostgreSQL storage by connecting to the given URL.
    ///
    /// This will establish a connection to the PostgreSQL database at the given URL.
    ///
    /// # Arguments
    ///
    /// * `url` - PostgreSQL connection URL (e.g., "postgresql://user:pass@localhost/db")
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use torii::ToriiBuilder;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let torii = ToriiBuilder::new()
    ///     .with_postgres("postgresql://user:pass@localhost/myapp")
    ///     .await?
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn with_postgres(
        self,
        url: &str,
    ) -> Result<
        ToriiBuilder<WithStorage<crate::postgres::PostgresRepositoryProvider>>,
        ToriiBuilderError,
    > {
        let storage = crate::postgres::PostgresStorage::connect(url)
            .await
            .map_err(|e| ToriiBuilderError::StorageConnection(e.to_string()))?;

        let repositories = Arc::new(storage.into_repository_provider());

        Ok(ToriiBuilder {
            storage: WithStorage { repositories },
            session_config: self.session_config,
            brute_force_config: self.brute_force_config,
            apply_migrations: self.apply_migrations,
            #[cfg(feature = "mailer")]
            mailer_config: self.mailer_config,
        })
    }

    /// Configure PostgreSQL storage with an existing connection pool.
    ///
    /// Use this when you already have a PostgreSQL connection pool and want to
    /// share it with Torii.
    ///
    /// # Arguments
    ///
    /// * `pool` - An existing PostgreSQL connection pool
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use torii::ToriiBuilder;
    /// use sqlx::PgPool;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let pool = PgPool::connect("postgresql://user:pass@localhost/myapp").await?;
    ///
    /// let torii = ToriiBuilder::new()
    ///     .with_postgres_pool(pool)
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_postgres_pool(
        self,
        pool: sqlx::PgPool,
    ) -> ToriiBuilder<WithStorage<crate::postgres::PostgresRepositoryProvider>> {
        let repositories = Arc::new(crate::postgres::PostgresRepositoryProvider::new(pool));

        ToriiBuilder {
            storage: WithStorage { repositories },
            session_config: self.session_config,
            brute_force_config: self.brute_force_config,
            apply_migrations: self.apply_migrations,
            #[cfg(feature = "mailer")]
            mailer_config: self.mailer_config,
        }
    }
}

#[cfg(any(
    feature = "seaorm-sqlite",
    feature = "seaorm-postgres",
    feature = "seaorm-mysql",
    feature = "seaorm"
))]
impl ToriiBuilder<NoStorage> {
    /// Configure SeaORM storage by connecting to the given URL.
    ///
    /// SeaORM supports SQLite, PostgreSQL, and MySQL. The database type is
    /// automatically detected from the URL scheme.
    ///
    /// # Arguments
    ///
    /// * `url` - Database connection URL
    ///   - SQLite: "sqlite://path/to/db.sqlite" or "sqlite::memory:"
    ///   - PostgreSQL: "postgresql://user:pass@localhost/db"
    ///   - MySQL: "mysql://user:pass@localhost/db"
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use torii::ToriiBuilder;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let torii = ToriiBuilder::new()
    ///     .with_seaorm("sqlite::memory:")
    ///     .await?
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn with_seaorm(
        self,
        url: &str,
    ) -> Result<ToriiBuilder<WithStorage<crate::seaorm::SeaORMRepositoryProvider>>, ToriiBuilderError>
    {
        let storage = crate::seaorm::SeaORMStorage::connect(url)
            .await
            .map_err(|e| ToriiBuilderError::StorageConnection(e.to_string()))?;

        let repositories = Arc::new(storage.into_repository_provider());

        Ok(ToriiBuilder {
            storage: WithStorage { repositories },
            session_config: self.session_config,
            brute_force_config: self.brute_force_config,
            apply_migrations: self.apply_migrations,
            #[cfg(feature = "mailer")]
            mailer_config: self.mailer_config,
        })
    }

    /// Configure SeaORM storage with an existing database connection.
    ///
    /// Use this when you already have a SeaORM database connection and want to
    /// share it with Torii.
    ///
    /// # Arguments
    ///
    /// * `connection` - An existing SeaORM database connection
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use torii::ToriiBuilder;
    /// use sea_orm::Database;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let connection = Database::connect("sqlite::memory:").await?;
    ///
    /// let torii = ToriiBuilder::new()
    ///     .with_seaorm_connection(connection)
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_seaorm_connection(
        self,
        connection: sea_orm::DatabaseConnection,
    ) -> ToriiBuilder<WithStorage<crate::seaorm::SeaORMRepositoryProvider>> {
        let repositories = Arc::new(crate::seaorm::SeaORMRepositoryProvider::new(connection));

        ToriiBuilder {
            storage: WithStorage { repositories },
            session_config: self.session_config,
            brute_force_config: self.brute_force_config,
            apply_migrations: self.apply_migrations,
            #[cfg(feature = "mailer")]
            mailer_config: self.mailer_config,
        }
    }
}

// ============================================================================
// Configuration Methods (available after storage is configured)
// ============================================================================

impl<R: RepositoryProvider> ToriiBuilder<WithStorage<R>> {
    /// Set the session expiration duration.
    ///
    /// Default: 30 days
    ///
    /// # Arguments
    ///
    /// * `duration` - How long sessions should remain valid
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use torii::ToriiBuilder;
    /// use chrono::Duration;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let torii = ToriiBuilder::new()
    ///     .with_sqlite("sqlite::memory:")
    ///     .await?
    ///     .with_session_expiry(Duration::days(7))
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_session_expiry(mut self, duration: Duration) -> Self {
        self.session_config.expires_in = duration;
        self
    }

    /// Configure JWT-based sessions instead of opaque database sessions.
    ///
    /// JWT sessions are stateless and don't require database lookups for
    /// validation, but cannot be revoked immediately.
    ///
    /// Default: Opaque sessions (database-backed)
    ///
    /// # Arguments
    ///
    /// * `config` - JWT configuration including algorithm and keys
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use torii::{ToriiBuilder, JwtConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let jwt_config = JwtConfig::new_hs256(vec![0u8; 32])?;
    ///
    /// let torii = ToriiBuilder::new()
    ///     .with_sqlite("sqlite::memory:")
    ///     .await?
    ///     .with_jwt_sessions(jwt_config)
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_jwt_sessions(mut self, config: JwtConfig) -> Self {
        self.session_config.provider_type = SessionProviderType::Jwt(config);
        self
    }

    /// Configure brute force protection settings.
    ///
    /// Brute force protection limits the number of failed login attempts
    /// before temporarily locking an account.
    ///
    /// Default: Enabled with 5 attempts and 15 minute lockout
    ///
    /// # Arguments
    ///
    /// * `config` - Brute force protection configuration
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use torii::{ToriiBuilder, BruteForceProtectionConfig};
    /// use chrono::Duration;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let torii = ToriiBuilder::new()
    ///     .with_sqlite("sqlite::memory:")
    ///     .await?
    ///     .with_brute_force_protection(BruteForceProtectionConfig {
    ///         max_failed_attempts: 3,
    ///         lockout_period: Duration::minutes(30),
    ///         ..Default::default()
    ///     })
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_brute_force_protection(mut self, config: BruteForceProtectionConfig) -> Self {
        self.brute_force_config = config;
        self
    }

    /// Set whether to automatically apply database migrations during build.
    ///
    /// Default: false
    ///
    /// When set to `true`, migrations will be applied automatically when
    /// `build()` is called. When `false`, you must call `torii.migrate()`
    /// manually after building.
    ///
    /// # Arguments
    ///
    /// * `apply` - Whether to apply migrations automatically
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use torii::ToriiBuilder;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // With auto-migration
    /// let torii = ToriiBuilder::new()
    ///     .with_sqlite("sqlite::memory:")
    ///     .await?
    ///     .apply_migrations(true)
    ///     .build()
    ///     .await?;
    ///
    /// // Without auto-migration (default)
    /// let torii = ToriiBuilder::new()
    ///     .with_sqlite("sqlite::memory:")
    ///     .await?
    ///     .build()
    ///     .await?;
    /// torii.migrate().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn apply_migrations(mut self, apply: bool) -> Self {
        self.apply_migrations = apply;
        self
    }

    /// Configure the mailer service for sending authentication emails.
    ///
    /// The mailer is used for sending welcome emails, password reset emails,
    /// and magic link emails.
    ///
    /// # Arguments
    ///
    /// * `config` - Mailer configuration
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use torii::{ToriiBuilder, MailerConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let torii = ToriiBuilder::new()
    ///     .with_sqlite("sqlite::memory:")
    ///     .await?
    ///     .with_mailer(MailerConfig::default())
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "mailer")]
    pub fn with_mailer(mut self, config: MailerConfig) -> Self {
        self.mailer_config = Some(config);
        self
    }

    /// Configure the mailer service from environment variables.
    ///
    /// This reads mailer configuration from environment variables.
    /// See [`MailerConfig::from_env`] for details on required variables.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use torii::ToriiBuilder;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let torii = ToriiBuilder::new()
    ///     .with_sqlite("sqlite::memory:")
    ///     .await?
    ///     .with_mailer_from_env()?
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "mailer")]
    pub fn with_mailer_from_env(mut self) -> Result<Self, ToriiBuilderError> {
        let config = MailerConfig::from_env()
            .map_err(|e| ToriiBuilderError::MailerConfiguration(e.to_string()))?;
        self.mailer_config = Some(config);
        Ok(self)
    }

    /// Build the Torii instance.
    ///
    /// This finalizes the configuration and creates the Torii instance.
    /// If `apply_migrations(true)` was called, migrations will be applied
    /// before returning.
    ///
    /// # Returns
    ///
    /// Returns the configured Torii instance, or an error if migration fails.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use torii::ToriiBuilder;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let torii = ToriiBuilder::new()
    ///     .with_sqlite("sqlite::memory:")
    ///     .await?
    ///     .apply_migrations(true)
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn build(self) -> Result<Torii<R>, ToriiBuilderError> {
        // Run migrations if requested
        if self.apply_migrations {
            self.storage
                .repositories
                .migrate()
                .await
                .map_err(|e| ToriiBuilderError::Migration(e.to_string()))?;
        }

        // Build Torii using the internal constructor
        // This will return an error if mailer configuration is invalid
        let torii = Torii::from_builder(
            self.storage.repositories,
            self.session_config,
            self.brute_force_config,
            #[cfg(feature = "mailer")]
            self.mailer_config,
        )?;

        Ok(torii)
    }
}
