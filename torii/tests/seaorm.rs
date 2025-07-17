//! SeaORM integration tests

#[cfg(feature = "seaorm")]
mod tests {
    use std::sync::Arc;
    use torii::{Torii, seaorm::SeaORMStorage};
    use torii_core::repositories::RepositoryProvider;

    #[tokio::test]
    async fn test_seaorm_storage_connection() {
        let storage = SeaORMStorage::connect("sqlite::memory:")
            .await
            .expect("Failed to connect to SeaORM storage");

        storage.migrate().await.expect("Failed to run migrations");
    }

    #[tokio::test]
    async fn test_seaorm_repository_provider_with_torii() {
        let storage = SeaORMStorage::connect("sqlite::memory:")
            .await
            .expect("Failed to connect to SeaORM storage");

        storage.migrate().await.expect("Failed to run migrations");

        let repositories = Arc::new(storage.into_repository_provider());

        // Test migration (should be a no-op since we already migrated)
        repositories.migrate().await.expect("Migration failed");

        // Test health check
        repositories
            .health_check()
            .await
            .expect("Health check failed");

        let torii = Torii::new(repositories);

        // Test basic health check through Torii
        torii.health_check().await.expect("Health check failed");
    }
}
