ToriiBuilder::new()
    .with_sqlite("sqlite::memory:")
    .await?
    .apply_migrations(true)
    .build()
    .await?