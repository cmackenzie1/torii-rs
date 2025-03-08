use sea_orm::{
    DbErr, DeriveMigrationName,
    prelude::*,
    sea_query::{Index, Table},
};
use sea_orm_migration::{
    MigrationTrait, SchemaManager,
    schema::{pk_auto, string, string_null, timestamp_with_time_zone},
};

use super::Sessions;

#[derive(DeriveMigrationName)]
pub struct CreateSessions;

#[async_trait::async_trait]
impl MigrationTrait for CreateSessions {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Sessions::Table)
                    .if_not_exists()
                    .col(pk_auto(Sessions::Id).big_integer())
                    .col(string(Sessions::UserId))
                    .col(string(Sessions::Token))
                    .col(string_null(Sessions::IpAddress))
                    .col(string_null(Sessions::UserAgent))
                    .col(timestamp_with_time_zone(Sessions::ExpiresAt))
                    .col(
                        timestamp_with_time_zone(Sessions::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp_with_time_zone(Sessions::UpdatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Sessions::Table)
                    .name("idx_sessions_token")
                    .col(Sessions::Token)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Sessions::Table)
                    .name("idx_sessions_user_id")
                    .col(Sessions::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Sessions::Table)
                    .name("idx_sessions_expires_at")
                    .col(Sessions::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Sessions::Table)
                    .name("idx_sessions_created_at")
                    .col(Sessions::CreatedAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Sessions::Table)
                    .name("idx_sessions_updated_at")
                    .col(Sessions::UpdatedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
