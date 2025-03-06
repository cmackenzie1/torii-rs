use sea_orm::{
    DbErr, DeriveMigrationName,
    prelude::*,
    sea_query::{Index, Table},
};
use sea_orm_migration::{
    MigrationTrait, SchemaManager,
    schema::{pk_auto, string, timestamp, timestamp_null},
};

use super::MagicLinks;

#[derive(DeriveMigrationName)]
pub struct CreateMagicLinks;

#[async_trait::async_trait]
impl MigrationTrait for CreateMagicLinks {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(MagicLinks::Table)
                    .if_not_exists()
                    .col(pk_auto(MagicLinks::Id))
                    .col(string(MagicLinks::UserId))
                    .col(string(MagicLinks::Token))
                    .col(timestamp_null(MagicLinks::UsedAt))
                    .col(timestamp(MagicLinks::ExpiresAt))
                    .col(timestamp(MagicLinks::CreatedAt).default(Expr::current_timestamp()))
                    .col(timestamp(MagicLinks::UpdatedAt).default(Expr::current_timestamp()))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(MagicLinks::Table)
                    .name("idx_magic_links_user_id")
                    .col(MagicLinks::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(MagicLinks::Table)
                    .name("idx_magic_links_token")
                    .col(MagicLinks::Token)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(MagicLinks::Table)
                    .name("idx_magic_links_expires_at")
                    .col(MagicLinks::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
