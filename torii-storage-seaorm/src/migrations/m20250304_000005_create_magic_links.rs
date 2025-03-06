use sea_orm::{DbErr, DeriveMigrationName, prelude::*, sea_query::Table};
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

        // TODO: Add indexes

        Ok(())
    }
}
