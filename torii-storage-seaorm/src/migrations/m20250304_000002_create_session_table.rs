use sea_orm::{DbErr, DeriveMigrationName, prelude::*, sea_query::Table};
use sea_orm_migration::{
    MigrationTrait, SchemaManager,
    schema::{pk_auto, string, string_null, timestamp},
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
                    .col(pk_auto(Sessions::Id))
                    .col(string(Sessions::UserId))
                    .col(string(Sessions::Token))
                    .col(string_null(Sessions::IpAddress))
                    .col(string_null(Sessions::UserAgent))
                    .col(timestamp(Sessions::ExpiresAt))
                    .col(timestamp(Sessions::CreatedAt).default(Expr::current_timestamp()))
                    .col(timestamp(Sessions::UpdatedAt).default(Expr::current_timestamp()))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
