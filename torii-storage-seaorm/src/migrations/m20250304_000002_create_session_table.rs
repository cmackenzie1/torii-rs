use sea_orm::{DbErr, DeriveMigrationName, prelude::*, sea_query::Table};
use sea_orm_migration::{
    MigrationTrait, SchemaManager,
    schema::{pk_uuid, string, timestamp},
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
                    .col(pk_uuid(Sessions::Id).not_null())
                    .col(string(Sessions::UserId).not_null())
                    .col(string(Sessions::Token).not_null())
                    .col(string(Sessions::IpAddress))
                    .col(string(Sessions::UserAgent))
                    .col(timestamp(Sessions::ExpiresAt).timestamp())
                    .col(
                        timestamp(Sessions::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(Sessions::UpdatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
