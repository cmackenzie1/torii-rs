use sea_orm::{DbErr, DeriveMigrationName, prelude::*, sea_query::Table};
use sea_orm_migration::{
    MigrationTrait, SchemaManager,
    schema::{pk_uuid, string, timestamp},
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
                    .col(pk_uuid(MagicLinks::Id).not_null())
                    .col(string(MagicLinks::UserId).not_null())
                    .col(string(MagicLinks::Token).not_null())
                    .col(string(MagicLinks::UsedAt).not_null())
                    .col(string(MagicLinks::ExpiresAt).not_null())
                    .col(
                        timestamp(MagicLinks::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(MagicLinks::UpdatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // TODO: Add indexes

        Ok(())
    }
}
