use sea_orm::{DbErr, DeriveMigrationName, prelude::*, sea_query::Table};
use sea_orm_migration::{
    MigrationTrait, SchemaManager,
    schema::{pk_uuid, string, timestamp},
};

use super::Users;

#[derive(DeriveMigrationName)]
pub struct CreateUsers;

#[async_trait::async_trait]
impl MigrationTrait for CreateUsers {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(pk_uuid(Users::Id).not_null())
                    .col(string(Users::Email).not_null())
                    .col(string(Users::Name).not_null())
                    .col(timestamp(Users::EmailVerifiedAt).timestamp())
                    .col(
                        timestamp(Users::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(Users::UpdatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
