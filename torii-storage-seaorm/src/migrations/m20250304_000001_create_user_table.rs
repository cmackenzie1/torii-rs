use sea_orm::{
    DbErr, DeriveMigrationName,
    prelude::*,
    sea_query::{Index, Table},
};
use sea_orm_migration::{
    MigrationTrait, SchemaManager,
    schema::{string, string_null, timestamp, timestamp_null},
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
                    .col(string(Users::Id).primary_key())
                    .col(string(Users::Email))
                    .col(string_null(Users::Name)) // Nullable since users may not have a name yet...
                    .col(string_null(Users::PasswordHash)) // Nullable since users may not have a password (i.e. OAuth, Passkey, Magic Link)
                    .col(timestamp_null(Users::EmailVerifiedAt))
                    .col(timestamp(Users::CreatedAt).default(Expr::current_timestamp()))
                    .col(timestamp(Users::UpdatedAt).default(Expr::current_timestamp()))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Users::Table)
                    .name("idx_users_email")
                    .col(Users::Email)
                    .unique()
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
