use sea_orm::{DbErr, DeriveMigrationName, prelude::*, sea_query::Table};
use sea_orm_migration::{
    MigrationTrait, SchemaManager,
    schema::{pk_auto, string, timestamp},
};

use super::OauthAccounts;
use super::PkceVerifiers;
#[derive(DeriveMigrationName)]
pub struct CreateOAuthAccounts;

#[async_trait::async_trait]
impl MigrationTrait for CreateOAuthAccounts {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(OauthAccounts::Table)
                    .if_not_exists()
                    .col(pk_auto(OauthAccounts::Id))
                    .col(string(OauthAccounts::UserId))
                    .col(string(OauthAccounts::Provider))
                    .col(string(OauthAccounts::Subject))
                    .col(timestamp(OauthAccounts::CreatedAt).default(Expr::current_timestamp()))
                    .col(timestamp(OauthAccounts::UpdatedAt).default(Expr::current_timestamp()))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(PkceVerifiers::Table)
                    .if_not_exists()
                    .col(pk_auto(PkceVerifiers::Id))
                    .col(string(PkceVerifiers::CsrfState))
                    .col(string(PkceVerifiers::Verifier))
                    .col(timestamp(PkceVerifiers::ExpiresAt).default(Expr::current_timestamp()))
                    .col(timestamp(PkceVerifiers::CreatedAt).default(Expr::current_timestamp()))
                    .col(timestamp(PkceVerifiers::UpdatedAt).default(Expr::current_timestamp()))
                    .to_owned(),
            )
            .await?;

        // TODO: Add indexes

        Ok(())
    }
}
