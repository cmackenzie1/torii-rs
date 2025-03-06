use sea_orm::{DbErr, DeriveMigrationName, prelude::*, sea_query::Table};
use sea_orm_migration::{
    MigrationTrait, SchemaManager,
    schema::{pk_uuid, string, timestamp},
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
                    .col(pk_uuid(OauthAccounts::Id).not_null())
                    .col(string(OauthAccounts::UserId).not_null())
                    .col(string(OauthAccounts::Provider).not_null())
                    .col(string(OauthAccounts::Subject).not_null())
                    .col(
                        timestamp(OauthAccounts::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(OauthAccounts::UpdatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(PkceVerifiers::Table)
                    .if_not_exists()
                    .col(pk_uuid(PkceVerifiers::Id).not_null())
                    .col(string(PkceVerifiers::CsrfState).not_null())
                    .col(string(PkceVerifiers::Verifier).not_null())
                    .col(
                        timestamp(PkceVerifiers::ExpiresAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(PkceVerifiers::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(PkceVerifiers::UpdatedAt)
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
