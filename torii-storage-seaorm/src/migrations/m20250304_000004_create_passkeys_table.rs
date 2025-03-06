use sea_orm::{DbErr, DeriveMigrationName, prelude::*, sea_query::Table};
use sea_orm_migration::{
    MigrationTrait, SchemaManager,
    schema::{pk_uuid, string, timestamp},
};

use super::{PasskeyChallenges, Passkeys};

#[derive(DeriveMigrationName)]
pub struct CreatePasskeys;

#[async_trait::async_trait]
impl MigrationTrait for CreatePasskeys {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Passkeys::Table)
                    .if_not_exists()
                    .col(pk_uuid(Passkeys::Id).not_null())
                    .col(string(Passkeys::UserId).not_null())
                    .col(string(Passkeys::CredentialId).not_null())
                    .col(string(Passkeys::DataJson).not_null())
                    .col(
                        timestamp(Passkeys::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(Passkeys::UpdatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(PasskeyChallenges::Table)
                    .if_not_exists()
                    .col(pk_uuid(PasskeyChallenges::Id).not_null())
                    .col(string(PasskeyChallenges::ChallengeId).not_null())
                    .col(string(PasskeyChallenges::Challenge).not_null())
                    .col(
                        timestamp(PasskeyChallenges::ExpiresAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(PasskeyChallenges::CreatedAt)
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        timestamp(PasskeyChallenges::UpdatedAt)
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
