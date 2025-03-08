use sea_orm::{
    DbErr, DeriveMigrationName,
    prelude::*,
    sea_query::{Index, Table},
};
use sea_orm_migration::{
    MigrationTrait, SchemaManager,
    schema::{pk_auto, string, timestamp},
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
                    .col(pk_auto(Passkeys::Id).big_integer())
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
            .create_index(
                Index::create()
                    .table(Passkeys::Table)
                    .name("idx_passkeys_user_id")
                    .col(Passkeys::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Passkeys::Table)
                    .name("idx_passkeys_credential_id")
                    .col(Passkeys::CredentialId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(PasskeyChallenges::Table)
                    .if_not_exists()
                    .col(pk_auto(PasskeyChallenges::Id).big_integer())
                    .col(string(PasskeyChallenges::ChallengeId))
                    .col(string(PasskeyChallenges::Challenge))
                    .col(timestamp(PasskeyChallenges::ExpiresAt).default(Expr::current_timestamp()))
                    .col(timestamp(PasskeyChallenges::CreatedAt).default(Expr::current_timestamp()))
                    .col(timestamp(PasskeyChallenges::UpdatedAt).default(Expr::current_timestamp()))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(PasskeyChallenges::Table)
                    .name("idx_passkey_challenges_challenge_id")
                    .col(PasskeyChallenges::ChallengeId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(PasskeyChallenges::Table)
                    .name("idx_passkey_challenges_expires_at")
                    .col(PasskeyChallenges::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
