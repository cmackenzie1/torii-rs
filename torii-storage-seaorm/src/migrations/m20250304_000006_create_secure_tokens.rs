use sea_orm_migration::prelude::*;

use super::{SecureTokens, Users};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SecureTokens::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SecureTokens::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(SecureTokens::UserId).string().not_null())
                    .col(
                        ColumnDef::new(SecureTokens::Token)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(SecureTokens::Purpose).string().not_null())
                    .col(ColumnDef::new(SecureTokens::UsedAt).timestamp_with_time_zone())
                    .col(
                        ColumnDef::new(SecureTokens::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SecureTokens::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SecureTokens::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-secure-token-user-id")
                            .from(SecureTokens::Table, SecureTokens::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on token for faster lookups
        manager
            .create_index(
                Index::create()
                    .name("idx-secure-tokens-token")
                    .table(SecureTokens::Table)
                    .col(SecureTokens::Token)
                    .to_owned(),
            )
            .await?;

        // Create index on purpose and expires_at for efficient cleanup
        manager
            .create_index(
                Index::create()
                    .name("idx-secure-tokens-purpose-expires")
                    .table(SecureTokens::Table)
                    .col(SecureTokens::Purpose)
                    .col(SecureTokens::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SecureTokens::Table).to_owned())
            .await
    }
}
