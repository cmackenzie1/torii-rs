use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SecureToken::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SecureToken::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(SecureToken::UserId).string().not_null())
                    .col(
                        ColumnDef::new(SecureToken::Token)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(SecureToken::Purpose).string().not_null())
                    .col(ColumnDef::new(SecureToken::UsedAt).timestamp_with_time_zone())
                    .col(
                        ColumnDef::new(SecureToken::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SecureToken::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SecureToken::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-secure-token-user-id")
                            .from(SecureToken::Table, SecureToken::UserId)
                            .to(User::Table, User::Id)
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
                    .table(SecureToken::Table)
                    .col(SecureToken::Token)
                    .to_owned(),
            )
            .await?;

        // Create index on purpose and expires_at for efficient cleanup
        manager
            .create_index(
                Index::create()
                    .name("idx-secure-tokens-purpose-expires")
                    .table(SecureToken::Table)
                    .col(SecureToken::Purpose)
                    .col(SecureToken::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SecureToken::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum SecureToken {
    Table,
    Id,
    UserId,
    Token,
    Purpose,
    UsedAt,
    ExpiresAt,
    CreatedAt,
    UpdatedAt,
}

// Reference the existing User table
#[derive(DeriveIden)]
enum User {
    Table,
    Id,
}
