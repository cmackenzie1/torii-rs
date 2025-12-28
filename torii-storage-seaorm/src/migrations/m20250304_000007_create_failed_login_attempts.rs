//! Migration to create failed_login_attempts table for brute force protection.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create failed_login_attempts table
        manager
            .create_table(
                Table::create()
                    .table(FailedLoginAttempts::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(FailedLoginAttempts::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(FailedLoginAttempts::Email)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(FailedLoginAttempts::IpAddress).string())
                    .col(
                        ColumnDef::new(FailedLoginAttempts::AttemptedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index for counting attempts by email within a time window
        manager
            .create_index(
                Index::create()
                    .name("idx_failed_login_attempts_email_time")
                    .table(FailedLoginAttempts::Table)
                    .col(FailedLoginAttempts::Email)
                    .col(FailedLoginAttempts::AttemptedAt)
                    .to_owned(),
            )
            .await?;

        // Create index for cleanup of old records
        manager
            .create_index(
                Index::create()
                    .name("idx_failed_login_attempts_attempted_at")
                    .table(FailedLoginAttempts::Table)
                    .col(FailedLoginAttempts::AttemptedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(FailedLoginAttempts::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum FailedLoginAttempts {
    Table,
    Id,
    Email,
    IpAddress,
    AttemptedAt,
}
