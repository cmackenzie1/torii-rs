use m20250304_000001_create_user_table::CreateUsers;
use m20250304_000002_create_session_table::CreateSessions;

use m20250304_000003_create_oauth_table::CreateOAuthAccounts;
use sea_orm::{
    DeriveIden,
    sea_query::{Alias, IntoIden},
};
use sea_orm_migration::{MigrationTrait, MigratorTrait};

mod m20250304_000001_create_user_table;
mod m20250304_000002_create_session_table;
mod m20250304_000003_create_oauth_table;
mod m20250304_000004_create_passkeys_table;
mod m20250304_000005_create_magic_links;

#[allow(dead_code)]
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    // Override the name of migration table
    fn migration_table_name() -> sea_orm::DynIden {
        Alias::new("torii_migrations").into_iden()
    }

    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(CreateUsers),
            Box::new(CreateSessions),
            Box::new(CreateOAuthAccounts),
        ]
    }
}

#[derive(DeriveIden)]
pub enum Users {
    Table,
    Id,
    Email,
    Name,
    PasswordHash,
    EmailVerifiedAt,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum Sessions {
    Table,
    Id,
    UserId,
    Token,
    IpAddress,
    UserAgent,
    ExpiresAt,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum OauthAccounts {
    Table,
    Id,
    UserId,
    Provider,
    Subject,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum PkceVerifiers {
    Table,
    Id,
    CsrfState,
    Verifier,
    ExpiresAt,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum Passkeys {
    Table,
    Id,
    UserId,
    CredentialId,
    DataJson,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum PasskeyChallenges {
    Table,
    Id,
    ChallengeId,
    Challenge,
    ExpiresAt,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum MagicLinks {
    Table,
    Id,
    UserId,
    Token,
    UsedAt,
    ExpiresAt,
    CreatedAt,
    UpdatedAt,
}
