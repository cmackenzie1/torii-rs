use m20250304_000001_create_user_table::CreateUsers;
use m20250304_000002_create_session_table::CreateSessions;

use sea_orm::{
    DeriveIden,
    sea_query::{Alias, IntoIden},
};
use sea_orm_migration::{MigrationTrait, MigratorTrait};

mod m20250304_000001_create_user_table;
mod m20250304_000002_create_session_table;

#[allow(dead_code)]
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    // Override the name of migration table
    fn migration_table_name() -> sea_orm::DynIden {
        Alias::new("torii_migrations").into_iden()
    }

    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(CreateUsers), Box::new(CreateSessions)]
    }
}

#[derive(DeriveIden)]
pub enum Users {
    Table,
    Id,
    Email,
    Name,
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
