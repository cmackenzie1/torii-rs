use std::any::TypeId;

use async_trait::async_trait;
use migrations::CreateOidcTables;
use sqlx::{Pool, Sqlite};
use torii_core::{migration::PluginMigration, plugin::CreateUserParams, Error, Plugin, User};

mod migrations;

pub struct OIDCPlugin;

impl Default for OIDCPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl OIDCPlugin {
    pub fn new() -> Self {
        Self {}
    }

    async fn authenticate(
        &self,
        _pool: &Pool<Sqlite>,
        _provider: &str,
        _id_token: &str,
    ) -> Result<User, Error> {
        Err(Error::UnsupportedAuthMethod(self.name().to_string()))
    }

    async fn create_user(
        &self,
        _pool: &Pool<Sqlite>,
        _params: &CreateUserParams,
    ) -> Result<User, Error> {
        Err(Error::UnsupportedAuthMethod(self.name().to_string()))
    }
}

#[async_trait]
impl Plugin for OIDCPlugin {
    fn id(&self) -> TypeId {
        TypeId::of::<OIDCPlugin>()
    }

    fn name(&self) -> &'static str {
        "oidc"
    }

    async fn setup(&self, _pool: &Pool<Sqlite>) -> Result<(), Error> {
        Ok(())
    }

    fn migrations(&self) -> Vec<Box<dyn PluginMigration>> {
        vec![Box::new(CreateOidcTables)]
    }
}
