mod migrations;

use std::{any::Any, sync::LazyLock};

use async_trait::async_trait;
use migrations::CreateOidcTables;
use sqlx::{Pool, Sqlite};
use torii_core::{
    migration::PluginMigration, plugin::CreateUserParams, Error, Plugin, PluginId, User,
};

pub static PLUGIN_ID: LazyLock<PluginId> = LazyLock::new(|| PluginId::new("oidc"));
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
    fn id(&self) -> PluginId {
        PluginId::new("oidc")
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

    fn as_any(&self) -> &dyn Any {
        self
    }
}
