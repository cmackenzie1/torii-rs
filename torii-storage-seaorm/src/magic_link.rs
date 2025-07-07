use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};
use torii_core::{
    UserId,
    storage::{MagicLinkStorage, MagicToken},
};

use crate::entities::magic_link;

use crate::{SeaORMStorage, SeaORMStorageError};

impl From<magic_link::Model> for MagicToken {
    fn from(value: magic_link::Model) -> Self {
        MagicToken {
            user_id: UserId::new(&value.user_id),
            token: value.token,
            used_at: value.used_at,
            expires_at: value.expires_at,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

#[async_trait]
impl MagicLinkStorage for SeaORMStorage {
    async fn save_magic_token(&self, token: &MagicToken) -> Result<(), torii_core::Error> {
        let magic_link = magic_link::ActiveModel {
            user_id: Set(token.user_id.to_string()),
            token: Set(token.token.clone()),
            used_at: Set(token.used_at),
            expires_at: Set(token.expires_at),
            ..Default::default()
        };
        magic_link
            .insert(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(())
    }

    async fn get_magic_token(&self, token: &str) -> Result<Option<MagicToken>, torii_core::Error> {
        let magic_link = magic_link::Entity::find()
            .filter(magic_link::Column::Token.eq(token))
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(magic_link.map(|model| model.into()))
    }

    async fn set_magic_token_used(&self, token: &str) -> Result<(), torii_core::Error> {
        let magic_link: Option<magic_link::ActiveModel> = magic_link::Entity::find()
            .filter(magic_link::Column::Token.eq(token))
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?
            .map(|model| model.into());

        if let Some(mut magic_link) = magic_link {
            magic_link.used_at = Set(Some(Utc::now()));
            magic_link
                .update(&self.pool)
                .await
                .map_err(SeaORMStorageError::Database)?;
        }

        Ok(())
    }
}
