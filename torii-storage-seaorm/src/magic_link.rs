use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, prelude::Uuid,
};
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
    type Error = SeaORMStorageError;

    async fn save_magic_token(
        &self,
        token: &MagicToken,
    ) -> Result<(), <Self as MagicLinkStorage>::Error> {
        let magic_link = magic_link::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(token.user_id.to_string()),
            token: Set(token.token.clone()),
            used_at: Set(token.used_at),
            expires_at: Set(token.expires_at),
            created_at: Set(Utc::now()),
            updated_at: Set(Utc::now()),
        };
        magic_link.insert(&self.pool).await?;

        Ok(())
    }

    async fn get_magic_token(
        &self,
        token: &str,
    ) -> Result<Option<MagicToken>, <Self as MagicLinkStorage>::Error> {
        let magic_link = magic_link::Entity::find()
            .filter(magic_link::Column::Token.eq(token))
            .one(&self.pool)
            .await?;

        Ok(magic_link.map(|model| model.into()))
    }

    async fn set_magic_token_used(
        &self,
        token: &str,
    ) -> Result<(), <Self as MagicLinkStorage>::Error> {
        let magic_link: Option<magic_link::ActiveModel> = magic_link::Entity::find()
            .filter(magic_link::Column::Token.eq(token))
            .one(&self.pool)
            .await?
            .map(|model| model.into());

        if let Some(mut magic_link) = magic_link {
            magic_link.used_at = Set(Some(Utc::now()));
            magic_link.update(&self.pool).await?;
        }

        Ok(())
    }
}
