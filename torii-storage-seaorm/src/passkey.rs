use async_trait::async_trait;
use chrono::Utc;
use sea_orm::ActiveValue::Set;
use sea_orm::prelude::Uuid;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};
use torii_core::{UserId, storage::PasskeyStorage};

use crate::{SeaORMStorage, SeaORMStorageError};

use crate::entities::{passkey, passkey_challenge};

#[async_trait]
impl PasskeyStorage for SeaORMStorage {
    type Error = SeaORMStorageError;

    async fn add_passkey(
        &self,
        user_id: &UserId,
        credential_id: &str,
        passkey_json: &str,
    ) -> Result<(), <Self as PasskeyStorage>::Error> {
        let passkey = passkey::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_string()),
            credential_id: Set(credential_id.to_string()),
            data_json: Set(passkey_json.to_string()),
            created_at: Set(Utc::now()),
            updated_at: Set(Utc::now()),
        };

        passkey.insert(&self.pool).await?;

        Ok(())
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<String>, <Self as PasskeyStorage>::Error> {
        let passkey = passkey::Entity::find()
            .filter(passkey::Column::CredentialId.eq(credential_id))
            .one(&self.pool)
            .await?;

        Ok(passkey.map(|p| p.data_json))
    }

    async fn get_passkeys(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<String>, <Self as PasskeyStorage>::Error> {
        let passkeys = passkey::Entity::find()
            .filter(passkey::Column::UserId.eq(user_id.to_string()))
            .all(&self.pool)
            .await?;

        Ok(passkeys.into_iter().map(|p| p.data_json).collect())
    }

    async fn set_passkey_challenge(
        &self,
        challenge_id: &str,
        challenge: &str,
        expires_in: chrono::Duration,
    ) -> Result<(), <Self as PasskeyStorage>::Error> {
        let passkey_challenge = passkey_challenge::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            challenge_id: Set(challenge_id.to_string()),
            challenge: Set(challenge.to_string()),
            expires_at: Set(Utc::now() + expires_in),
            created_at: Set(Utc::now()),
            updated_at: Set(Utc::now()),
        };

        passkey_challenge.insert(&self.pool).await?;

        Ok(())
    }

    async fn get_passkey_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Option<String>, <Self as PasskeyStorage>::Error> {
        let passkey_challenge = passkey_challenge::Entity::find()
            .filter(passkey_challenge::Column::ChallengeId.eq(challenge_id))
            .one(&self.pool)
            .await?;

        Ok(passkey_challenge.map(|p| p.challenge))
    }
}
