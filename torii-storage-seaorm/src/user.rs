use chrono::Utc;
use sea_orm::ColumnTrait;
use sea_orm::QueryFilter;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use torii_core::{NewUser, User as ToriiUser, UserId, UserStorage};

use crate::SeaORMStorage;
use crate::entities::user;

impl From<user::Model> for ToriiUser {
    fn from(user: user::Model) -> Self {
        Self {
            id: UserId::new(&user.id),
            name: user.name.to_owned(),
            email: user.email.to_owned(),
            email_verified_at: user.email_verified_at.to_owned(),
            created_at: user.created_at.to_owned(),
            updated_at: user.updated_at.to_owned(),
        }
    }
}

#[async_trait::async_trait]
impl UserStorage for SeaORMStorage {
    type Error = sea_orm::DbErr;

    async fn create_user(&self, user: &NewUser) -> Result<ToriiUser, Self::Error> {
        let model = user::ActiveModel {
            email: Set(user.email.to_owned()),
            name: Set(user.name.to_owned()),
            email_verified_at: Set(user.email_verified_at.to_owned()),
            ..Default::default()
        };

        Ok(model.insert(&self.pool).await?.into())
    }

    async fn get_user(&self, id: &UserId) -> Result<Option<ToriiUser>, Self::Error> {
        let user = user::Entity::find_by_id(id.as_str())
            .one(&self.pool)
            .await?;

        Ok(user.map(ToriiUser::from))
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<ToriiUser>, Self::Error> {
        Ok(user::Entity::find()
            .filter(user::Column::Email.eq(email))
            .one(&self.pool)
            .await?
            .map(ToriiUser::from))
    }

    async fn get_or_create_user_by_email(&self, email: &str) -> Result<ToriiUser, Self::Error> {
        let user = self.get_user_by_email(email).await?;

        match user {
            Some(user) => Ok(user),
            None => {
                self.create_user(&NewUser::builder().email(email.to_string()).build().unwrap())
                    .await
            }
        }
    }

    async fn update_user(&self, user: &ToriiUser) -> Result<ToriiUser, Self::Error> {
        let model = user::ActiveModel {
            name: Set(user.name.to_owned()),
            ..Default::default()
        };

        Ok(model.update(&self.pool).await?.into())
    }

    async fn delete_user(&self, id: &UserId) -> Result<(), Self::Error> {
        let _ = user::Entity::delete_by_id(id.as_str())
            .exec(&self.pool)
            .await?;

        Ok(())
    }

    async fn set_user_email_verified(&self, user_id: &UserId) -> Result<(), Self::Error> {
        let mut user: user::ActiveModel = user::Entity::find_by_id(user_id.as_str())
            .one(&self.pool)
            .await?
            .unwrap()
            .into();

        user.email_verified_at = Set(Some(Utc::now()));
        user.update(&self.pool).await?;

        Ok(())
    }
}
