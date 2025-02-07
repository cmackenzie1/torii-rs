use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::{session::SessionId, Session, User, UserId};

#[async_trait]
pub trait UserStorage: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn create_user(&self, user: &NewUser) -> Result<User, Self::Error>;
    async fn get_user(&self, id: &UserId) -> Result<Option<User>, Self::Error>;
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Self::Error>;
    async fn get_or_create_user_by_email(&self, email: &str) -> Result<User, Self::Error>;
    async fn update_user(&self, user: &User) -> Result<User, Self::Error>;
    async fn delete_user(&self, id: &UserId) -> Result<(), Self::Error>;
}

#[async_trait]
pub trait SessionStorage: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn create_session(&self, session: &Session) -> Result<Session, Self::Error>;
    async fn get_session(&self, id: &SessionId) -> Result<Option<Session>, Self::Error>;
    async fn delete_session(&self, id: &SessionId) -> Result<(), Self::Error>;
    async fn cleanup_expired_sessions(&self) -> Result<(), Self::Error>;
    async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone)]
pub struct Storage<U: UserStorage, S: SessionStorage> {
    user_storage: Arc<U>,
    session_storage: Arc<S>,
}

impl<U: UserStorage, S: SessionStorage> Storage<U, S> {
    pub fn new(user_storage: Arc<U>, session_storage: Arc<S>) -> Self {
        Self {
            user_storage,
            session_storage,
        }
    }

    pub async fn create_user(&self, user: &NewUser) -> Result<User, U::Error> {
        self.user_storage.create_user(user).await
    }

    pub async fn get_user(&self, id: &UserId) -> Result<Option<User>, U::Error> {
        self.user_storage.get_user(id).await
    }

    pub async fn create_session(&self, session: &Session) -> Result<Session, S::Error> {
        self.session_storage.create_session(session).await
    }

    pub async fn get_session(&self, id: &SessionId) -> Result<Option<Session>, S::Error> {
        self.session_storage.get_session(id).await
    }

    pub async fn delete_session(&self, id: &SessionId) -> Result<(), S::Error> {
        self.session_storage.delete_session(id).await
    }

    pub async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), S::Error> {
        self.session_storage.delete_sessions_for_user(user_id).await
    }

    pub fn user_storage(&self) -> Arc<U> {
        self.user_storage.clone()
    }

    pub fn session_storage(&self) -> Arc<S> {
        self.session_storage.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
#[builder(pattern = "owned")]
pub struct NewUser {
    #[builder(default = "UserId::new_random()")]
    pub id: UserId,
    pub email: String,
    #[builder(default = "None")]
    pub name: Option<String>,
    #[builder(default = "None")]
    pub email_verified_at: Option<DateTime<Utc>>,
}

impl NewUser {
    pub fn builder() -> NewUserBuilder {
        NewUserBuilder::default()
    }

    pub fn new(email: String) -> Self {
        NewUserBuilder::default()
            .email(email)
            .build()
            .expect("Default builder should never fail")
    }

    pub fn with_id(id: UserId, email: String) -> Self {
        NewUserBuilder::default()
            .id(id)
            .email(email)
            .build()
            .expect("Default builder should never fail")
    }
}
