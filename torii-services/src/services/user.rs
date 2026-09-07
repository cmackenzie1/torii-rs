use std::sync::Arc;
use torii_core::{
    Error, User, UserId, events::Event, repositories::UserRepository, storage::NewUser,
    validation::validate_email,
};

use crate::{EventBus, EventEmitter};

/// Service for user management operations
pub struct UserService<R: UserRepository> {
    repository: Arc<R>,
    event_bus: Option<Arc<EventBus>>,
}

impl<R: UserRepository> UserService<R> {
    /// Create a new UserService with the given repository
    pub fn new(repository: Arc<R>) -> Self {
        Self {
            repository,
            event_bus: None,
        }
    }

    /// Enable lifecycle event emission for this service.
    pub fn with_event_bus(mut self, event_bus: Arc<EventBus>) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    /// Create a new user
    pub async fn create_user(&self, email: &str, name: Option<String>) -> Result<User, Error> {
        // Validate email format
        validate_email(email)?;

        let mut builder = NewUser::builder()
            .id(UserId::new_random())
            .email(email.to_string());

        if let Some(name) = name {
            builder = builder.name(name);
        }

        let new_user = builder.build()?;

        let user = self.repository.create(new_user).await?;
        self.emit_event(Event::UserCreated(user.clone())).await?;
        Ok(user)
    }

    /// Get a user by ID
    pub async fn get_user(&self, user_id: &UserId) -> Result<Option<User>, Error> {
        self.repository.find_by_id(user_id).await
    }

    /// Get a user by email
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Error> {
        self.repository.find_by_email(email).await
    }

    /// Get or create a user by email
    pub async fn get_or_create_user(&self, email: &str) -> Result<User, Error> {
        // Validate email format
        validate_email(email)?;

        self.repository.find_or_create_by_email(email).await
    }

    /// Update a user
    pub async fn update_user(&self, user: &User) -> Result<User, Error> {
        let user = self.repository.update(user).await?;
        self.emit_event(Event::UserUpdated(user.clone())).await?;
        Ok(user)
    }

    /// Delete a user
    pub async fn delete_user(&self, user_id: &UserId) -> Result<(), Error> {
        let user = self.repository.find_by_id(user_id).await?;
        self.repository.delete(user_id).await?;
        if let Some(user) = user {
            self.emit_event(Event::UserDeleted(user.id)).await?;
        }
        Ok(())
    }

    /// Mark a user's email as verified
    pub async fn verify_email(&self, user_id: &UserId) -> Result<(), Error> {
        self.repository.mark_email_verified(user_id).await
    }
}

#[async_trait::async_trait]
impl<R: UserRepository> EventEmitter for UserService<R> {
    fn event_bus(&self) -> Option<&Arc<EventBus>> {
        self.event_bus.as_ref()
    }
}
