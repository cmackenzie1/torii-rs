use torii_core::{OAuthAccount, UserId};

use crate::entities::oauth;

impl From<oauth::Model> for OAuthAccount {
    fn from(value: oauth::Model) -> Self {
        OAuthAccount::builder()
            .user_id(UserId::new(&value.user_id))
            .provider(value.provider)
            .subject(value.subject)
            .build()
            .expect("Failed to build OAuthAccount")
    }
}
