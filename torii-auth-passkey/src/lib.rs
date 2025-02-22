use std::collections::HashMap;

use async_trait::async_trait;
use torii_core::auth::{AuthChallenge, AuthStage};
use torii_core::storage::{PasskeyStorage, SessionStorage, Storage};
use torii_core::{AuthPlugin, AuthResponse, Credentials, Error, NewUser, Plugin, Session, UserId};
use webauthn_rs::prelude::*;

pub struct PasskeyPlugin<U: PasskeyStorage, S: SessionStorage> {
    webauthn: Webauthn,
    storage: Storage<U, S>,
}

impl<U: PasskeyStorage, S: SessionStorage> PasskeyPlugin<U, S> {
    pub fn new(rp_id: &str, rp_origin: &str, storage: Storage<U, S>) -> Self {
        let rp_origin = Url::parse(rp_origin).expect("Failed to parse rp_origin");
        let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");
        let webauthn = builder.build().expect("Invalid configuration");

        Self { webauthn, storage }
    }

    /// Start a passkey registration and return the challenge to the client.
    /// The challenge is stored in the database for verification, and no user is created.
    pub async fn start_registration(&self, email: &str) -> Result<AuthStage, Error> {
        let challenge_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        // CCR is sent to the client, SKR is stored in the database for verification
        let (ccr, skr) = self
            .webauthn
            .start_passkey_registration(user_id, email, email, None)
            .expect("Failed to start registration.");

        self.storage
            .user_storage()
            .set_passkey_challenge(
                &challenge_id.to_string(),
                &serde_json::to_string(&skr).unwrap(),
            )
            .await
            .map_err(|_| Error::InternalServerError)?;

        Ok(AuthStage::Challenge(AuthChallenge {
            challenge_type: "passkey_registration".to_string(),
            challenge: serde_json::to_value(&ccr).unwrap(),
            metadata: HashMap::from([
                ("challenge_id".to_string(), challenge_id.to_string()),
                ("user_id".to_string(), user_id.to_string()),
            ]),
        }))
    }

    /// Complete a passkey registration and create a user in the user storage.
    pub async fn complete_registration(
        &self,
        email: &str,
        challenge_response: Option<serde_json::Value>,
        metadata: &HashMap<String, String>,
    ) -> Result<AuthStage, Error> {
        let challenge_id = metadata
            .get("challenge_id")
            .ok_or(Error::InvalidCredentials)?
            .to_string();

        let passkey_challenge = self
            .storage
            .user_storage()
            .get_passkey_challenge(&challenge_id)
            .await
            .map_err(|_| Error::InternalServerError)?
            .ok_or(Error::InvalidCredentials)?;

        let passkey_challenge = serde_json::from_str::<PasskeyRegistration>(&passkey_challenge)
            .map_err(|_| Error::InternalServerError)?;

        let challenge_response =
            serde_json::from_value::<RegisterPublicKeyCredential>(challenge_response.unwrap())
                .map_err(|_| Error::InternalServerError)?;

        let passkey_challenge = self
            .webauthn
            .finish_passkey_registration(&challenge_response, &passkey_challenge)
            .expect("Failed to complete registration.");

        let user_id = UserId::new(
            &metadata
                .get("user_id")
                .ok_or(Error::InvalidCredentials)?
                .to_string(),
        );

        let user = self
            .storage
            .user_storage()
            .create_user(&NewUser {
                id: user_id.clone(),
                email: email.to_string(),
                name: None,
                email_verified_at: None,
            })
            .await
            .map_err(|_| Error::InternalServerError)?;

        self.storage
            .user_storage()
            .add_passkey_credential(
                &user_id,
                &serde_json::to_string(&passkey_challenge).unwrap(),
            )
            .await
            .map_err(|_| Error::InternalServerError)?;

        Ok(AuthStage::Complete(AuthResponse {
            user,
            session: None, // TODO: Create session
            metadata: HashMap::new(),
            passkey_challenge: None,
        }))
    }

    pub async fn start_login(&self, email: &str) -> Result<AuthStage, Error> {
        let user = self
            .storage
            .user_storage()
            .get_user_by_email(email)
            .await
            .map_err(|_| Error::InternalServerError)?
            .ok_or(Error::InvalidCredentials)?;

        let passkey_credentials = self
            .storage
            .user_storage()
            .get_passkey_credentials(&user.id)
            .await
            .map_err(|_| Error::InternalServerError)?;

        let allowed_credentials = passkey_credentials
            .iter()
            .map(|cred| serde_json::from_str::<Passkey>(cred).unwrap())
            .collect::<Vec<_>>();

        let challenge_id = Uuid::new_v4();
        let (rcr, rak) = self
            .webauthn
            .start_passkey_authentication(&allowed_credentials)
            .expect("Failed to start login.");

        self.storage
            .user_storage()
            .set_passkey_challenge(
                &challenge_id.to_string(),
                &serde_json::to_string(&rak).unwrap(),
            )
            .await
            .map_err(|_| Error::InternalServerError)?;

        Ok(AuthStage::Challenge(AuthChallenge {
            challenge_type: "passkey_login".to_string(),
            challenge: serde_json::to_value(&rcr).unwrap(),
            metadata: HashMap::from([
                ("challenge_id".to_string(), challenge_id.to_string()),
                ("user_id".to_string(), user.id.to_string()),
            ]),
        }))
    }

    pub async fn complete_login(
        &self,
        email: &str,
        public_key: Option<serde_json::Value>,
        metadata: &HashMap<String, String>,
    ) -> Result<AuthStage, Error> {
        let challenge_id = metadata
            .get("challenge_id")
            .ok_or(Error::InvalidCredentials)?
            .to_string();

        let passkey_challenge = self
            .storage
            .user_storage()
            .get_passkey_challenge(&challenge_id)
            .await
            .map_err(|_| Error::InternalServerError)?
            .ok_or(Error::InvalidCredentials)?;

        let passkey_challenge = serde_json::from_str::<PasskeyAuthentication>(&passkey_challenge)
            .map_err(|_| Error::InternalServerError)?;

        let public_key = serde_json::from_value::<PublicKeyCredential>(public_key.unwrap())
            .map_err(|_| Error::InternalServerError)?;

        // TODO: There is no correlation between user and the passkeys right now
        let user = self
            .storage
            .user_storage()
            .get_user_by_email(email)
            .await
            .map_err(|_| Error::InternalServerError)?
            .ok_or(Error::InvalidCredentials)?;

        match self
            .webauthn
            .finish_passkey_authentication(&public_key, &passkey_challenge)
        {
            Ok(_) => {
                Ok(AuthStage::Complete(AuthResponse {
                    user,
                    session: None, // TODO: Create session
                    metadata: HashMap::new(),
                    passkey_challenge: None,
                }))
            }
            Err(e) => {
                tracing::error!(error = ?e, "Failed to complete login");
                Err(Error::InvalidCredentials)
            }
        }
    }
}

impl<U: PasskeyStorage, S: SessionStorage> Plugin for PasskeyPlugin<U, S> {
    fn name(&self) -> String {
        "passkey".to_string()
    }
}

#[async_trait]
impl<U: PasskeyStorage, S: SessionStorage> AuthPlugin for PasskeyPlugin<U, S> {
    fn auth_method(&self) -> String {
        "passkey".to_string()
    }

    async fn register(&self, credentials: &Credentials) -> Result<AuthStage, Error> {
        match credentials {
            Credentials::Passkey { stage, email, .. } if stage == "start_registration" => {
                self.start_registration(email).await
            }
            Credentials::Passkey {
                stage,
                email,
                challenge_response,
                metadata,
            } if stage == "complete_registration" => {
                self.complete_registration(email, challenge_response.clone(), metadata)
                    .await
            }
            _ => Err(Error::InvalidCredentials),
        }
    }

    async fn authenticate(&self, credentials: &Credentials) -> Result<AuthStage, Error> {
        match credentials {
            Credentials::Passkey { stage, email, .. } if stage == "start_login" => {
                self.start_login(email).await
            }
            Credentials::Passkey {
                stage,
                email,
                challenge_response,
                metadata,
            } if stage == "complete_login" => {
                self.complete_login(email, challenge_response.clone(), metadata)
                    .await
            }
            _ => Err(Error::InvalidCredentials),
        }
    }

    async fn validate_session(&self, _session: &Session) -> Result<bool, Error> {
        todo!()
    }

    async fn logout(&self, _session: &Session) -> Result<(), Error> {
        todo!()
    }
}
