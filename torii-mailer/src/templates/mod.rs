mod auth_templates;
mod engine;

pub use auth_templates::{
    MagicLinkTemplate, PasswordChangedTemplate, PasswordResetTemplate, TemplateContext,
    WelcomeTemplate,
};
pub use engine::{AskamaTemplateEngine, TemplateEngine};

use crate::MailerError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateData {
    pub data: HashMap<String, serde_json::Value>,
}

impl TemplateData {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    pub fn insert<T: Serialize>(mut self, key: &str, value: T) -> Result<Self, MailerError> {
        self.data
            .insert(key.to_string(), serde_json::to_value(value)?);
        Ok(self)
    }

    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.data.get(key)
    }
}

impl Default for TemplateData {
    fn default() -> Self {
        Self::new()
    }
}
