use std::sync::Arc;
use torii::{Torii, SessionConfig};
use chrono::Duration;

let torii = Torii::new(repositories)
    .with_session_config(
        SessionConfig::default()
            .expires_in(Duration::days(30))
    );