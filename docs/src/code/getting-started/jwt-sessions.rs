use torii::{Torii, JwtConfig, SessionConfig};
use chrono::Duration;

// Create JWT configuration with HS256 algorithm
let jwt_config = JwtConfig::new("your-secret-key-at-least-32-chars-long!".to_string())
    .with_issuer("your-app-name")
    .with_metadata(true);

let torii = Torii::new(repositories)
    .with_jwt_sessions(jwt_config);

// Or with custom expiration
let torii = Torii::new(repositories)
    .with_session_config(
        SessionConfig::default()
            .with_jwt(jwt_config)
            .expires_in(Duration::hours(2))
    );