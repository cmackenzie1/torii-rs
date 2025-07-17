let jwt_config = JwtConfig::new(secret_key.to_string());
let torii = Torii::new(repositories).with_jwt_sessions(jwt_config);