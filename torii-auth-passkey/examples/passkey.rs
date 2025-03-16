use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use serde::Deserialize;
use serde_json::json;
use sqlx::{Pool, Sqlite};
use torii_auth_passkey::{
    ChallengeId, PasskeyAuthPlugin, PasskeyLoginCompletion, PasskeyLoginRequest, PasskeyPlugin,
    PasskeyRegistrationCompletion, PasskeyRegistrationRequest,
};
use torii_core::{
    DefaultUserManager, Session, plugin::PluginManager, session::SessionToken,
    storage::SessionStorage, storage::UserStorage,
};
use torii_storage_sqlite::SqliteStorage;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

#[derive(Clone)]
struct AppState {
    plugin_manager: Arc<PluginManager<SqliteStorage, SqliteStorage>>,
}

#[axum::debug_handler]
async fn begin_registration_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(params): Json<PasskeyRegistrationRequest>,
) -> impl IntoResponse {
    let plugin = state
        .plugin_manager
        .get_plugin::<PasskeyPlugin<DefaultUserManager<SqliteStorage>, SqliteStorage>>("passkey")
        .unwrap();

    let options = <PasskeyPlugin<DefaultUserManager<SqliteStorage>, SqliteStorage> as PasskeyAuthPlugin>::start_registration(
        plugin.as_ref(),
        &params,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to start registration: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to start registration",
        )
    })
    .expect("Failed to start registration");

    // Debug the options structure
    tracing::info!("Registration options: {:?}", options);
    tracing::info!("Options.options: {:?}", options.options);

    // Convert options.options to a string for detailed debugging
    if let Ok(json_str) = serde_json::to_string_pretty(&options.options) {
        tracing::info!("Options.options as JSON:\n{}", json_str);
    }

    let jar = jar.add(
        Cookie::build(("passkey_challenge_id", options.challenge_id.to_string()))
            .path("/")
            .http_only(true),
    );

    (jar, Json(options.options)).into_response()
}

#[derive(Debug, Deserialize)]
struct RegistrationCompletionRequest {
    email: String,
    #[allow(dead_code)]
    challenge_id: Option<String>,
    response: serde_json::Value,
}

#[axum::debug_handler]
async fn finish_registration_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<RegistrationCompletionRequest>,
) -> impl IntoResponse {
    // Debug the request body
    tracing::info!("Registration completion raw body: {:#?}", body);

    // Get the challenge_id from the cookie
    let challenge_id = if let Some(cookie) = jar.get("passkey_challenge_id") {
        let cookie_value = cookie.value().to_string();
        tracing::info!("Found challenge_id in cookie: {}", cookie_value);
        ChallengeId::new(cookie_value)
    } else {
        tracing::error!("Missing challenge ID cookie");
        return (StatusCode::BAD_REQUEST, "Missing challenge ID cookie").into_response();
    };

    // Convert the raw JSON response to the proper WebAuthn type
    let response =
        match serde_json::from_value::<RegisterPublicKeyCredential>(body.response.clone()) {
            Ok(credential) => credential,
            Err(e) => {
                tracing::error!("Failed to deserialize credential: {}", e);
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid credential: {}", e),
                )
                    .into_response();
            }
        };

    // Create the proper PasskeyRegistrationCompletion object
    let completion = PasskeyRegistrationCompletion {
        email: body.email,
        challenge_id,
        response,
    };

    tracing::info!("Created PasskeyRegistrationCompletion: {:#?}", completion);

    let plugin = state
        .plugin_manager
        .get_plugin::<PasskeyPlugin<DefaultUserManager<SqliteStorage>, SqliteStorage>>("passkey")
        .unwrap();

    let user = <PasskeyPlugin<DefaultUserManager<SqliteStorage>, SqliteStorage> as PasskeyAuthPlugin>::complete_registration(
        plugin.as_ref(),
        &completion,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to complete registration: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to complete registration: {}", e),
        )
            .into_response()
    })
    .unwrap();

    let session = state
        .plugin_manager
        .session_storage()
        .create_session(&Session::builder().user_id(user.id.clone()).build().unwrap())
        .await
        .unwrap();

    let jar = jar.add(
        Cookie::build(("session_id", session.token.to_string()))
            .path("/")
            .http_only(true),
    );

    (jar, Json(user)).into_response()
}

/// Protected route that displays the currently authenticated user's details
/// Returns 401 if not authenticated
async fn whoami_handler(State(state): State<AppState>, jar: CookieJar) -> Response {
    let session_id = jar
        .get("session_id")
        .and_then(|cookie| cookie.value().parse::<String>().ok());

    if let Some(session_id) = session_id {
        let session = state
            .plugin_manager
            .session_storage()
            .get_session(&SessionToken::new(&session_id))
            .await
            .unwrap();

        let user = state
            .plugin_manager
            .user_storage()
            .get_user(&session.unwrap().user_id)
            .await
            .unwrap();
        return Json(user).into_response();
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "Not authenticated"
        })),
    )
        .into_response()
}

/// Middleware to protect routes that require authentication
/// Checks for valid session cookie and redirects to sign-in if missing/invalid
async fn verify_session(
    State(state): State<AppState>,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Response {
    let session_id = jar
        .get("session_id")
        .and_then(|cookie| cookie.value().parse::<String>().ok());

    if let Some(session_id) = session_id {
        // Verify session exists and is valid
        state
            .plugin_manager
            .session_storage()
            .get_session(&SessionToken::new(&session_id))
            .await
            .unwrap();

        return next.run(request).await;
    }

    // If session is invalid or missing, redirect to home page
    Redirect::to("/").into_response()
}

#[axum::debug_handler]
async fn begin_login_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(params): Json<PasskeyLoginRequest>,
) -> Response {
    let plugin = state
        .plugin_manager
        .get_plugin::<PasskeyPlugin<DefaultUserManager<SqliteStorage>, SqliteStorage>>("passkey")
        .unwrap();

    let options =
        <PasskeyPlugin<DefaultUserManager<SqliteStorage>, SqliteStorage> as PasskeyAuthPlugin>::start_login(plugin.as_ref(), &params)
            .await
            .map_err(|e| {
                tracing::error!("Failed to start login: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to start login").into_response()
            })
            .unwrap();

    // Debug the options structure
    tracing::info!("Login options: {:?}", options);
    tracing::info!("Options.options: {:?}", options.options);

    // Convert options.options to a string for detailed debugging
    if let Ok(json_str) = serde_json::to_string_pretty(&options.options) {
        tracing::info!("Options.options as JSON:\n{}", json_str);
    }

    let jar = jar.add(
        Cookie::build(("passkey_challenge_id", options.challenge_id.to_string()))
            .path("/")
            .http_only(true),
    );

    (jar, Json(options.options)).into_response()
}

#[derive(Debug, Deserialize)]
struct LoginCompletionRequest {
    email: String,
    #[allow(dead_code)]
    challenge_id: Option<String>,
    response: serde_json::Value,
}

#[axum::debug_handler]
async fn finish_login_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<LoginCompletionRequest>,
) -> Response {
    // Debug the request body
    tracing::info!("Login completion raw body: {:#?}", body);

    // Get the challenge_id from the cookie
    let challenge_id = if let Some(cookie) = jar.get("passkey_challenge_id") {
        let cookie_value = cookie.value().to_string();
        tracing::info!("Found challenge_id in cookie: {}", cookie_value);
        ChallengeId::new(cookie_value)
    } else {
        tracing::error!("Missing challenge ID cookie");
        return (StatusCode::BAD_REQUEST, "Missing challenge ID cookie").into_response();
    };

    // Convert the raw JSON response to the proper WebAuthn type
    let response = match serde_json::from_value::<PublicKeyCredential>(body.response.clone()) {
        Ok(credential) => credential,
        Err(e) => {
            tracing::error!("Failed to deserialize credential: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid credential: {}", e),
            )
                .into_response();
        }
    };

    // Create the proper PasskeyLoginCompletion object
    let completion = PasskeyLoginCompletion {
        email: body.email,
        challenge_id,
        response,
    };

    tracing::info!("Created PasskeyLoginCompletion: {:#?}", completion);

    let plugin = state
        .plugin_manager
        .get_plugin::<PasskeyPlugin<DefaultUserManager<SqliteStorage>, SqliteStorage>>("passkey")
        .unwrap();

    let user = <PasskeyPlugin<DefaultUserManager<SqliteStorage>, SqliteStorage> as PasskeyAuthPlugin>::complete_login(
        plugin.as_ref(),
        &completion,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to complete login: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to complete login: {}", e),
        )
            .into_response()
    })
    .unwrap();

    let session = state
        .plugin_manager
        .session_storage()
        .create_session(&Session::builder().user_id(user.id.clone()).build().unwrap())
        .await
        .unwrap();

    let jar = jar.add(
        Cookie::build(("session_id", session.token.to_string()))
            .path("/")
            .http_only(true),
    );

    (jar, Json(user)).into_response()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let pool = Pool::<Sqlite>::connect("sqlite:./passkey.db?mode=rwc")
        .await
        .unwrap();

    let storage = Arc::new(SqliteStorage::new(pool.clone()));
    let session_storage = Arc::new(SqliteStorage::new(pool.clone()));

    storage.migrate().await.unwrap();
    session_storage.migrate().await.unwrap();

    // Create user manager
    let user_manager = Arc::new(DefaultUserManager::new(storage.clone()));

    let mut plugin_manager = PluginManager::new(storage.clone(), session_storage.clone());
    plugin_manager.register_plugin(PasskeyPlugin::new(
        "localhost",
        "http://localhost:4000",
        user_manager.clone(),
        storage.clone(),
    ));

    let app_state = AppState {
        plugin_manager: Arc::new(plugin_manager),
    };

    let app = Router::new()
        .route("/whoami", get(whoami_handler))
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            verify_session,
        ))
        .route(
            "/",
            get(|| async {
                Html(
                    r#"
            <!DOCTYPE html>
            <html>
                <body>
                    <h1>Passkey Example</h1>
                    <input type="email" id="email" placeholder="Email">
                    <button onclick="beginRegistration()">Begin Registration</button>
                    <button onclick="beginLogin()">Begin Login</button>

                    <script src="https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.umd.min.js"></script>
                    <script>
                        // Access the SimpleWebAuthn browser library
                        const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;
                        async function beginRegistration() {
                        try {
                            const email = document.getElementById('email').value;
                            
                            if (!email) {
                                alert('Please enter an email address');
                                return;
                            }
                            
                            // Start registration flow
                            console.log("Starting registration with email:", email);
                            const response = await fetch('/auth/passkey/begin-registration', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json'
                                },
                                body: JSON.stringify({ email })
                            });

                            if (!response.ok) {
                                const errorText = await response.text();
                                console.error('Failed to begin registration:', errorText);
                                alert(`Failed to begin registration: ${errorText}`);
                                return;
                            }

                            // Parse the registration options
                            const responseData = await response.json();
                            console.log("Registration response:", responseData);
                            
                            // The server might be sending {publicKey: {...}} or directly the publicKey content
                            const publicKeyOptions = responseData.publicKey || responseData;
                            console.log("Public key options:", publicKeyOptions);
                            
                            if (!publicKeyOptions || !publicKeyOptions.challenge) {
                                console.error('Invalid registration options - no challenge found');
                                alert('Failed to start registration: Invalid server response (no challenge)');
                                return;
                            }
                            
                            console.log("Creating credentials with options:", publicKeyOptions);
                            
                            // Use SimpleWebAuthn to handle the registration
                            const credential = await startRegistration(publicKeyOptions);
                            console.log("Created credential:", credential);

                            // Complete registration
                            // Get the challenge_id from the cookie or from the options
                            const challenge_id = document.cookie
                                .split('; ')
                                .find(row => row.startsWith('passkey_challenge_id='))
                                ?.split('=')[1];
                                
                            console.log("Challenge ID for completion:", challenge_id);
                            
                            const result = await fetch('/auth/passkey/finish-registration', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json'
                                },
                                body: JSON.stringify({
                                    email,
                                    challenge_id,
                                    response: credential
                                })
                            });

                            if (!result.ok) {
                                const errorText = await result.text();
                                console.error('Failed to complete registration:', errorText);
                                alert(`Failed to complete registration: ${errorText}`);
                                return;
                            }

                            alert('Registration successful!');
                            window.location.href = '/whoami';
                        } catch (error) {
                            console.error('Registration error:', error);
                            alert(`Registration error: ${error.message}`);
                        }
                    }

                    async function beginLogin() {
                        try {
                            const email = document.getElementById('email').value;
                            
                            if (!email) {
                                alert('Please enter an email address');
                                return;
                            }
                            
                            // Start login flow
                            console.log("Starting login with email:", email);
                            const response = await fetch('/auth/passkey/begin-login', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json'
                                },
                                body: JSON.stringify({ email })
                            });

                            if (!response.ok) {
                                const errorText = await response.text();
                                console.error('Failed to begin login:', errorText);
                                alert(`Failed to begin login: ${errorText}`);
                                return;
                            }

                            // Parse the login options
                            const responseData = await response.json();
                            console.log("Login response:", responseData);
                            
                            // The server might be sending {publicKey: {...}} or directly the publicKey content
                            const publicKeyOptions = responseData.publicKey || responseData;
                            console.log("Public key options:", publicKeyOptions);
                            
                            if (!publicKeyOptions || !publicKeyOptions.challenge) {
                                console.error('Invalid login options - no challenge found');
                                alert('Failed to start login: Invalid server response (no challenge)');
                                return;
                            }
                            
                            // Use SimpleWebAuthn to handle the authentication
                            console.log("Getting credentials with options:", publicKeyOptions);
                            const credential = await startAuthentication(publicKeyOptions);
                            console.log("Retrieved credential:", credential);

                            // Complete login
                            // Get the challenge_id from the cookie or from the options
                            const challenge_id = document.cookie
                                .split('; ')
                                .find(row => row.startsWith('passkey_challenge_id='))
                                ?.split('=')[1];
                                
                            console.log("Challenge ID for login completion:", challenge_id);
                            
                            const result = await fetch('/auth/passkey/finish-login', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json'
                                },  
                                body: JSON.stringify({
                                    email,
                                    challenge_id,
                                    response: credential
                                })
                            });

                            if (!result.ok) {
                                const errorText = await result.text();
                                console.error('Failed to complete login:', errorText);
                                alert(`Failed to complete login: ${errorText}`);
                                return;
                            }

                            alert('Login successful!');
                            window.location.href = '/whoami';
                        } catch (error) {
                            console.error('Login error:', error);
                            alert(`Login error: ${error.message}`);
                        }
                    }
                    </script>
                </body>
            </html>
        "#,
                )
            }),
        )
        .route(
            "/auth/passkey/begin-registration",
            post(begin_registration_handler),
        )
        .route(
            "/auth/passkey/finish-registration",
            post(finish_registration_handler),
        )
        .route(
            "/auth/passkey/begin-login",
            post(begin_login_handler),
        )
        .route(
            "/auth/passkey/finish-login",
            post(finish_login_handler),
        )
        .with_state(app_state);

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:4000").await.unwrap();
        println!("Listening on {}", listener.local_addr().unwrap());
        axum::serve(listener, app).await.unwrap();
    });

    println!("Please open the following URL in your browser: http://localhost:4000/");

    println!("Press Enter or Ctrl+C to exit...");
    let _ = std::io::stdin().read_line(&mut String::new());
}
