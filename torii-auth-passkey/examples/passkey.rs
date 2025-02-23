use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
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
use torii_auth_passkey::PasskeyPlugin;
use torii_core::{auth::AuthStage, plugin::PluginManager, session::SessionId, storage::Storage};
use torii_storage_sqlite::SqliteStorage;

#[derive(Clone)]
struct AppState {
    plugin_manager: Arc<PluginManager<SqliteStorage, SqliteStorage>>,
}

#[derive(Debug, Deserialize)]
struct BeginRegistrationBody {
    email: String,
}

#[axum::debug_handler]
async fn begin_registration_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(params): Json<BeginRegistrationBody>,
) -> impl IntoResponse {
    let plugin = state
        .plugin_manager
        .get_auth_plugin::<PasskeyPlugin<SqliteStorage, SqliteStorage>>("passkey")
        .unwrap();

    let challenge = plugin
        .start_registration(&params.email)
        .await
        .map_err(|e| {
            tracing::error!("Failed to start registration: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to start registration",
            )
        })
        .expect("Failed to start registration");

    let jar = jar.add(
        Cookie::build(("passkey_challenge_id", challenge.challenge_id().to_string()))
            .path("/")
            .http_only(true),
    );

    (jar, Json(challenge.challenge())).into_response()
}

#[derive(Debug, Deserialize)]
struct FinishRegistrationBody {
    email: String,
    challenge_response: serde_json::Value,
}

#[axum::debug_handler]
async fn finish_registration_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<FinishRegistrationBody>,
) -> impl IntoResponse {
    let email = body.email;
    let passkey_challenge_id = jar.get("passkey_challenge_id").unwrap().value();

    let plugin = state
        .plugin_manager
        .get_auth_plugin::<PasskeyPlugin<SqliteStorage, SqliteStorage>>("passkey")
        .unwrap();

    let auth_stage = plugin
        .complete_registration(&email, &passkey_challenge_id, &body.challenge_response)
        .await
        .unwrap();

    match auth_stage {
        AuthStage::Complete(auth_response) => {
            let session = auth_response.session.unwrap();
            let user = auth_response.user;

            let jar = jar.add(
                Cookie::build(("session_id", session.id.to_string()))
                    .path("/")
                    .http_only(true),
            );

            (jar, Json(user)).into_response()
        }
        _ => (StatusCode::BAD_REQUEST, "Failed to complete registration").into_response(),
    }
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
            .storage()
            .get_session(&SessionId::new(&session_id))
            .await
            .unwrap();

        if let Some(session) = session {
            let user = state
                .plugin_manager
                .storage()
                .get_user(&session.user_id)
                .await
                .unwrap();
            return Json(user).into_response();
        }
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
async fn verify_session<B>(
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
        if let Ok(session) = state
            .plugin_manager
            .storage()
            .get_session(&SessionId::new(&session_id))
            .await
        {
            if session.is_some() {
                return next.run(request).await;
            }
        }
    }

    // If session is invalid or missing, redirect to sign in
    Redirect::to("/sign-in").into_response()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let pool = Pool::<Sqlite>::connect("sqlite:./passkey.db?mode=rwc")
        .await
        .unwrap();

    let user_storage = Arc::new(SqliteStorage::new(pool.clone()));
    let session_storage = Arc::new(SqliteStorage::new(pool.clone()));

    user_storage.migrate().await.unwrap();
    session_storage.migrate().await.unwrap();

    let storage = Storage::new(user_storage.clone(), session_storage.clone());

    let mut plugin_manager = PluginManager::new(user_storage.clone(), session_storage.clone());
    plugin_manager.register_auth_plugin(PasskeyPlugin::new(
        &"localhost",
        &"http://localhost:4000",
        storage,
    ));

    let app_state = AppState {
        plugin_manager: Arc::new(plugin_manager),
    };

    let app = Router::new()
        .route("/whoami", get(whoami_handler))
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            verify_session::<Body>,
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

                    <script>
                        async function beginRegistration() {
                        const email = document.getElementById('email').value;
                        
                        // Start registration flow
                        const response = await fetch('/auth/passkey/begin-registration', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({ email })
                        });

                        if (!response.ok) {
                            console.error('Failed to begin registration');
                            return;
                        }

                        
                        const challenge = await response.json();
                        /* 
                        NOTE: The server returns a base64 encoded challenge but the WebAuthn API expects an ArrayBuffer. Using atob() doesn't work 
                        because no one can agree on what base64 standard to use.

                        Your mileage may vary and you may need to do something different.
                        */
                        const opts = PublicKeyCredential.parseCreationOptionsFromJSON(challenge.publicKey);
                        console.log(opts);
                        
                        // Create credentials using WebAuthn API
                        const credential = await navigator.credentials.create({
                            publicKey: opts
                        });

                        console.log(credential);

                        // Complete registration
                        const result = await fetch('/auth/passkey/finish-registration', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                email,
                                challenge_response: credential
                            })
                        });

                        if (!result.ok) {
                            console.error('Failed to complete registration');
                            return;
                        }

                        window.location.href = '/whoami';
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
