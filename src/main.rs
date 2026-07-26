mod config;
mod error;
mod handlers;
mod keys;
mod state;
mod store;
mod util;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

use config::Config;
use keys::SigningKeys;
use state::AppState;
use store::CodeStore;

#[tokio::main]
async fn main() {
    let config = Config::load();
    let issuer = config.issuer.clone();

    let state = AppState {
        config: Arc::new(config),
        codes: Arc::new(CodeStore::new()),
        keys: Arc::new(SigningKeys::generate()),
    };

    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(handlers::discovery::discovery),
        )
        .route("/.well-known/jwks.json", get(handlers::jwks::jwks))
        .route("/authorize", get(handlers::authorize::authorize))
        .route("/token", post(handlers::token::token))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("rust-idp listening on {issuer}");
    axum::serve(listener, app).await.unwrap();
}
