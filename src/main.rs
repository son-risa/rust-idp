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

/// main()とテスト(実HTTPルーティングを通す統合テスト)の両方から使う共通のルーター構築。
fn build_router(state: AppState) -> Router {
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(handlers::discovery::discovery),
        )
        .route("/.well-known/jwks.json", get(handlers::jwks::jwks))
        .route("/authorize", get(handlers::authorize::authorize))
        .route("/token", post(handlers::token::token))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    let config = Config::load();
    let issuer = config.issuer.clone();

    let state = AppState {
        config: Arc::new(config),
        codes: Arc::new(CodeStore::new()),
        keys: Arc::new(SigningKeys::generate()),
    };

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("rust-idp listening on {issuer}");
    axum::serve(listener, app).await.unwrap();
}
