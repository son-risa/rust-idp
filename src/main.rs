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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use config::ClientConfig;
    use serde_json::Value;
    use tower::ServiceExt;

    const REDIRECT_URI: &str = "http://localhost:8080/callback";
    const CLIENT_ID: &str = "demo-client";
    const CLIENT_SECRET: &str = "demo-secret";

    fn test_app() -> Router {
        let state = AppState {
            config: Arc::new(Config {
                issuer: "http://localhost:8080".to_string(),
                client: ClientConfig {
                    client_id: CLIENT_ID.to_string(),
                    client_secret: CLIENT_SECRET.to_string(),
                    redirect_uris: vec![REDIRECT_URI.to_string()],
                },
            }),
            codes: Arc::new(CodeStore::new()),
            keys: Arc::new(SigningKeys::generate()),
        };
        build_router(state)
    }

    async fn body_json(resp: axum::response::Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn discovery_route_is_wired() {
        let resp = test_app()
            .oneshot(Request::builder().uri("/.well-known/openid-configuration").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["issuer"], "http://localhost:8080");
    }

    #[tokio::test]
    async fn jwks_route_is_wired() {
        let resp = test_app()
            .oneshot(Request::builder().uri("/.well-known/jwks.json").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// authorize -> token を実HTTP(クエリ文字列/フォームエンコード)で通す統合テスト。
    /// ハンドラを直接呼ぶユニットテストと違い、axumのルーティング/extractor配線自体を検証する。
    #[tokio::test]
    async fn authorize_then_token_round_trip_over_http() {
        let app = test_app();

        let authorize_uri = format!(
            "/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={}&scope=openid&state=xyz",
            urlencoding::encode(REDIRECT_URI)
        );
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(authorize_uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
        let code = location
            .split('?')
            .nth(1)
            .unwrap()
            .split('&')
            .find_map(|kv| kv.strip_prefix("code="))
            .unwrap();

        let form_body = format!(
            "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={CLIENT_ID}&client_secret={CLIENT_SECRET}",
            urlencoding::encode(REDIRECT_URI)
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert!(body["id_token"].as_str().is_some());
    }
}
