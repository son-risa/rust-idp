//! FIDO2 の適合試験の道（/fido/*）は、FIDO_CONFORMANCE_ENABLED を 1 か true にしたときだけ在る。
//!
//! router() は環境変数を読むので、ほかの試験と同じ process で変数を書き換えると取り合いになる。
//! 試験の binary を分け、この 1 本だけで順に書き換える。

use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

async fn fido_status(setting: Option<&str>) -> StatusCode {
    // SAFETY: この binary の試験はこの 1 本だけで、ほかの thread は環境変数を読み書きしない。
    unsafe {
        match setting {
            Some(v) => std::env::set_var("FIDO_CONFORMANCE_ENABLED", v),
            None => std::env::remove_var("FIDO_CONFORMANCE_ENABLED"),
        }
    }
    let app = rust_idp::router(rust_idp::Provider::new("https://op.example"));
    let req = Request::builder()
        .method("POST")
        .uri("/fido/attestation/options")
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from("{}"))
        .unwrap();
    app.oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn the_fido_conformance_routes_exist_only_when_enabled() {
    assert_eq!(fido_status(None).await, StatusCode::NOT_FOUND, "設定が無いのに在る");
    assert_eq!(fido_status(Some("0")).await, StatusCode::NOT_FOUND, "0 なのに在る");
    assert_ne!(fido_status(Some("1")).await, StatusCode::NOT_FOUND, "1 なのに無い");
    assert_ne!(fido_status(Some("true")).await, StatusCode::NOT_FOUND, "true なのに無い");
}
