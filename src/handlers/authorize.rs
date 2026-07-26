use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use serde_json::json;

use crate::state::AppState;

/// この段階ではログインUI/WebAuthnは実装せず、固定ユーザーに自動ログイン済み扱いとする。
const DUMMY_USER_SUB: &str = "user-001";

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    nonce: Option<String>,
}

pub async fn authorize(State(state): State<AppState>, Query(q): Query<AuthorizeQuery>) -> Response {
    // client_id/redirect_uriが信頼できないうちはredirectしない(オープンリダイレクタ防止)。
    if q.client_id != state.config.client.client_id {
        return bad_request("unauthorized_client", "unknown client_id");
    }
    if !state.config.client.redirect_uris.contains(&q.redirect_uri) {
        return bad_request("invalid_request", "redirect_uri is not registered for this client");
    }

    if q.response_type != "code" {
        return redirect_with_error(&q.redirect_uri, "unsupported_response_type", q.state.as_deref());
    }
    if !q.scope.split_whitespace().any(|s| s == "openid") {
        return redirect_with_error(&q.redirect_uri, "invalid_scope", q.state.as_deref());
    }

    let code = state.codes.issue(
        q.client_id.clone(),
        q.redirect_uri.clone(),
        q.scope.clone(),
        DUMMY_USER_SUB.to_string(),
        q.nonce.clone(),
    );

    let mut location = format!("{}?code={}", q.redirect_uri, urlencoding::encode(&code));
    if let Some(s) = &q.state {
        location.push_str(&format!("&state={}", urlencoding::encode(s)));
    }
    Redirect::to(&location).into_response()
}

fn bad_request(error: &'static str, description: &'static str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

fn redirect_with_error(redirect_uri: &str, error: &'static str, state: Option<&str>) -> Response {
    let mut location = format!("{redirect_uri}?error={error}");
    if let Some(s) = state {
        location.push_str(&format!("&state={}", urlencoding::encode(s)));
    }
    Redirect::to(&location).into_response()
}
