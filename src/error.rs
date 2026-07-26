use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// RFC 6749 5.2 で定義されたtoken endpointのエラーコード。仕様上ほぼ閉じているためenumで表す。
pub enum TokenError {
    InvalidRequest(&'static str),
    InvalidClient,
    InvalidGrant,
    UnsupportedGrantType,
}

impl IntoResponse for TokenError {
    fn into_response(self) -> Response {
        let (status, error, description) = match self {
            TokenError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, "invalid_request", msg),
            TokenError::InvalidClient => (
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "client authentication failed",
            ),
            TokenError::InvalidGrant => (
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "authorization code is invalid, expired, or already used",
            ),
            TokenError::UnsupportedGrantType => (
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "only authorization_code is supported",
            ),
        };
        (
            status,
            Json(json!({ "error": error, "error_description": description })),
        )
            .into_response()
    }
}
