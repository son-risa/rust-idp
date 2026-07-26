use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// RFC 6749 5.2 で定義されたtoken endpointのエラーコード。仕様上ほぼ閉じているためenumで表す。
#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn error_body(err: TokenError) -> (StatusCode, serde_json::Value) {
        let resp = err.into_response();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn invalid_request_maps_to_400() {
        let (status, body) = error_body(TokenError::InvalidRequest("failed to sign id_token")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_request");
        assert_eq!(body["error_description"], "failed to sign id_token");
    }

    #[tokio::test]
    async fn invalid_client_maps_to_401() {
        let (status, body) = error_body(TokenError::InvalidClient).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid_client");
    }

    #[tokio::test]
    async fn invalid_grant_maps_to_400() {
        let (status, body) = error_body(TokenError::InvalidGrant).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn unsupported_grant_type_maps_to_400() {
        let (status, body) = error_body(TokenError::UnsupportedGrantType).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "unsupported_grant_type");
    }
}
