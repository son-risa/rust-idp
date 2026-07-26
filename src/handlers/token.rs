use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::{Form, Json};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::TokenError;
use crate::keys::IdTokenClaims;
use crate::state::AppState;
use crate::util::random_token;

const TOKEN_TTL_SECS: usize = 3600;

#[derive(Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    client_secret: String,
}

pub async fn token(
    State(state): State<AppState>,
    Form(req): Form<TokenRequest>,
) -> Result<Json<Value>, TokenError> {
    if req.grant_type != "authorization_code" {
        return Err(TokenError::UnsupportedGrantType);
    }
    if req.client_id != state.config.client.client_id || req.client_secret != state.config.client.client_secret {
        return Err(TokenError::InvalidClient);
    }

    let auth_code = state.codes.consume(&req.code).ok_or(TokenError::InvalidGrant)?;
    if auth_code.client_id != req.client_id || auth_code.redirect_uri != req.redirect_uri {
        return Err(TokenError::InvalidGrant);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as usize;

    let claims = IdTokenClaims {
        iss: state.config.issuer.clone(),
        sub: auth_code.sub.clone(),
        aud: state.config.client.client_id.clone(),
        exp: now + TOKEN_TTL_SECS,
        iat: now,
        nonce: auth_code.nonce.clone(),
    };
    let id_token = state
        .keys
        .sign_id_token(&claims)
        .map_err(|_| TokenError::InvalidRequest("failed to sign id_token"))?;

    let access_token = random_token(32);

    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL_SECS,
        "id_token": id_token,
        "scope": auth_code.scope,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientConfig, Config};
    use crate::keys::SigningKeys;
    use crate::store::CodeStore;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use std::sync::Arc;

    const REDIRECT_URI: &str = "http://localhost:8080/callback";
    const CLIENT_ID: &str = "demo-client";
    const CLIENT_SECRET: &str = "demo-secret";

    fn test_state() -> AppState {
        AppState {
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
        }
    }

    fn issue_code(state: &AppState) -> String {
        state.codes.issue(
            CLIENT_ID.to_string(),
            REDIRECT_URI.to_string(),
            "openid".to_string(),
            "user-001".to_string(),
            Some("nonce-1".to_string()),
        )
    }

    fn issue_code_without_nonce(state: &AppState) -> String {
        state.codes.issue(
            CLIENT_ID.to_string(),
            REDIRECT_URI.to_string(),
            "openid".to_string(),
            "user-001".to_string(),
            None,
        )
    }

    fn valid_request(code: String) -> TokenRequest {
        TokenRequest {
            grant_type: "authorization_code".to_string(),
            code,
            redirect_uri: REDIRECT_URI.to_string(),
            client_id: CLIENT_ID.to_string(),
            client_secret: CLIENT_SECRET.to_string(),
        }
    }

    fn status_of(err: TokenError) -> StatusCode {
        err.into_response().status()
    }

    #[tokio::test]
    async fn unsupported_grant_type_is_rejected() {
        let state = test_state();
        let code = issue_code(&state);
        let mut req = valid_request(code);
        req.grant_type = "client_credentials".to_string();
        let err = token(State(state), Form(req)).await.unwrap_err();
        assert_eq!(status_of(err), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn wrong_client_secret_is_rejected() {
        let state = test_state();
        let code = issue_code(&state);
        let mut req = valid_request(code);
        req.client_secret = "wrong".to_string();
        let err = token(State(state), Form(req)).await.unwrap_err();
        assert_eq!(status_of(err), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unknown_code_is_rejected() {
        let state = test_state();
        let req = valid_request("no-such-code".to_string());
        let err = token(State(state), Form(req)).await.unwrap_err();
        assert_eq!(status_of(err), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn code_cannot_be_reused() {
        let state = test_state();
        let code = issue_code(&state);
        let req = valid_request(code.clone());
        assert!(token(State(state.clone()), Form(req)).await.is_ok());

        let replay = valid_request(code);
        let err = token(State(state), Form(replay)).await.unwrap_err();
        assert_eq!(status_of(err), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn redirect_uri_mismatch_is_rejected() {
        let state = test_state();
        let code = issue_code(&state);
        let mut req = valid_request(code);
        req.redirect_uri = "http://localhost:8080/other".to_string();
        let err = token(State(state), Form(req)).await.unwrap_err();
        assert_eq!(status_of(err), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn valid_request_returns_id_token() {
        let state = test_state();
        let code = issue_code(&state);
        let req = valid_request(code);
        let Json(body) = token(State(state), Form(req)).await.unwrap();
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["scope"], "openid");
        let id_token = body["id_token"].as_str().unwrap();
        assert_eq!(id_token.split('.').count(), 3);
    }

    #[tokio::test]
    async fn id_token_omits_nonce_when_not_requested() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let state = test_state();
        let code = issue_code_without_nonce(&state);
        let req = valid_request(code);
        let Json(body) = token(State(state), Form(req)).await.unwrap();
        let id_token = body["id_token"].as_str().unwrap();
        let claims_b64 = id_token.split('.').nth(1).unwrap();
        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims_b64).unwrap()).unwrap();
        assert!(
            claims.get("nonce").is_none(),
            "nonce key must be omitted entirely, not just null: {claims:?}"
        );
    }
}
