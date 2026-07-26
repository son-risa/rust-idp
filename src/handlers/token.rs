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
