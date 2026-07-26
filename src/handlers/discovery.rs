use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};

use crate::state::AppState;

pub async fn discovery(State(state): State<AppState>) -> Json<Value> {
    let issuer = &state.config.issuer;
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat"],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientConfig, Config};
    use crate::keys::SigningKeys;
    use crate::store::CodeStore;
    use std::sync::Arc;

    #[tokio::test]
    async fn endpoints_are_derived_from_issuer() {
        let state = AppState {
            config: Arc::new(Config {
                issuer: "https://idp.example".to_string(),
                client: ClientConfig {
                    client_id: "demo-client".to_string(),
                    client_secret: "demo-secret".to_string(),
                    redirect_uris: vec![],
                },
            }),
            codes: Arc::new(CodeStore::new()),
            keys: Arc::new(SigningKeys::generate()),
        };
        let Json(doc) = discovery(State(state)).await;
        assert_eq!(doc["issuer"], "https://idp.example");
        assert_eq!(doc["authorization_endpoint"], "https://idp.example/authorize");
        assert_eq!(doc["token_endpoint"], "https://idp.example/token");
        assert_eq!(doc["jwks_uri"], "https://idp.example/.well-known/jwks.json");
    }
}
