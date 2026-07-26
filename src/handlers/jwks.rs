use axum::Json;
use axum::extract::State;
use serde_json::Value;

use crate::state::AppState;

pub async fn jwks(State(state): State<AppState>) -> Json<Value> {
    Json(state.keys.jwks_document())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientConfig, Config};
    use crate::keys::SigningKeys;
    use crate::store::CodeStore;
    use std::sync::Arc;

    #[tokio::test]
    async fn jwks_exposes_one_rsa_key() {
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
        let Json(doc) = jwks(State(state)).await;
        let keys = doc["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "RSA");
        assert_eq!(keys[0]["alg"], "RS256");
        assert!(keys[0]["n"].as_str().is_some());
        assert!(keys[0]["e"].as_str().is_some());
    }
}
