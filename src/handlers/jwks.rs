use axum::Json;
use axum::extract::State;
use serde_json::Value;

use crate::state::AppState;

pub async fn jwks(State(state): State<AppState>) -> Json<Value> {
    Json(state.keys.jwks_document())
}
