use std::sync::Arc;

use crate::config::Config;
use crate::keys::SigningKeys;
use crate::store::CodeStore;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub codes: Arc<CodeStore>,
    pub keys: Arc<SigningKeys>,
}
