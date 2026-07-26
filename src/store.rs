use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::util::random_token;

const CODE_TTL: Duration = Duration::from_secs(60);

pub struct AuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub sub: String,
    pub nonce: Option<String>,
    expires_at: Instant,
}

/// authorization codeのインメモリストア。Firestore等への永続化はスコープ外。
pub struct CodeStore {
    codes: Mutex<HashMap<String, AuthCode>>,
    ttl: Duration,
}

impl CodeStore {
    pub fn new() -> Self {
        Self::with_ttl(CODE_TTL)
    }

    /// TTLを外から指定できる非公開コンストラクタ。期限切れの実際の挙動をテストするために存在する
    /// (実時間で60秒待つテストは書けないため)。公開APIやnew()の挙動は変わらない。
    fn with_ttl(ttl: Duration) -> Self {
        CodeStore {
            codes: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    pub fn issue(&self, client_id: String, redirect_uri: String, scope: String, sub: String, nonce: Option<String>) -> String {
        let code = random_token(32);
        let entry = AuthCode {
            client_id,
            redirect_uri,
            scope,
            sub,
            nonce,
            expires_at: Instant::now() + self.ttl,
        };
        self.codes.lock().unwrap().insert(code.clone(), entry);
        code
    }

    /// 発行済みcodeを一度だけ使えるように取り出して削除する。期限切れは無効として扱う。
    pub fn consume(&self, code: &str) -> Option<AuthCode> {
        let mut codes = self.codes.lock().unwrap();
        let entry = codes.remove(code)?;
        if entry.expires_at < Instant::now() {
            return None;
        }
        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue_sample(store: &CodeStore) -> String {
        store.issue(
            "demo-client".to_string(),
            "http://localhost:8080/callback".to_string(),
            "openid".to_string(),
            "user-001".to_string(),
            Some("nonce-1".to_string()),
        )
    }

    #[test]
    fn consume_returns_issued_fields() {
        let store = CodeStore::new();
        let code = issue_sample(&store);
        let entry = store.consume(&code).expect("code should be valid");
        assert_eq!(entry.client_id, "demo-client");
        assert_eq!(entry.redirect_uri, "http://localhost:8080/callback");
        assert_eq!(entry.scope, "openid");
        assert_eq!(entry.sub, "user-001");
        assert_eq!(entry.nonce.as_deref(), Some("nonce-1"));
    }

    #[test]
    fn consume_is_single_use() {
        let store = CodeStore::new();
        let code = issue_sample(&store);
        assert!(store.consume(&code).is_some());
        assert!(store.consume(&code).is_none(), "reused code must be rejected");
    }

    #[test]
    fn consume_unknown_code_returns_none() {
        let store = CodeStore::new();
        assert!(store.consume("no-such-code").is_none());
    }

    #[test]
    fn consume_rejects_expired_code() {
        let store = CodeStore::with_ttl(Duration::from_millis(10));
        let code = issue_sample(&store);
        std::thread::sleep(Duration::from_millis(50));
        assert!(store.consume(&code).is_none(), "expired code must be rejected");
    }
}
