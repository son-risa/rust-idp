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

