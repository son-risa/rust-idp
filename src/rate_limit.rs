//! 回数の上限（滑る窓）。数は [`DocumentStore`] に置くので、同じ保存先を使う台が何台あっても上限は全体で 1 つ。
//!
//! 文書は `rateLimits/{名前}-{hash}`。hash は (scope, key) の SHA-256 で、IP やアドレスを文書の id にも中身にも残さない。
//! ただし `LOG_PSEUDONYM_KEY` が無いと hash に秘密が混ざらないので、候補の IP・アドレスを総当たりすれば hash から戻せる。
//! 中身は窓の中で通した時刻（ミリ秒）の並び `hits` と、最後に通した時刻に窓を足した `expireAt`。
//! Firestore は `expireAt` の TTL ポリシーで消し、Memory・SQLite は定期の掃除（`DocumentStore::sweep_expired`）で消す。

use crate::document_store::DocumentStore;
use crate::firestore;
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const COLLECTION: &str = "rateLimits";

/// 前提条件つきの書き込みがほかの台に負けたときに、読み直す回数。
const CAS_ATTEMPTS: usize = 5;

pub struct RateLimiter {
    /// 文書の id の頭。上限の違う limiter が同じ (scope, key) で数を混ぜないように分ける。
    name: &'static str,
    window: Duration,
    max: usize,
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn parse_hits(fields: &serde_json::Value) -> Vec<u64> {
    firestore::field_str(fields, "hits")
        .unwrap_or("")
        .split_whitespace()
        .filter_map(|t| t.parse().ok())
        .collect()
}

impl RateLimiter {
    pub fn new(name: &'static str, window: Duration, max: usize) -> Self {
        Self { name, window, max }
    }

    /// `LOG_PSEUDONYM_KEY` があれば混ぜる（ログの擬似化 `pseudonymize_sub` と同じ）。
    fn doc_id(&self, scope: &str, key: &str) -> String {
        let salt = std::env::var("LOG_PSEUDONYM_KEY").unwrap_or_default();
        let digest = Sha256::digest(format!("{salt}\0{scope}\0{key}").as_bytes());
        format!("{}-{}", self.name, crate::es256::b64url_encode(digest))
    }

    fn fields(&self, hits: &[u64]) -> serde_json::Value {
        // 台ごとの時計がずれると並びの最後が最新とは限らないので、最大から付ける。
        let latest = hits.iter().copied().max().unwrap_or(0);
        let expire_secs = (latest + self.window.as_millis() as u64).div_ceil(1000);
        let hits = hits
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        serde_json::json!({
            "hits": firestore::s(&hits),
            "expireAt": firestore::ts(&firestore::rfc3339(expire_secs)),
        })
    }

    /// 窓の中で通した数が上限より少なければ、今を数に足して Ok(true)。上限なら Ok(false)。
    /// 保存先が答えなければ Err で、呼ぶ側は通さない（数えられないまま通すと、障害の間は上限が無くなる）。
    /// ほかの台との書き込みの競り合いに続けて負けたときも、同じ key への連発なので Ok(false) で断る。
    pub async fn check_and_record(
        &self,
        docs: &dyn DocumentStore,
        scope: &str,
        key: &str,
    ) -> Result<bool, String> {
        let id = self.doc_id(scope, key);
        for _ in 0..CAS_ATTEMPTS {
            let now = now_millis();
            let since = now.saturating_sub(self.window.as_millis() as u64);
            let written = match docs.get_doc_with_update_time(COLLECTION, &id).await? {
                None => {
                    docs.create_if_absent(COLLECTION, &id, self.fields(&[now]))
                        .await?
                }
                Some((f, update_time)) => {
                    let mut hits: Vec<u64> =
                        parse_hits(&f).into_iter().filter(|&t| t >= since).collect();
                    if hits.len() >= self.max {
                        return Ok(false);
                    }
                    hits.push(now);
                    docs.set_doc_if_unchanged(COLLECTION, &id, self.fields(&hits), &update_time)
                        .await?
                }
            };
            if written {
                return Ok(true);
            }
        }
        tracing::warn!(
            "rate limit {}: lost the write {CAS_ATTEMPTS} times",
            self.name
        );
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document_store::MemoryDocumentStore;

    #[tokio::test]
    async fn admits_then_blocks_within_window() {
        let docs = MemoryDocumentStore::default();
        let rl = RateLimiter::new("t", Duration::from_secs(60), 3);
        for _ in 0..3 {
            assert!(rl.check_and_record(&docs, "rp", "u").await.unwrap());
        }
        assert!(!rl.check_and_record(&docs, "rp", "u").await.unwrap());
        // 別の scope・別の key は独立
        assert!(rl.check_and_record(&docs, "rp2", "u").await.unwrap());
        assert!(rl.check_and_record(&docs, "rp", "v").await.unwrap());
        // 名前の違う limiter とも数を混ぜない
        let other = RateLimiter::new("o", Duration::from_secs(60), 3);
        assert!(other.check_and_record(&docs, "rp", "u").await.unwrap());
    }

    /// ほかの台との書き込みの競り合いに続けて負けたら、通さない。
    #[tokio::test]
    async fn losing_every_write_refuses() {
        let docs = crate::document_store::FailingDocs::always_losing();
        let rl = RateLimiter::new("t", Duration::from_secs(60), 3);
        assert!(!rl.check_and_record(&docs, "rp", "u").await.unwrap());
    }

    /// 時計のずれで並びの最後が最新でなくても、expireAt は最新の時刻から窓の分だけ先。
    #[test]
    fn expire_at_follows_the_latest_hit() {
        let rl = RateLimiter::new("t", Duration::from_secs(60), 3);
        let f = rl.fields(&[90_000, 10_000]);
        assert_eq!(firestore::field_ts_secs(&f, "expireAt"), Some(150));
    }

    #[tokio::test]
    async fn recovers_after_window() {
        let docs = MemoryDocumentStore::default();
        let rl = RateLimiter::new("t", Duration::from_millis(50), 2);
        assert!(rl.check_and_record(&docs, "rp", "u").await.unwrap());
        assert!(rl.check_and_record(&docs, "rp", "u").await.unwrap());
        assert!(!rl.check_and_record(&docs, "rp", "u").await.unwrap());
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert!(rl.check_and_record(&docs, "rp", "u").await.unwrap());
    }

    /// 窓は滑る: 窓の途中で通した分は、その時刻から窓が経つまで数に残る（固定の窓の境目で 2 倍通ることはない）。
    #[tokio::test]
    async fn the_window_slides_from_each_hit() {
        let docs = MemoryDocumentStore::default();
        let rl = RateLimiter::new("t", Duration::from_millis(200), 2);
        assert!(rl.check_and_record(&docs, "s", "k").await.unwrap());
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(rl.check_and_record(&docs, "s", "k").await.unwrap());
        tokio::time::sleep(Duration::from_millis(120)).await;
        // 1 つ目は窓を出たが、2 つ目はまだ窓の中
        assert!(rl.check_and_record(&docs, "s", "k").await.unwrap());
        assert!(!rl.check_and_record(&docs, "s", "k").await.unwrap());
    }

    /// 文書の id にも中身にも、scope と key をそのまま残さない。
    #[tokio::test]
    async fn the_document_holds_neither_the_address_nor_the_ip() {
        let docs = MemoryDocumentStore::default();
        let rl = RateLimiter::new("register", Duration::from_secs(60), 5);
        rl.check_and_record(&docs, "email", "alice@example.com")
            .await
            .unwrap();
        rl.check_and_record(&docs, "ip", "192.0.2.7").await.unwrap();
        let rows = docs.list_collection(COLLECTION).await.unwrap();
        assert_eq!(rows.len(), 2);
        for (id, f, _) in rows {
            let all = format!("{id} {f}");
            assert!(
                !all.contains("alice") && !all.contains("192.0.2.7"),
                "{all}"
            );
            assert!(id.starts_with("register-"), "{id}");
        }
    }

    /// 同じ key に同時に来ても、通るのは上限の数だけ（前提条件つきの書き込みで 1 ずつ足す）。
    async fn concurrent_hits_never_pass_more_than_the_limit(
        docs: std::sync::Arc<dyn DocumentStore>,
    ) {
        let rl = std::sync::Arc::new(RateLimiter::new("t", Duration::from_secs(60), 3));
        let start = std::sync::Arc::new(tokio::sync::Barrier::new(20));
        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let (docs, rl, start) = (docs.clone(), rl.clone(), start.clone());
                tokio::spawn(async move {
                    start.wait().await;
                    rl.check_and_record(&*docs, "s", "k").await.unwrap()
                })
            })
            .collect();
        let mut passed = 0;
        for t in tasks {
            passed += t.await.unwrap() as usize;
        }
        assert!((1..=3).contains(&passed), "{passed} 回通った");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_hits_in_memory_never_pass_more_than_the_limit() {
        concurrent_hits_never_pass_more_than_the_limit(std::sync::Arc::new(
            MemoryDocumentStore::default(),
        ))
        .await;
    }

    /// 読みと書きの間で await が挟まる保存先（fake Firestore）で、競り合いを起こす。
    #[cfg(feature = "gcp")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_hits_in_firestore_never_pass_more_than_the_limit() {
        let (host, _state) = crate::firestore::fake_firestore::spawn().await;
        concurrent_hits_never_pass_more_than_the_limit(std::sync::Arc::new(
            crate::firestore::Firestore::new_for_test("proj", host),
        ))
        .await;
    }

    /// 定期の掃除（MemoryStore の sweep_expired が登録の保存先にも掛ける）は、窓の過ぎた数の文書だけを消す。
    /// SQLite の掃除は sqlite.rs の試験が、同じ expireAt で確かめている。
    #[tokio::test]
    async fn sweeping_drops_only_documents_whose_window_has_passed() {
        use crate::store::Store;
        let docs = std::sync::Arc::new(MemoryDocumentStore::default());
        let store = crate::store::MemoryStore::with_documents(docs.clone());
        let short = RateLimiter::new("s", Duration::from_millis(1), 2);
        let long = RateLimiter::new("l", Duration::from_secs(3600), 2);
        short.check_and_record(&*docs, "ip", "old").await.unwrap();
        long.check_and_record(&*docs, "ip", "new").await.unwrap();
        // expireAt は秒で切り上げるので、秒が変わるのを待つ
        tokio::time::sleep(Duration::from_millis(2100)).await;
        store.sweep_expired().await;
        let ids: Vec<String> = docs
            .list_collection(COLLECTION)
            .await
            .unwrap()
            .into_iter()
            .map(|(id, _, _)| id)
            .collect();
        assert_eq!(ids, vec![long.doc_id("ip", "new")]);
    }

    /// 保存先が答えないときは、通さない。
    #[tokio::test]
    async fn a_failing_store_lets_nothing_through() {
        let rl = RateLimiter::new("t", Duration::from_secs(60), 5);
        assert!(
            rl.check_and_record(&crate::document_store::FailingDocs::all(), "s", "k")
                .await
                .is_err()
        );
    }
}
