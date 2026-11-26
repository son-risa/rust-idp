//! パスキーの登録とログイン・復旧・管理画面・PAR・DCR・CIBA の承認などが使う文書の保存先。
//!
//! [`Store`](crate::Store)（セッション・認可コード・トークン）や [`CibaStore`](crate::CibaStore) と違い、
//! こちらは「集まり（collection）の中の、id を持つ文書」を読み書きする低い段の操作だけを持つ。
//! 文書の中身は Firestore の REST の値の形（`{"stringValue": "..."}`・`{"timestampValue": "RFC3339"}`・
//! `{"booleanValue": true}`・`{"integerValue": "1"}`）で、上の段（アカウント・パスキー・招待など）が組み立てる。
//!
//! 実装は 3 つ。既定の [`MemoryDocumentStore`]（1 つの process の中だけ）と、`gcp` の feature の Firestore と、
//! `sqlite` の feature の SQLite の file（`crate::sqlite::SqliteDocumentStore`）。

use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Mutex;

/// 文書の保存先。誤りは文字列で返す（上の段はログに出して 500/503 にする）。
///
/// `update_time` は文書の版を表す不透明な文字列で、書くたびに変わる。前提条件つきの書き込み
/// （`*_if_unchanged`）に、読んだときの値をそのまま渡す。
#[async_trait]
pub trait DocumentStore: Send + Sync {
    /// 文書を丸ごと置き換える（無ければ作る）。
    async fn set_doc(&self, col: &str, id: &str, fields: Value) -> Result<(), String>;
    /// 1 つの field だけを書く。文書が無ければ誤り。
    async fn update_field(
        &self,
        col: &str,
        id: &str,
        field: &str,
        value: Value,
    ) -> Result<(), String>;
    /// `fields` の各 key だけを書く。文書が無ければ誤り。
    async fn update_fields(&self, col: &str, id: &str, fields: Value) -> Result<(), String>;
    /// `fields` の各 key を書き、`remove` の field を消す。他の field は残す。文書が無ければ作る。
    async fn merge_fields(
        &self,
        col: &str,
        id: &str,
        fields: Value,
        remove: &[String],
    ) -> Result<(), String>;
    /// 文書の fields（無ければ None）。
    async fn get_doc(&self, col: &str, id: &str) -> Result<Option<Value>, String>;
    /// 文書の fields と update_time（無ければ None）。
    async fn get_doc_with_update_time(
        &self,
        col: &str,
        id: &str,
    ) -> Result<Option<(Value, String)>, String>;
    /// update_time が一致するときだけ丸ごと置き換える。負けたら Ok(false)。
    async fn set_doc_if_unchanged(
        &self,
        col: &str,
        id: &str,
        fields: Value,
        update_time: &str,
    ) -> Result<bool, String>;
    /// 文書が無いときだけ作る。既に在れば Ok(false)。
    async fn create_if_absent(&self, col: &str, id: &str, fields: Value) -> Result<bool, String>;
    /// update_time が一致するときだけ消す。負けたら（消えていたら）Ok(false)。
    async fn delete_doc_if_unchanged(
        &self,
        col: &str,
        id: &str,
        update_time: &str,
    ) -> Result<bool, String>;
    /// 文書を 1 度だけ取り出して消す。並んで呼ばれても Some を返すのは高々 1 回。
    async fn take_doc(&self, col: &str, id: &str) -> Result<Option<Value>, String>;
    /// 文字列の field が `value` に等しい文書の (id, fields)。
    async fn query_eq(
        &self,
        col: &str,
        field: &str,
        value: &str,
    ) -> Result<Vec<(String, Value)>, String>;
    /// `order_field`（時刻か文字列）の新しい順、同じなら id の大きい順に `limit` 件。
    async fn list_recent_ordered(
        &self,
        col: &str,
        order_field: &str,
        limit: u32,
    ) -> Result<Vec<(String, Value)>, String>;
    /// 集まりの全ての文書の (id, fields, update_time)。数十件の集まりにだけ使う。
    async fn list_collection(&self, col: &str) -> Result<Vec<(String, Value, String)>, String>;
    /// 文書を消す。無くても誤りにしない。
    async fn delete_doc(&self, col: &str, id: &str) -> Result<(), String>;
}

struct Doc {
    fields: Value,
    version: u64,
}

/// メモリ上の [`DocumentStore`]。process を止めると消え、複数の instance の間では分け合わない。
/// 前提条件つきの書き込みは 1 つの lock の中で確かめて書くので、1 つの process の中では Firestore と同じく単回になる。
#[derive(Default)]
pub struct MemoryDocumentStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    docs: HashMap<(String, String), Doc>,
    next_version: u64,
}

impl Inner {
    fn put(&mut self, col: &str, id: &str, fields: Value) {
        self.next_version += 1;
        let version = self.next_version;
        self.docs
            .insert((col.to_string(), id.to_string()), Doc { fields, version });
    }

    fn version_matches(&self, col: &str, id: &str, update_time: &str) -> bool {
        self.docs
            .get(&key(col, id))
            .is_some_and(|d| version_str(d.version) == update_time)
    }

    fn merged(&self, col: &str, id: &str, fields: &Value, remove: &[String]) -> Value {
        merge(
            self.docs.get(&key(col, id)).map(|d| d.fields.clone()),
            fields,
            remove,
        )
    }
}

/// 在る文書の fields（`base`）に `fields` の各 key を書き、`remove` を消したもの。無ければ空から。
pub(crate) fn merge(base: Option<Value>, fields: &Value, remove: &[String]) -> Value {
    let mut base = base.unwrap_or_else(|| json!({}));
    if let Some(obj) = base.as_object_mut() {
        for (k, v) in fields.as_object().into_iter().flatten() {
            obj.insert(k.clone(), v.clone());
        }
        for k in remove {
            obj.remove(k);
        }
    }
    base
}

fn key(col: &str, id: &str) -> (String, String) {
    (col.to_string(), id.to_string())
}

pub(crate) fn version_str(v: u64) -> String {
    format!("v{v}")
}

/// 並べ替えの key。時刻（RFC3339 は辞書順が時刻順）を先に見て、無ければ文字列。
fn sort_key(fields: &Value, field: &str) -> String {
    let Some(v) = fields.get(field) else {
        return String::new();
    };
    v.get("timestampValue")
        .or_else(|| v.get("stringValue"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

impl MemoryDocumentStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait]
impl DocumentStore for MemoryDocumentStore {
    async fn set_doc(&self, col: &str, id: &str, fields: Value) -> Result<(), String> {
        self.lock().put(col, id, fields);
        Ok(())
    }

    async fn update_field(
        &self,
        col: &str,
        id: &str,
        field: &str,
        value: Value,
    ) -> Result<(), String> {
        self.update_fields(col, id, json!({ field: value })).await
    }

    async fn update_fields(&self, col: &str, id: &str, fields: Value) -> Result<(), String> {
        let mut g = self.lock();
        if !g.docs.contains_key(&key(col, id)) {
            return Err(format!("update_fields {col}: not found"));
        }
        let merged = g.merged(col, id, &fields, &[]);
        g.put(col, id, merged);
        Ok(())
    }

    async fn merge_fields(
        &self,
        col: &str,
        id: &str,
        fields: Value,
        remove: &[String],
    ) -> Result<(), String> {
        let mut g = self.lock();
        let merged = g.merged(col, id, &fields, remove);
        g.put(col, id, merged);
        Ok(())
    }

    async fn get_doc(&self, col: &str, id: &str) -> Result<Option<Value>, String> {
        Ok(self
            .lock()
            .docs
            .get(&key(col, id))
            .map(|d| d.fields.clone()))
    }

    async fn get_doc_with_update_time(
        &self,
        col: &str,
        id: &str,
    ) -> Result<Option<(Value, String)>, String> {
        Ok(self
            .lock()
            .docs
            .get(&key(col, id))
            .map(|d| (d.fields.clone(), version_str(d.version))))
    }

    async fn set_doc_if_unchanged(
        &self,
        col: &str,
        id: &str,
        fields: Value,
        update_time: &str,
    ) -> Result<bool, String> {
        let mut g = self.lock();
        if !g.version_matches(col, id, update_time) {
            return Ok(false);
        }
        g.put(col, id, fields);
        Ok(true)
    }

    async fn create_if_absent(&self, col: &str, id: &str, fields: Value) -> Result<bool, String> {
        let mut g = self.lock();
        if g.docs.contains_key(&key(col, id)) {
            return Ok(false);
        }
        g.put(col, id, fields);
        Ok(true)
    }

    async fn delete_doc_if_unchanged(
        &self,
        col: &str,
        id: &str,
        update_time: &str,
    ) -> Result<bool, String> {
        let mut g = self.lock();
        if !g.version_matches(col, id, update_time) {
            return Ok(false);
        }
        g.docs.remove(&key(col, id));
        Ok(true)
    }

    async fn take_doc(&self, col: &str, id: &str) -> Result<Option<Value>, String> {
        Ok(self.lock().docs.remove(&key(col, id)).map(|d| d.fields))
    }

    async fn query_eq(
        &self,
        col: &str,
        field: &str,
        value: &str,
    ) -> Result<Vec<(String, Value)>, String> {
        let g = self.lock();
        let mut rows: Vec<(String, Value)> = g
            .docs
            .iter()
            .filter(|((c, _), d)| {
                c == col
                    && d.fields
                        .get(field)
                        .and_then(|v| v.get("stringValue"))
                        .and_then(Value::as_str)
                        == Some(value)
            })
            .map(|((_, id), d)| (id.clone(), d.fields.clone()))
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(rows)
    }

    async fn list_recent_ordered(
        &self,
        col: &str,
        order_field: &str,
        limit: u32,
    ) -> Result<Vec<(String, Value)>, String> {
        let g = self.lock();
        let mut rows: Vec<(String, Value)> = g
            .docs
            .iter()
            .filter(|((c, _), _)| c == col)
            .map(|((_, id), d)| (id.clone(), d.fields.clone()))
            .collect();
        rows.sort_by(|a, b| {
            sort_key(&b.1, order_field)
                .cmp(&sort_key(&a.1, order_field))
                .then_with(|| b.0.cmp(&a.0))
        });
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn list_collection(&self, col: &str) -> Result<Vec<(String, Value, String)>, String> {
        let g = self.lock();
        let mut rows: Vec<(String, Value, String)> = g
            .docs
            .iter()
            .filter(|((c, _), _)| c == col)
            .map(|((_, id), d)| (id.clone(), d.fields.clone(), version_str(d.version)))
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(rows)
    }

    async fn delete_doc(&self, col: &str, id: &str) -> Result<(), String> {
        self.lock().docs.remove(&key(col, id));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn memory() -> MemoryDocumentStore {
        MemoryDocumentStore::default()
    }

    crate::document_store_contract::document_store_contract_tests!(memory);
}
