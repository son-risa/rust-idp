//! 保存先を SQLite の file 1 つにする（feature `sqlite`）。DB サーバを立てずに 1 台で動かすため。
//!
//! SQLite で書くのは [`DocumentStore`] だけ。[`Store`](crate::Store) と [`CibaStore`](crate::CibaStore) は、
//! Firestore でも使っている「DocumentStore の上の実装」をそのまま載せる。
//! 1 つの process だけが file を開く前提で、Connection は 1 本を Mutex で守る。

use crate::document_store::{DocumentStore, merge, version_str};
use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::Value;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

/// SQLite の file の [`DocumentStore`]。表は `docs`（集まり・id・JSON の fields・版）の 1 つ。
///
/// 版は [`MemoryDocumentStore`](crate::MemoryDocumentStore) と同じく、書くたびに 1 つ進む通しの番号
/// （`v{n}`）。番号は `version_seq` に置くので、消して作り直した文書や、開き直した後にも同じ番号は出ない。
pub struct SqliteDocumentStore {
    conn: Mutex<Connection>,
    /// 試験の file を置いた一時 directory。Connection を閉じた後に消す（field は書いた順に drop される）。
    #[cfg(test)]
    temp_dir: Option<tempfile::TempDir>,
}

fn err(op: &'static str) -> impl Fn(rusqlite::Error) -> String {
    move |e| format!("sqlite {op}: {e}")
}

fn to_json(fields: &Value) -> String {
    fields.to_string()
}

fn from_json(text: &str) -> Result<Value, String> {
    serde_json::from_str(text).map_err(|e| format!("sqlite: broken fields: {e}"))
}

/// `v{n}` の n。形が違えばどの版とも一致しない。
fn parse_version(update_time: &str) -> Option<i64> {
    update_time.strip_prefix('v')?.parse().ok()
}

/// `$."field".key` の JSON path。field は呼び手が決めた名（外から来た値ではない）。
fn path(field: &str, key: &str) -> String {
    format!("$.\"{field}\".{key}")
}

fn next_version(tx: &Transaction) -> Result<i64, String> {
    tx.query_row(
        "UPDATE version_seq SET last = last + 1 WHERE only = 1 RETURNING last",
        [],
        |r| r.get(0),
    )
    .map_err(err("next_version"))
}

fn put(tx: &Transaction, col: &str, id: &str, fields: &Value) -> Result<(), String> {
    let v = next_version(tx)?;
    tx.execute(
        "INSERT INTO docs (col, id, fields, version) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (col, id) DO UPDATE SET fields = excluded.fields, version = excluded.version",
        params![col, id, to_json(fields), v],
    )
    .map_err(err("put"))?;
    Ok(())
}

fn get(tx: &Transaction, col: &str, id: &str) -> Result<Option<Value>, String> {
    tx.query_row(
        "SELECT fields FROM docs WHERE col = ?1 AND id = ?2",
        params![col, id],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .map_err(err("get"))?
    .map(|t| from_json(&t))
    .transpose()
}

impl SqliteDocumentStore {
    /// `path` の file を開く（無ければ作る）。WAL と `synchronous=FULL` にし、表が無ければ作る。
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(err("open"))?;
        let mode: String = conn
            .pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))
            .map_err(err("journal_mode"))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(format!("sqlite: journal_mode stayed {mode}"));
        }
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(err("synchronous"))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS docs (
                 col TEXT NOT NULL,
                 id TEXT NOT NULL,
                 fields TEXT NOT NULL,
                 version INTEGER NOT NULL,
                 PRIMARY KEY (col, id)
             );
             CREATE TABLE IF NOT EXISTS version_seq (
                 only INTEGER PRIMARY KEY CHECK (only = 1),
                 last INTEGER NOT NULL
             );
             INSERT OR IGNORE INTO version_seq (only, last) VALUES (1, 0);",
        )
        .map_err(err("schema"))?;
        Ok(Self {
            conn: Mutex::new(conn),
            #[cfg(test)]
            temp_dir: None,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 1 つの transaction の中で `f` を走らせ、Ok なら commit する。
    fn write<T>(&self, f: impl FnOnce(&Transaction) -> Result<T, String>) -> Result<T, String> {
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(err("begin"))?;
        let out = f(&tx)?;
        tx.commit().map_err(err("commit"))?;
        Ok(out)
    }

    fn rows(
        &self,
        sql: &str,
        args: impl rusqlite::Params,
    ) -> Result<Vec<(String, Value, i64)>, String> {
        let conn = self.lock();
        let mut stmt = conn.prepare_cached(sql).map_err(err("prepare"))?;
        let raw = stmt
            .query_map(args, |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })
            .map_err(err("query"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err("row"))?;
        raw.into_iter()
            .map(|(id, f, v)| Ok((id, from_json(&f)?, v)))
            .collect()
    }
}

#[async_trait]
impl DocumentStore for SqliteDocumentStore {
    async fn set_doc(&self, col: &str, id: &str, fields: Value) -> Result<(), String> {
        self.write(|tx| put(tx, col, id, &fields))
    }

    async fn update_field(
        &self,
        col: &str,
        id: &str,
        field: &str,
        value: Value,
    ) -> Result<(), String> {
        self.update_fields(col, id, serde_json::json!({ field: value }))
            .await
    }

    async fn update_fields(&self, col: &str, id: &str, fields: Value) -> Result<(), String> {
        self.write(|tx| {
            let Some(base) = get(tx, col, id)? else {
                return Err(format!("update_fields {col}: not found"));
            };
            put(tx, col, id, &merge(Some(base), &fields, &[]))
        })
    }

    async fn merge_fields(
        &self,
        col: &str,
        id: &str,
        fields: Value,
        remove: &[String],
    ) -> Result<(), String> {
        self.write(|tx| {
            let base = get(tx, col, id)?;
            put(tx, col, id, &merge(base, &fields, remove))
        })
    }

    async fn get_doc(&self, col: &str, id: &str) -> Result<Option<Value>, String> {
        Ok(self
            .get_doc_with_update_time(col, id)
            .await?
            .map(|(f, _)| f))
    }

    async fn get_doc_with_update_time(
        &self,
        col: &str,
        id: &str,
    ) -> Result<Option<(Value, String)>, String> {
        let row = self
            .lock()
            .query_row(
                "SELECT fields, version FROM docs WHERE col = ?1 AND id = ?2",
                params![col, id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(err("get_doc"))?;
        row.map(|(f, v)| Ok((from_json(&f)?, version_str(v as u64))))
            .transpose()
    }

    async fn set_doc_if_unchanged(
        &self,
        col: &str,
        id: &str,
        fields: Value,
        update_time: &str,
    ) -> Result<bool, String> {
        let Some(expected) = parse_version(update_time) else {
            return Ok(false);
        };
        self.write(|tx| {
            let v = next_version(tx)?;
            let n = tx
                .execute(
                    "UPDATE docs SET fields = ?1, version = ?2
                     WHERE col = ?3 AND id = ?4 AND version = ?5",
                    params![to_json(&fields), v, col, id, expected],
                )
                .map_err(err("set_doc_if_unchanged"))?;
            Ok(n == 1)
        })
    }

    async fn create_if_absent(&self, col: &str, id: &str, fields: Value) -> Result<bool, String> {
        self.write(|tx| {
            let v = next_version(tx)?;
            let n = tx
                .execute(
                    "INSERT INTO docs (col, id, fields, version) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT (col, id) DO NOTHING",
                    params![col, id, to_json(&fields), v],
                )
                .map_err(err("create_if_absent"))?;
            Ok(n == 1)
        })
    }

    async fn delete_doc_if_unchanged(
        &self,
        col: &str,
        id: &str,
        update_time: &str,
    ) -> Result<bool, String> {
        let Some(expected) = parse_version(update_time) else {
            return Ok(false);
        };
        let n = self
            .lock()
            .execute(
                "DELETE FROM docs WHERE col = ?1 AND id = ?2 AND version = ?3",
                params![col, id, expected],
            )
            .map_err(err("delete_doc_if_unchanged"))?;
        Ok(n == 1)
    }

    async fn take_doc(&self, col: &str, id: &str) -> Result<Option<Value>, String> {
        self.lock()
            .query_row(
                "DELETE FROM docs WHERE col = ?1 AND id = ?2 RETURNING fields",
                params![col, id],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(err("take_doc"))?
            .map(|t| from_json(&t))
            .transpose()
    }

    async fn query_eq(
        &self,
        col: &str,
        field: &str,
        value: &str,
    ) -> Result<Vec<(String, Value)>, String> {
        let rows = self.rows(
            "SELECT id, fields, version FROM docs
             WHERE col = ?1 AND json_type(fields, ?2) = 'text' AND json_extract(fields, ?2) = ?3
             ORDER BY id",
            params![col, path(field, "stringValue"), value],
        )?;
        Ok(rows.into_iter().map(|(id, f, _)| (id, f)).collect())
    }

    async fn list_recent_ordered(
        &self,
        col: &str,
        order_field: &str,
        limit: u32,
    ) -> Result<Vec<(String, Value)>, String> {
        // MemoryDocumentStore の sort_key と同じ key: timestampValue が在ればそれ（文字列でなければ ""）、
        // 無ければ stringValue（文字列でなければ ""）。
        let rows = self.rows(
            "SELECT id, fields, version FROM docs WHERE col = ?1
             ORDER BY CASE
                 WHEN json_type(fields, ?2) = 'text' THEN json_extract(fields, ?2)
                 WHEN json_type(fields, ?2) IS NOT NULL THEN ''
                 WHEN json_type(fields, ?3) = 'text' THEN json_extract(fields, ?3)
                 ELSE ''
             END DESC, id DESC
             LIMIT ?4",
            params![
                col,
                path(order_field, "timestampValue"),
                path(order_field, "stringValue"),
                limit
            ],
        )?;
        Ok(rows.into_iter().map(|(id, f, _)| (id, f)).collect())
    }

    async fn list_collection(&self, col: &str) -> Result<Vec<(String, Value, String)>, String> {
        let rows = self.rows(
            "SELECT id, fields, version FROM docs WHERE col = ?1 ORDER BY id",
            params![col],
        )?;
        Ok(rows
            .into_iter()
            .map(|(id, f, v)| (id, f, version_str(v as u64)))
            .collect())
    }

    async fn delete_doc(&self, col: &str, id: &str) -> Result<(), String> {
        self.lock()
            .execute(
                "DELETE FROM docs WHERE col = ?1 AND id = ?2",
                params![col, id],
            )
            .map_err(err("delete_doc"))?;
        Ok(())
    }
}

/// `provider` の文書・セッションとトークン・CIBA の保存先を、`path` の SQLite の file 1 つに向ける。
pub fn configure(
    provider: crate::Provider,
    path: impl AsRef<Path>,
) -> Result<crate::Provider, String> {
    let docs: Arc<dyn DocumentStore> = Arc::new(SqliteDocumentStore::open(path)?);
    Ok(provider
        .with_document_store(docs.clone())
        .with_store(Arc::new(crate::firestore_store::FirestoreStore::new(
            docs.clone(),
        )))
        .with_ciba(Arc::new(crate::ciba::FirestoreCibaStore::new(docs))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 一時 directory の中の新しい file を開く。directory は保存先と一緒に消える。
    fn open() -> SqliteDocumentStore {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = SqliteDocumentStore::open(dir.path().join("idp.sqlite")).unwrap();
        store.temp_dir = Some(dir);
        store
    }

    mod documents {
        async fn store() -> super::SqliteDocumentStore {
            super::open()
        }
        crate::document_store_contract::document_store_contract_tests!(store);
    }

    mod store {
        async fn store() -> crate::firestore_store::FirestoreStore {
            crate::firestore_store::FirestoreStore::new(std::sync::Arc::new(super::open()))
        }
        crate::store_contract::store_contract_tests!(store);
    }

    mod ciba {
        async fn store() -> crate::ciba::FirestoreCibaStore {
            crate::ciba::FirestoreCibaStore::new(std::sync::Arc::new(super::open()))
        }
        crate::ciba_store_contract::ciba_store_contract_tests!(store);
    }

    /// query_eq と list_recent_ordered は、MemoryDocumentStore と同じ文書を同じ順で返す。契約の試験は
    /// 並びを問わない（Firestore は順を決めない）ので、ここで Memory と突き合わせる。
    /// 並べの key が崩れた文書（時刻が数・null、stringValue だけ、field が無い）も混ぜる。
    #[tokio::test]
    async fn queries_return_the_same_rows_in_the_same_order_as_memory() {
        use crate::firestore::{s, ts};
        let sqlite = open();
        let memory = crate::MemoryDocumentStore::default();
        let docs = [
            (
                "3",
                json!({ "who": s("a"), "at": ts("2026-01-02T00:00:00Z") }),
            ),
            (
                "1",
                json!({ "who": s("a"), "at": s("2026-01-03T00:00:00Z") }),
            ),
            (
                "5",
                json!({ "who": s("b"), "at": ts("2026-01-02T00:00:00Z") }),
            ),
            ("2", json!({ "who": s("a"), "at": { "timestampValue": 5 } })),
            ("7", json!({ "who": { "stringValue": 1 }, "at": null })),
            (
                "4",
                json!({ "who": s("a"), "at": { "timestampValue": null, "stringValue": "z" } }),
            ),
            ("6", json!({ "who": s("a") })),
        ];
        for (id, f) in docs {
            sqlite.set_doc("log", id, f.clone()).await.unwrap();
            memory.set_doc("log", id, f).await.unwrap();
        }
        for who in ["a", "b", "1"] {
            assert_eq!(
                sqlite.query_eq("log", "who", who).await.unwrap(),
                memory.query_eq("log", "who", who).await.unwrap(),
                "query_eq who={who}"
            );
        }
        for limit in [2, 10] {
            assert_eq!(
                sqlite
                    .list_recent_ordered("log", "at", limit)
                    .await
                    .unwrap(),
                memory
                    .list_recent_ordered("log", "at", limit)
                    .await
                    .unwrap(),
                "list_recent_ordered limit={limit}"
            );
        }
    }

    /// Connection を作り直しても中身と版が残る。開き直す前の版で前提条件つきの書き込みができ、
    /// 開き直した後の書き込みは、前の版の番号を使い回さない。
    #[tokio::test]
    async fn reopening_the_file_keeps_docs_and_versions() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("idp.sqlite");
        let first = SqliteDocumentStore::open(&file).unwrap();
        first
            .set_doc("c", "a", json!({ "n": crate::firestore::int(1) }))
            .await
            .unwrap();
        let (_, before) = first
            .get_doc_with_update_time("c", "a")
            .await
            .unwrap()
            .unwrap();
        drop(first);

        let second = SqliteDocumentStore::open(&file).unwrap();
        assert_eq!(
            second.get_doc_with_update_time("c", "a").await.unwrap(),
            Some((json!({ "n": crate::firestore::int(1) }), before.clone()))
        );
        assert!(
            second
                .set_doc_if_unchanged("c", "a", json!({ "n": crate::firestore::int(2) }), &before)
                .await
                .unwrap()
        );
        let (_, after) = second
            .get_doc_with_update_time("c", "a")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(after, before);
        assert!(
            !second
                .set_doc_if_unchanged("c", "a", json!({}), &before)
                .await
                .unwrap()
        );
    }
}
