//! [`DocumentStore`] の契約の試験。実装ごとに 1 度 [`document_store_contract_tests!`] を呼ぶと、
//! 同じ試験がその実装に当たる。実装を足すときは、その実装の試験の mod から同じ macro を呼ぶ。
//!
//! 実装に固有のこと（Firestore の頁送り・時間の上限・400 の扱いなど）は、それぞれの実装の側に置く。

use crate::document_store::DocumentStore;
use crate::firestore::{int, rfc3339, s, ts};
use serde_json::json;

fn ids<T>(rows: &[(String, T)]) -> Vec<&str> {
    rows.iter().map(|(id, _)| id.as_str()).collect()
}

/// 無いときだけ作り、2 度目は負けて中身を変えない。
pub(crate) async fn create_if_absent_wins_once(m: &dyn DocumentStore) {
    assert!(
        m.create_if_absent("c", "a", json!({ "v": int(1) }))
            .await
            .unwrap()
    );
    assert!(
        !m.create_if_absent("c", "a", json!({ "v": int(2) }))
            .await
            .unwrap()
    );
    assert_eq!(
        m.get_doc("c", "a").await.unwrap(),
        Some(json!({ "v": int(1) }))
    );
}

/// 読んだときの update_time が合えば置き換え、古ければ負けて中身を変えない。
pub(crate) async fn set_doc_if_unchanged_loses_on_a_stale_update_time(m: &dyn DocumentStore) {
    m.set_doc("c", "a", json!({ "v": int(1) })).await.unwrap();
    let (_, ut) = m.get_doc_with_update_time("c", "a").await.unwrap().unwrap();
    assert!(
        m.set_doc_if_unchanged("c", "a", json!({ "v": int(2) }), &ut)
            .await
            .unwrap()
    );
    assert!(
        !m.set_doc_if_unchanged("c", "a", json!({ "v": int(3) }), &ut)
            .await
            .unwrap()
    );
    assert_eq!(
        m.get_doc("c", "a").await.unwrap(),
        Some(json!({ "v": int(2) }))
    );
    assert!(
        !m.set_doc_if_unchanged("c", "none", json!({}), &ut)
            .await
            .unwrap(),
        "無い文書に書けた"
    );
}

/// 間に書き込みが入った後の古い update_time では消せず、新しい update_time なら消せる。
pub(crate) async fn delete_doc_if_unchanged_loses_on_a_stale_update_time(m: &dyn DocumentStore) {
    m.set_doc("c", "a", json!({ "v": int(1) })).await.unwrap();
    let (_, stale) = m.get_doc_with_update_time("c", "a").await.unwrap().unwrap();
    m.set_doc("c", "a", json!({ "v": int(2) })).await.unwrap();
    assert!(!m.delete_doc_if_unchanged("c", "a", &stale).await.unwrap());
    assert!(
        m.get_doc("c", "a").await.unwrap().is_some(),
        "負けた削除で消えた"
    );
    let (_, fresh) = m.get_doc_with_update_time("c", "a").await.unwrap().unwrap();
    assert!(m.delete_doc_if_unchanged("c", "a", &fresh).await.unwrap());
    assert!(m.get_doc("c", "a").await.unwrap().is_none());
    assert!(
        !m.delete_doc_if_unchanged("c", "a", &fresh).await.unwrap(),
        "消えた文書をもう 1 度消せた"
    );
}

/// 取り出しは 1 度だけで、取り出した文書は残らない。
pub(crate) async fn take_doc_returns_the_doc_once(m: &dyn DocumentStore) {
    m.set_doc("c", "a", json!({ "v": int(1) })).await.unwrap();
    assert_eq!(
        m.take_doc("c", "a").await.unwrap(),
        Some(json!({ "v": int(1) }))
    );
    assert_eq!(m.take_doc("c", "a").await.unwrap(), None);
    assert!(m.get_doc("c", "a").await.unwrap().is_none());
}

/// 並んで呼ばれても、作れるのも取り出せるのも 1 回だけ。
pub(crate) async fn racing_single_use_operations_let_one_through(m: &dyn DocumentStore) {
    let (a, b) = tokio::join!(
        m.create_if_absent("c", "a", json!({ "v": int(1) })),
        m.create_if_absent("c", "a", json!({ "v": int(2) })),
    );
    assert_eq!([a.unwrap(), b.unwrap()].iter().filter(|w| **w).count(), 1);
    let (a, b) = tokio::join!(m.take_doc("c", "a"), m.take_doc("c", "a"));
    assert_eq!(
        [a.unwrap(), b.unwrap()]
            .iter()
            .filter(|d| d.is_some())
            .count(),
        1
    );
}

/// 一部の書き込みはほかの field を残す。update は文書が要り、merge は無ければ作る。
pub(crate) async fn partial_writes_keep_other_fields_and_update_needs_the_doc(
    m: &dyn DocumentStore,
) {
    assert!(m.update_field("c", "a", "x", s("1")).await.is_err());
    assert!(
        m.update_fields("c", "a", json!({ "x": s("1") }))
            .await
            .is_err()
    );
    assert!(
        m.get_doc("c", "a").await.unwrap().is_none(),
        "失敗した update が文書を作った"
    );
    m.merge_fields("c", "a", json!({ "x": s("1"), "y": s("2") }), &[])
        .await
        .unwrap();
    m.update_field("c", "a", "x", s("3")).await.unwrap();
    m.update_fields("c", "a", json!({ "z": s("4") }))
        .await
        .unwrap();
    m.merge_fields("c", "a", json!({}), &["y".to_string()])
        .await
        .unwrap();
    assert_eq!(
        m.get_doc("c", "a").await.unwrap(),
        Some(json!({ "x": s("3"), "z": s("4") }))
    );
}

/// 書くたびに update_time が変わる（前提条件つきの書き込みが古い読みを見分けられる）。
pub(crate) async fn every_write_changes_the_update_time(m: &dyn DocumentStore) {
    m.set_doc("c", "a", json!({ "v": int(1) })).await.unwrap();
    let mut seen = vec![
        m.get_doc_with_update_time("c", "a")
            .await
            .unwrap()
            .unwrap()
            .1,
    ];
    m.set_doc("c", "a", json!({ "v": int(1) })).await.unwrap();
    seen.push(
        m.get_doc_with_update_time("c", "a")
            .await
            .unwrap()
            .unwrap()
            .1,
    );
    m.update_field("c", "a", "v", int(2)).await.unwrap();
    seen.push(
        m.get_doc_with_update_time("c", "a")
            .await
            .unwrap()
            .unwrap()
            .1,
    );
    m.merge_fields("c", "a", json!({ "w": int(3) }), &[])
        .await
        .unwrap();
    seen.push(
        m.get_doc_with_update_time("c", "a")
            .await
            .unwrap()
            .unwrap()
            .1,
    );
    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        seen.len(),
        "同じ update_time が続いた: {seen:?}"
    );
}

/// 文字列の field が等しい文書だけを、その集まりの中から返す。
pub(crate) async fn query_eq_returns_only_matching_docs_of_the_collection(m: &dyn DocumentStore) {
    for (id, who) in [("1", "a"), ("2", "b"), ("3", "a")] {
        m.set_doc("log", id, json!({ "who": s(who) }))
            .await
            .unwrap();
    }
    m.set_doc("other", "9", json!({ "who": s("a") }))
        .await
        .unwrap();
    let mut rows = m.query_eq("log", "who", "a").await.unwrap();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(ids(&rows), ["1", "3"]);
    assert_eq!(rows[0].1, json!({ "who": s("a") }));
    assert!(m.query_eq("log", "who", "nobody").await.unwrap().is_empty());
}

/// 時刻の新しい順に `limit` 件。同じ時刻なら id の大きい順。
pub(crate) async fn list_recent_ordered_sorts_newest_first_and_breaks_ties_by_id(
    m: &dyn DocumentStore,
) {
    for (id, at) in [("1", 10), ("2", 30), ("3", 20), ("4", 30)] {
        m.set_doc("log", id, json!({ "at": ts(&rfc3339(at)) }))
            .await
            .unwrap();
    }
    assert_eq!(
        ids(&m.list_recent_ordered("log", "at", 3).await.unwrap()),
        ["4", "2", "3"]
    );
    assert_eq!(
        ids(&m.list_recent_ordered("log", "at", 10).await.unwrap()),
        ["4", "2", "3", "1"]
    );
    assert!(
        m.list_recent_ordered("empty", "at", 3)
            .await
            .unwrap()
            .is_empty()
    );
}

/// その集まりの文書を全部、update_time つきで返す。消すのは無くても誤りにしない。
pub(crate) async fn list_collection_returns_every_doc_of_the_collection(m: &dyn DocumentStore) {
    assert!(m.list_collection("things").await.unwrap().is_empty());
    for id in ["a", "b", "c"] {
        m.set_doc("things", id, json!({ "id": s(id) }))
            .await
            .unwrap();
    }
    m.set_doc("other", "x", json!({})).await.unwrap();
    let mut rows = m.list_collection("things").await.unwrap();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        rows.iter()
            .map(|(id, _, _)| id.as_str())
            .collect::<Vec<_>>(),
        ["a", "b", "c"]
    );
    for (id, fields, update_time) in &rows {
        assert_eq!(fields, &json!({ "id": s(id) }));
        let (_, current) = m
            .get_doc_with_update_time("things", id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(update_time, &current);
    }
    m.delete_doc("things", "a").await.unwrap();
    m.delete_doc("things", "a").await.unwrap();
    assert_eq!(m.list_collection("things").await.unwrap().len(), 2);
}

/// `$make` は新しい空の保存先を返す async fn（`impl DocumentStore`）。
macro_rules! document_store_contract_tests {
    ($make:path) => {
        mod contract {
            #[allow(unused_imports)]
            use super::*;
            use $crate::document_store_contract as c;

            $crate::document_store_contract::document_store_contract_tests!(@each $make;
                create_if_absent_wins_once,
                set_doc_if_unchanged_loses_on_a_stale_update_time,
                delete_doc_if_unchanged_loses_on_a_stale_update_time,
                take_doc_returns_the_doc_once,
                racing_single_use_operations_let_one_through,
                partial_writes_keep_other_fields_and_update_needs_the_doc,
                every_write_changes_the_update_time,
                query_eq_returns_only_matching_docs_of_the_collection,
                list_recent_ordered_sorts_newest_first_and_breaks_ties_by_id,
                list_collection_returns_every_doc_of_the_collection,
            );
        }
    };
    (@each $make:path; $($name:ident),* $(,)?) => {
        $(
            #[tokio::test]
            async fn $name() {
                c::$name(&$make().await).await;
            }
        )*
    };
}
pub(crate) use document_store_contract_tests;
