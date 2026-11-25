//! [`FidoStore`] の契約の試験。実装ごとに 1 度 [`fido_store_contract_tests!`] を呼ぶと、同じ試験がその実装に当たる。
//! 実装を足すときは、その実装の試験の mod から同じ macro を呼ぶ。
//!
//! challenge の期限（5 分）は、MemFidoStore が `created_at` から、FirestoreFidoStore が保存した時刻から測るので、
//! ここでは見ない。

use crate::fido::store::{ChallengeState, FidoStore, StoredCredential};
use crate::fido::verify::CredKey;
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn challenge(username: &str, uv: Option<&str>) -> ChallengeState {
    ChallengeState {
        username: username.into(),
        user_verification: uv.map(str::to_string),
        created_at: now(),
    }
}

fn cred(id: &str, key: CredKey, sign_count: u32) -> StoredCredential {
    StoredCredential {
        id: id.into(),
        key,
        sign_count,
    }
}

fn es256(seed: u8) -> CredKey {
    CredKey::Es256 {
        x: vec![seed; 32],
        y: vec![seed.wrapping_add(1); 32],
    }
}

/// StoredCredential と CredKey に PartialEq が無いので、(id, 鍵の種類, 鍵の各部, signCount) にして比べる。
type View = (String, &'static str, Vec<Vec<u8>>, u32);

fn view(c: &StoredCredential) -> View {
    let (kind, parts) = match &c.key {
        CredKey::Es256 { x, y } => ("es256", vec![x.clone(), y.clone()]),
        CredKey::Rs256 { n, e } => ("rs256", vec![n.clone(), e.clone()]),
        CredKey::Rs1 { n, e } => ("rs1", vec![n.clone(), e.clone()]),
        CredKey::Ed25519 { pk } => ("ed25519", vec![pk.clone()]),
    };
    (c.id.clone(), kind, parts, c.sign_count)
}

fn sorted(mut v: Vec<StoredCredential>) -> Vec<View> {
    v.sort_by(|a, b| a.id.cmp(&b.id));
    v.iter().map(view).collect()
}

/// 保存した challenge は、利用者名と UV の要否を保ったまま引ける。UV の指定が無ければ無いまま。知らない challenge は None。
pub(crate) async fn a_saved_challenge_is_read_back(s: &dyn FidoStore) {
    s.save_challenge("CH1", challenge("alice", Some("required")))
        .await;
    s.save_challenge("CH2", challenge("bob", None)).await;

    let c1 = s.get_challenge("CH1").await.expect("CH1 が無い");
    assert_eq!(
        (c1.username.as_str(), c1.user_verification.as_deref()),
        ("alice", Some("required"))
    );
    let c2 = s.get_challenge("CH2").await.expect("CH2 が無い");
    assert_eq!(
        (c2.username.as_str(), c2.user_verification.as_deref()),
        ("bob", None)
    );
    assert!(s.get_challenge("NOPE").await.is_none());
}

/// 保存した credential は、その利用者で引くと鍵の種類・鍵・signCount を保ったまま返る。ほかの利用者のものは混ざらない。
pub(crate) async fn credentials_are_found_per_user_with_their_keys(s: &dyn FidoStore) {
    let keys = [
        cred("A1", es256(1), 0),
        cred(
            "A2",
            CredKey::Rs256 {
                n: vec![0xC3; 256],
                e: vec![1, 0, 1],
            },
            7,
        ),
        cred(
            "A3",
            CredKey::Rs1 {
                n: vec![0xB5; 256],
                e: vec![3],
            },
            0,
        ),
        cred("A4", CredKey::Ed25519 { pk: vec![9; 32] }, 42),
    ];
    for k in &keys {
        s.save_credential("alice", k.clone()).await;
    }
    s.save_credential("bob", cred("B1", es256(5), 3)).await;

    assert_eq!(
        sorted(s.find_credentials("alice").await),
        sorted(keys.to_vec())
    );
    assert_eq!(
        sorted(s.find_credentials("bob").await),
        sorted(vec![cred("B1", es256(5), 3)])
    );
    assert!(s.find_credentials("nobody").await.is_empty());
}

/// 同じ credentialId を 2 度保存しても、その利用者の credential は 1 つのまま。
pub(crate) async fn saving_the_same_credential_twice_keeps_one(s: &dyn FidoStore) {
    s.save_credential("alice", cred("C1", es256(1), 0)).await;
    s.save_credential("alice", cred("C1", es256(1), 0)).await;
    let ids: Vec<String> = s
        .find_credentials("alice")
        .await
        .into_iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(ids, ["C1"]);
}

/// signCount の更新は、その credential にだけ効き、鍵は変わらない。知らない credential の更新は何も作らない。
pub(crate) async fn update_sign_count_changes_only_that_credential(s: &dyn FidoStore) {
    s.save_credential("alice", cred("C1", es256(1), 1)).await;
    s.save_credential("alice", cred("C2", es256(2), 5)).await;

    s.update_sign_count("alice", "C1", 9).await;
    assert_eq!(
        sorted(s.find_credentials("alice").await),
        sorted(vec![cred("C1", es256(1), 9), cred("C2", es256(2), 5)])
    );

    s.update_sign_count("alice", "NOPE", 3).await;
    s.update_sign_count("nobody", "NOPE", 3).await;
    assert_eq!(s.find_credentials("alice").await.len(), 2);
    assert!(s.find_credentials("nobody").await.is_empty());
}

/// signCount の更新は、渡した利用者が持つ credential にだけ効く。持ち主の違う credential は更新せず、持ち主も変えない。
pub(crate) async fn update_sign_count_ignores_a_credential_of_another_user(s: &dyn FidoStore) {
    s.save_credential("alice", cred("C1", es256(1), 4)).await;
    s.save_credential("bob", cred("B1", es256(5), 2)).await;

    s.update_sign_count("bob", "C1", 9).await;
    assert_eq!(
        sorted(s.find_credentials("alice").await),
        sorted(vec![cred("C1", es256(1), 4)])
    );
    assert_eq!(
        sorted(s.find_credentials("bob").await),
        sorted(vec![cred("B1", es256(5), 2)])
    );
}

/// `$make` は新しい空の保存先を返す async fn（`impl FidoStore`）。
macro_rules! fido_store_contract_tests {
    ($make:path) => {
        mod contract {
            #[allow(unused_imports)]
            use super::*;
            use $crate::fido_store_contract as c;

            $crate::fido_store_contract::fido_store_contract_tests!(@each $make;
                a_saved_challenge_is_read_back,
                credentials_are_found_per_user_with_their_keys,
                saving_the_same_credential_twice_keeps_one,
                update_sign_count_changes_only_that_credential,
                update_sign_count_ignores_a_credential_of_another_user,
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
pub(crate) use fido_store_contract_tests;
