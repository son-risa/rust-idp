//! Firebase Cloud Messaging HTTP v1。CIBA 承認要求を利用者の端末に通知する。
//! token は端末ごとに fcmDevices/{sha256(token)} に置き、持ち主の accountId を書く。
//! 1 つの token の持ち主は、最後に登録したアカウントだけ（端末でアカウントを替えたら、
//! 前のアカウントの通知はその端末へ行かない）。1 アカウントは新しい順に MAX_DEVICES 台まで。
//! 古い形の fcmTokens/{account_id}（1 アカウント 1 つ）も読み、そのアカウントの次の登録で移す。
//! 送信は metadata トークンで v1 を直叩き。

use crate::document_store::DocumentStore;
use crate::firestore;
#[cfg(feature = "gcp")]
use crate::firestore::Firestore;
#[cfg(feature = "gcp")]
use serde_json::Value;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const DEVICES: &str = "fcmDevices";
const LEGACY: &str = "fcmTokens";
const MAX_DEVICES: usize = 10;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// token をそのまま文書 id にすると `/` などで道が壊れるので、ハッシュを id にする。
fn device_id(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn device_doc(
    account_id: &str,
    token: &str,
    platform: &str,
    updated_at: &str,
) -> serde_json::Value {
    json!({
        "accountId": firestore::s(account_id),
        "token": firestore::s(token),
        "platform": firestore::s(platform),
        "updatedAt": firestore::ts(updated_at),
    })
}

pub async fn save_token(
    fs: &dyn DocumentStore,
    account_id: &str,
    token: &str,
    platform: &str,
) -> Result<(), String> {
    migrate_legacy(fs, account_id).await?;
    fs.set_doc(
        DEVICES,
        &device_id(token),
        device_doc(account_id, token, platform, &firestore::rfc3339(now())),
    )
    .await?;
    trim(fs, account_id).await
}

/// 古い形の 1 つを新しい形へ移す。その token が既に誰かの端末として在れば、そちらを残す。
async fn migrate_legacy(fs: &dyn DocumentStore, account_id: &str) -> Result<(), String> {
    let Some(f) = fs.get_doc(LEGACY, account_id).await? else {
        return Ok(());
    };
    if let Some(token) = firestore::field_str(&f, "token") {
        let platform = firestore::field_str(&f, "platform").unwrap_or("ios");
        let updated_at = f
            .get("updatedAt")
            .and_then(|v| v.get("timestampValue"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| firestore::rfc3339(0));
        fs.create_if_absent(
            DEVICES,
            &device_id(token),
            device_doc(account_id, token, platform, &updated_at),
        )
        .await?;
    }
    fs.delete_doc(LEGACY, account_id).await
}

/// 新しい順に MAX_DEVICES 台だけ残す。
async fn trim(fs: &dyn DocumentStore, account_id: &str) -> Result<(), String> {
    let mut docs = fs.query_eq(DEVICES, "accountId", account_id).await?;
    if docs.len() <= MAX_DEVICES {
        return Ok(());
    }
    docs.sort_by(|(ia, a), (ib, b)| {
        let ta = firestore::field_ts_secs(a, "updatedAt").unwrap_or(0);
        let tb = firestore::field_ts_secs(b, "updatedAt").unwrap_or(0);
        tb.cmp(&ta).then_with(|| ib.cmp(ia))
    });
    for (id, _) in &docs[MAX_DEVICES..] {
        fs.delete_doc(DEVICES, id).await?;
    }
    Ok(())
}

/// アカウントを消すときに、その端末の token を全部消す。
pub async fn delete_account_devices(
    fs: &dyn DocumentStore,
    account_id: &str,
) -> Result<(), String> {
    for (id, _) in fs.query_eq(DEVICES, "accountId", account_id).await? {
        fs.delete_doc(DEVICES, &id).await?;
    }
    fs.delete_doc(LEGACY, account_id).await
}

/// 送り先: (消すときの集まり, 文書 id, token)。
#[cfg(feature = "gcp")]
async fn targets(
    fs: &dyn DocumentStore,
    account_id: &str,
) -> Result<Vec<(&'static str, String, String)>, String> {
    let mut out: Vec<(&'static str, String, String)> = fs
        .query_eq(DEVICES, "accountId", account_id)
        .await?
        .into_iter()
        .filter_map(|(id, f)| Some((DEVICES, id, firestore::field_str(&f, "token")?.to_string())))
        .collect();
    let legacy = fs.get_doc(LEGACY, account_id).await?;
    let Some(token) = legacy
        .as_ref()
        .and_then(|f| firestore::field_str(f, "token"))
    else {
        return Ok(out);
    };
    if out.iter().any(|(_, _, t)| t == token) {
        return Ok(out);
    }
    // 同じ token が別のアカウントの端末として登録し直されていたら、古い形のほうは送らない。
    let moved = fs
        .get_doc(DEVICES, &device_id(token))
        .await?
        .is_some_and(|d| firestore::field_str(&d, "accountId") != Some(account_id));
    if !moved {
        out.push((LEGACY, account_id.to_string(), token.to_string()));
    }
    Ok(out)
}

/// CIBA 承認要求の data メッセージを、そのアカウントの端末すべてへ送る。token 未登録なら no-op
/// （Web 承認に委ねる）。FCM が token を知らないと答えたら、その token を消す。
/// Cloud Run の suspend を避けるため呼び出し側で .await すること。
#[cfg(feature = "gcp")]
pub async fn send_ciba_request(
    fs: &Firestore,
    account_id: &str,
    client_id: &str,
    scope: &str,
    binding: &str,
    auth_req_id: &str,
    authorization_details: Option<&str>,
) -> Result<(), String> {
    // FCM data は string-only。authorization_details は JSON 文字列をそのまま渡す。
    // 端末の側で jsonDecode してから構造化表示する（Mandate を端末で確認できる）。
    let mut data = serde_json::Map::new();
    data.insert("type".into(), json!("ciba_request"));
    data.insert("auth_req_id".into(), json!(auth_req_id));
    data.insert("client_name".into(), json!(client_id));
    data.insert("scope".into(), json!(scope));
    data.insert("binding_message".into(), json!(binding));
    if let Some(ad) = authorization_details {
        data.insert("authorization_details".into(), json!(ad));
    }
    let mut errors = Vec::new();
    for (col, id, token) in targets(fs, account_id).await? {
        let message = json!({
            "token": token,
            "notification": {
                "title": crate::web::i18n::bilingual("[[Sign-in approval]]"),
                "body": crate::web::i18n::bilingual("[[Sign-in request from {client}]]").replace("{client}", client_id),
            },
            "data": data,
            "apns": { "payload": { "aps": { "sound": "default", "mutable-content": 1 } } },
        });
        match send(fs, message).await {
            Ok(()) => {}
            Err(SendError::Unregistered) => {
                if let Err(e) = DocumentStore::delete_doc(fs, col, &id).await {
                    errors.push(format!("delete stale token: {e}"));
                }
            }
            Err(SendError::Other(e)) => errors.push(e),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[cfg(feature = "gcp")]
enum SendError {
    /// FCM がその token を知らない（アプリを消した・token が替わった）。
    Unregistered,
    Other(String),
}

#[cfg(feature = "gcp")]
async fn send(fs: &Firestore, message: Value) -> Result<(), SendError> {
    let access = fs.token().await.map_err(SendError::Other)?;
    let url = format!(
        "{}/v1/projects/{}/messages:send",
        fs.base_url_or("fcm.googleapis.com"),
        fs.project()
    );
    let r = crate::http::client()
        .post(url)
        .bearer_auth(access)
        .json(&json!({ "message": message }))
        .send()
        .await
        .map_err(|e| SendError::Other(format!("fcm: {e}")))?;
    let status = r.status();
    if status.is_success() {
        Ok(())
    } else if status == reqwest::StatusCode::NOT_FOUND {
        Err(SendError::Unregistered)
    } else {
        Err(SendError::Other(format!(
            "fcm {} {}",
            status,
            r.text().await.unwrap_or_default()
        )))
    }
}

#[cfg(all(test, feature = "gcp"))]
mod tests {
    use super::*;
    use crate::firestore::fake_firestore;

    #[tokio::test]
    async fn send_ciba_request_finds_token_saved_under_same_account_id() {
        let (host, state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);

        // save_token は account_id をキーに保存し、send_ciba_request は同じキーで引く。
        // 別々の場所で同じ識別子(account_id)を渡し続けられているかを検証する
        // (かつて login_hint/email との取り違えでこのキーがズレていたクラスのバグを防ぐ)。
        save_token(&fs, "acct-123", "tok-abc", "ios").await.unwrap();
        send_ciba_request(
            &fs,
            "acct-123",
            "client-1",
            "openid",
            "承認してください",
            "req-1",
            None,
        )
        .await
        .unwrap();

        let sent = state.fcm_sent_messages();
        assert_eq!(
            sent.len(),
            1,
            "同じ account_id で保存した token 宛にちょうど1通送られる"
        );
        assert_eq!(sent[0]["message"]["token"], json!("tok-abc"));
        assert_eq!(sent[0]["message"]["data"]["auth_req_id"], json!("req-1"));
        assert_eq!(
            sent[0]["message"]["notification"]["title"],
            json!("ログインの承認 / Sign-in approval")
        );
        assert_eq!(
            sent[0]["message"]["notification"]["body"],
            json!("client-1 からのログイン要求があります / Sign-in request from client-1"),
            "端末の言語が分からないので、日本語と英語を 1 行に並べる"
        );
    }

    #[tokio::test]
    async fn send_ciba_request_is_noop_when_identifier_does_not_match_saved_token() {
        let (host, state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);

        save_token(&fs, "acct-123", "tok-abc", "ios").await.unwrap();
        // account_id ではなく email 等、違う識別子系列で呼ばれた場合を模す。
        // 現状の契約は「見つからなければ静かに no-op」であり、エラーにはならない
        // (呼び出し側のキー取り違えを検知する仕組みは無いことの記録でもある)。
        send_ciba_request(
            &fs,
            "someone@example.com",
            "client-1",
            "openid",
            "",
            "req-2",
            None,
        )
        .await
        .unwrap();

        assert!(
            state.fcm_sent_messages().is_empty(),
            "識別子が一致しない場合は送信されない(静かな no-op)"
        );
    }

    fn sent_tokens(state: &fake_firestore::FakeState) -> Vec<String> {
        let mut t: Vec<String> = state
            .fcm_sent_messages()
            .iter()
            .map(|m| m["message"]["token"].as_str().unwrap().to_string())
            .collect();
        t.sort();
        t
    }

    async fn send(fs: &Firestore, account_id: &str) -> Result<(), String> {
        send_ciba_request(fs, account_id, "client-1", "openid", "", "req-1", None).await
    }

    #[tokio::test]
    async fn send_reaches_every_device_of_the_account() {
        let (host, state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        save_token(&fs, "acct-a", "tok-phone", "ios").await.unwrap();
        save_token(&fs, "acct-a", "tok-pad", "ios").await.unwrap();
        save_token(&fs, "acct-b", "tok-other", "ios").await.unwrap();
        send(&fs, "acct-a").await.unwrap();
        assert_eq!(sent_tokens(&state), ["tok-pad", "tok-phone"]);
    }

    #[tokio::test]
    async fn send_removes_a_token_fcm_no_longer_knows_and_still_reaches_the_rest() {
        let (host, state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        save_token(&fs, "acct-a", "tok-gone", "ios").await.unwrap();
        save_token(&fs, "acct-a", "tok-live", "ios").await.unwrap();
        state.fcm_unregister("tok-gone");
        send(&fs, "acct-a").await.unwrap();
        assert_eq!(sent_tokens(&state), ["tok-live"]);
        assert!(
            DocumentStore::get_doc(&fs, DEVICES, &device_id("tok-gone"))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn send_still_reaches_a_legacy_token() {
        let (host, state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        DocumentStore::set_doc(
            &fs,
            LEGACY,
            "acct-a",
            json!({ "token": firestore::s("tok-old") }),
        )
        .await
        .unwrap();
        send(&fs, "acct-a").await.unwrap();
        assert_eq!(sent_tokens(&state), ["tok-old"]);
    }

    #[tokio::test]
    async fn send_skips_a_legacy_token_now_registered_by_another_account() {
        let (host, state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        DocumentStore::set_doc(
            &fs,
            LEGACY,
            "acct-a",
            json!({ "token": firestore::s("tok-shared") }),
        )
        .await
        .unwrap();
        save_token(&fs, "acct-b", "tok-shared", "ios")
            .await
            .unwrap();
        send(&fs, "acct-a").await.unwrap();
        assert!(state.fcm_sent_messages().is_empty());
    }
}

#[cfg(test)]
mod store_tests {
    use super::*;
    use crate::document_store::MemoryDocumentStore;

    async fn tokens_of(fs: &dyn DocumentStore, account_id: &str) -> Vec<String> {
        let mut t: Vec<String> = fs
            .query_eq(DEVICES, "accountId", account_id)
            .await
            .unwrap()
            .iter()
            .filter_map(|(_, f)| firestore::field_str(f, "token").map(str::to_string))
            .collect();
        t.sort();
        t
    }

    #[tokio::test]
    async fn one_account_keeps_every_device() {
        let fs = MemoryDocumentStore::default();
        save_token(&fs, "acct-a", "tok-phone", "ios").await.unwrap();
        save_token(&fs, "acct-a", "tok-pad", "ios").await.unwrap();
        save_token(&fs, "acct-a", "tok-phone", "ios").await.unwrap();
        assert_eq!(tokens_of(&fs, "acct-a").await, ["tok-pad", "tok-phone"]);
    }

    #[tokio::test]
    async fn a_token_moves_to_the_account_that_registered_it_last() {
        let fs = MemoryDocumentStore::default();
        save_token(&fs, "acct-a", "tok-shared", "ios")
            .await
            .unwrap();
        save_token(&fs, "acct-b", "tok-shared", "ios")
            .await
            .unwrap();
        assert!(tokens_of(&fs, "acct-a").await.is_empty());
        assert_eq!(tokens_of(&fs, "acct-b").await, ["tok-shared"]);
    }

    #[tokio::test]
    async fn an_account_keeps_at_most_max_devices() {
        let fs = MemoryDocumentStore::default();
        for i in 0..MAX_DEVICES + 2 {
            save_token(&fs, "acct-a", &format!("tok-{i:02}"), "ios")
                .await
                .unwrap();
        }
        assert_eq!(tokens_of(&fs, "acct-a").await.len(), MAX_DEVICES);
    }

    #[tokio::test]
    async fn registering_moves_the_legacy_token_into_devices() {
        let fs = MemoryDocumentStore::default();
        fs.set_doc(
            LEGACY,
            "acct-a",
            json!({ "token": firestore::s("tok-old") }),
        )
        .await
        .unwrap();
        save_token(&fs, "acct-a", "tok-new", "ios").await.unwrap();
        assert_eq!(tokens_of(&fs, "acct-a").await, ["tok-new", "tok-old"]);
        assert!(fs.get_doc(LEGACY, "acct-a").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn deleting_an_account_removes_only_its_devices() {
        let fs = MemoryDocumentStore::default();
        save_token(&fs, "acct-a", "tok-a", "ios").await.unwrap();
        save_token(&fs, "acct-b", "tok-b", "ios").await.unwrap();
        fs.set_doc(
            LEGACY,
            "acct-a",
            json!({ "token": firestore::s("tok-old") }),
        )
        .await
        .unwrap();
        delete_account_devices(&fs, "acct-a").await.unwrap();
        assert!(tokens_of(&fs, "acct-a").await.is_empty());
        assert!(fs.get_doc(LEGACY, "acct-a").await.unwrap().is_none());
        assert_eq!(tokens_of(&fs, "acct-b").await, ["tok-b"]);
    }
}
