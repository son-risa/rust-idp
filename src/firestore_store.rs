//! Store トレイトの、[`DocumentStore`] の上の実装。ゼロスケールでもインスタンス跨ぎで
//! セッション/コード/トークンを永続化する（TS の FirestoreAdapter 相当）。
//! gcp では Firestore、sqlite では SQLite の file を下に置く。
//! interactions / sessions / authCodes / accessTokens / refreshTokens を保存。
//! find_account は static（accounts/{email} は別 collection で registration.rs が管理）。

use crate::document_store::DocumentStore;
use crate::firestore as fs_h;
use crate::model::*;
use crate::store::{CodeTake, RevocationCounts, Store, StoreResult};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// 保持期間は store.rs の共有定数を参照する（バックエンド間でドリフトさせない）。
use crate::store::{
    ACCESS_TTL_SECS as ACCESS_TTL, INTERACTION_TTL_SECS as INTERACTION_TTL,
    REFRESH_TTL_SECS as REFRESH_TTL, SESSION_TTL_SECS as SESSION_TTL,
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// 系列の失効の札（refreshFamilyRevocations/{familyId}）。
const FAMILY_REVOCATIONS: &str = "refreshFamilyRevocations";
/// 札の書き込みと、後片付けで消せなかった RT（ストアの誤り・CAS の負け）を読み直して消し直す回数。
const REVOKE_RETRIES: usize = 3;
/// 1 回の失効の後片付けで扱う RT の数の上限。
pub(crate) const REVOKE_MAX_RTS: usize = 1000;

fn doc_expired(fields: &Value) -> bool {
    fs_h::field_ts_secs(fields, "expiresAt").unwrap_or(0) < now()
}

fn code_from_fields(code: &str, f: &Value) -> AuthorizationCode {
    AuthorizationCode {
        code: code.to_string(),
        client_id: fs_h::field_str(f, "clientId").unwrap_or("").to_string(),
        account_id: fs_h::field_str(f, "accountId").unwrap_or("").to_string(),
        redirect_uri: fs_h::field_str(f, "redirectUri").unwrap_or("").to_string(),
        scope: fs_h::field_str(f, "scope").unwrap_or("").to_string(),
        nonce: fs_h::field_str(f, "nonce").map(str::to_string),
        code_challenge: fs_h::field_str(f, "codeChallenge").map(str::to_string),
        code_challenge_method: fs_h::field_str(f, "codeChallengeMethod").map(str::to_string),
        auth_time: fs_h::field_u64(f, "authTime").unwrap_or(0),
        acr: fs_h::field_str(f, "acr").map(str::to_string),
        dpop_jkt: fs_h::field_str(f, "dpopJkt").map(str::to_string),
        resource: fs_h::field_str(f, "resource").map(str::to_string),
        expires_at: fs_h::field_ts_secs(f, "expiresAt").unwrap_or(0),
    }
}

/// refreshTokens の fields から RefreshToken を復元する（take/get 共通）。
fn rt_from_fields(token: &str, f: &Value) -> RefreshToken {
    RefreshToken {
        token: token.to_string(),
        client_id: fs_h::field_str(f, "clientId").unwrap_or("").to_string(),
        account_id: fs_h::field_str(f, "accountId").unwrap_or("").to_string(),
        scope: fs_h::field_str(f, "scope").unwrap_or("").to_string(),
        resource: fs_h::field_str(f, "resource").map(str::to_string),
        jkt: fs_h::field_str(f, "jkt").map(str::to_string),
        acr: fs_h::field_str(f, "acr").map(str::to_string),
        auth_time: fs_h::field_u64(f, "authTime"),
        family_id: fs_h::field_str(f, "familyId").unwrap_or("").to_string(),
        used: fs_h::field_bool(f, "used").unwrap_or(false),
        replaced_by: fs_h::field_str(f, "replacedBy").map(str::to_string),
    }
}

pub struct FirestoreStore {
    fs: Arc<dyn DocumentStore>,
}

impl FirestoreStore {
    pub fn new(fs: Arc<dyn DocumentStore>) -> Self {
        Self { fs }
    }

    /// RT を 1 本、読んだ updateTime の CAS で消す。消せた（または既に無い）なら gone=true、消せなかったら
    /// gone=false で、どちらでも読めた replacedBy を返す。CAS に負けた（読んでから消すまでの間に、その RT の
    /// ローテーションが replacedBy を書いた）ときもストアの誤りと同じく gone=false にし、消し直しの周で
    /// 読み直して新しい replacedBy の先まで辿る。条件なしで消すと、その間に渡った新しい RT が系列から外れて残る。
    async fn revoke_one_refresh(&self, token: &str) -> (bool, Option<String>) {
        let (f, update_time) = match self
            .fs
            .get_doc_with_update_time("refreshTokens", token)
            .await
        {
            Ok(Some(x)) => x,
            Ok(None) => return (true, None),
            Err(_) => return (false, None),
        };
        let next = fs_h::field_str(&f, "replacedBy").map(str::to_string);
        let gone = matches!(
            self.fs
                .delete_doc_if_unchanged("refreshTokens", token, &update_time)
                .await,
            Ok(true)
        );
        (gone, next)
    }
}

/// 外から来た値をそのまま文書 ID にする前に形を見る。発行する値は 32 桁の 16 進なので、それより緩く
/// 「Firestore が ID として受け付ける形」だけを通す。受け付けない形を引くと Firestore が 400 を返し、
/// それがストアの誤り（5xx）になって、ただの「無い」が障害に見えてしまう。
fn issued_shape(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && !id.starts_with("__")
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[async_trait]
impl Store for FirestoreStore {
    async fn save_interaction(&self, i: Interaction) {
        let mut f = json!({
            "rawQuery": fs_h::s(&i.raw_query),
            "browserBinding": fs_h::s(&i.browser_binding),
            "expiresAt": fs_h::ts(&fs_h::rfc3339(now() + INTERACTION_TTL)),
        });
        if let Some(a) = &i.account_id {
            f["accountId"] = fs_h::s(a);
        }
        if let Some(t) = i.auth_time {
            f["authTime"] = fs_h::int(t);
        }
        if let Some(ru) = &i.request_uri {
            f["requestUri"] = fs_h::s(ru);
        }
        let _ = self.fs.set_doc("interactions", &i.uid, f).await;
    }

    async fn get_interaction(&self, uid: &str) -> Option<Interaction> {
        let f = self.fs.get_doc("interactions", uid).await.ok()??;
        if doc_expired(&f) {
            return None;
        }
        Some(Interaction {
            uid: uid.to_string(),
            raw_query: fs_h::field_str(&f, "rawQuery").unwrap_or("").to_string(),
            account_id: fs_h::field_str(&f, "accountId").map(str::to_string),
            auth_time: fs_h::field_u64(&f, "authTime"),
            request_uri: fs_h::field_str(&f, "requestUri").map(str::to_string),
            browser_binding: fs_h::field_str(&f, "browserBinding")
                .unwrap_or("")
                .to_string(),
        })
    }

    async fn complete_interaction(&self, uid: &str, account_id: &str, auth_time: u64) -> bool {
        // 読んだ updateTime の CAS で書く。間に resume が消費（CAS 削除）していれば負けて false。
        let Ok(Some((mut f, update_time))) =
            self.fs.get_doc_with_update_time("interactions", uid).await
        else {
            return false;
        };
        if doc_expired(&f) {
            return false;
        }
        f["accountId"] = fs_h::s(account_id);
        f["authTime"] = fs_h::int(auth_time);
        matches!(
            self.fs
                .set_doc_if_unchanged("interactions", uid, f, &update_time)
                .await,
            Ok(true)
        )
    }

    async fn consume_interaction(&self, uid: &str) -> bool {
        // updateTime CAS で単回削除（並行 resume / リプレイで高々 1 回だけ成功）。
        matches!(self.fs.take_doc("interactions", uid).await, Ok(Some(_)))
    }

    async fn save_session(&self, s: Session) -> StoreResult<()> {
        let f = json!({
            "accountId": fs_h::s(&s.account_id),
            "authTime": fs_h::int(s.auth_time),
            "expiresAt": fs_h::ts(&fs_h::rfc3339(now() + SESSION_TTL)),
        });
        Ok(self.fs.set_doc("sessions", &s.sid, f).await?)
    }

    async fn get_session(&self, sid: &str) -> StoreResult<Option<Session>> {
        let Some(f) = self.fs.get_doc("sessions", sid).await? else {
            return Ok(None);
        };
        if doc_expired(&f) {
            return Ok(None);
        }
        Ok(Some(Session {
            sid: sid.to_string(),
            account_id: fs_h::field_str(&f, "accountId").unwrap_or("").to_string(),
            auth_time: fs_h::field_u64(&f, "authTime").unwrap_or(0),
        }))
    }

    async fn delete_session(&self, sid: &str) -> StoreResult<()> {
        Ok(self.fs.delete_doc("sessions", sid).await?)
    }

    async fn save_code(&self, c: AuthorizationCode) -> StoreResult<()> {
        let mut f = json!({
            "clientId": fs_h::s(&c.client_id),
            "accountId": fs_h::s(&c.account_id),
            "redirectUri": fs_h::s(&c.redirect_uri),
            "scope": fs_h::s(&c.scope),
            "authTime": fs_h::int(c.auth_time),
            "expiresAt": fs_h::ts(&fs_h::rfc3339(c.expires_at)),
            // 再利用検出用。消費後も削除せず used=true にし、発行トークンを紐付ける。
            "used": fs_h::b(false),
        });
        if let Some(v) = &c.nonce {
            f["nonce"] = fs_h::s(v);
        }
        if let Some(v) = &c.code_challenge {
            f["codeChallenge"] = fs_h::s(v);
        }
        if let Some(v) = &c.code_challenge_method {
            f["codeChallengeMethod"] = fs_h::s(v);
        }
        if let Some(v) = &c.acr {
            f["acr"] = fs_h::s(v);
        }
        if let Some(v) = &c.dpop_jkt {
            f["dpopJkt"] = fs_h::s(v);
        }
        if let Some(v) = &c.resource {
            f["resource"] = fs_h::s(v);
        }
        Ok(self.fs.set_doc("authCodes", &c.code, f).await?)
    }

    async fn take_code(&self, code: &str) -> StoreResult<CodeTake> {
        if !issued_shape(code) {
            return Ok(CodeTake::Unknown);
        }
        // updateTime CAS で単回消費を原子化する。get→write の間に別リクエストが消費した
        // 場合は CAS が負け、二重発行を防ぐ（consume_mandate_if_unused / CIBA と同型）。
        let Some((mut f, update_time)) =
            self.fs.get_doc_with_update_time("authCodes", code).await?
        else {
            return Ok(CodeTake::Unknown);
        };
        // 期限切れのコードは未知と同じ（MemoryStore の alive と同じく、期限ちょうども切れとする）。
        if fs_h::field_ts_secs(&f, "expiresAt").unwrap_or(0) <= now() {
            return Ok(CodeTake::Unknown);
        }
        let used = f
            .get("used")
            .and_then(|v| v.get("booleanValue"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if used {
            return Ok(CodeTake::Reused(code_from_fields(code, &f)));
        }
        // 初回消費: used=true を CAS で書く。並行消費に負けたら再利用と同じに扱う。
        f["used"] = fs_h::b(true);
        if !self
            .fs
            .set_doc_if_unchanged("authCodes", code, f.clone(), &update_time)
            .await?
        {
            return Ok(CodeTake::Reused(code_from_fields(code, &f)));
        }
        Ok(CodeTake::Fresh(code_from_fields(code, &f)))
    }

    async fn revoke_code_tokens(&self, code: &str) {
        // 消せなかったトークンはログで追う（呼び出し側はどのみちコードを拒否する）。
        let f = match self.fs.get_doc("authCodes", code).await {
            Ok(Some(f)) => f,
            Ok(None) => return,
            Err(e) => {
                tracing::error!(event = "code_reuse_revoke_failed", kind = "code", "{e}");
                return;
            }
        };
        if let Some(at) = fs_h::field_str(&f, "issuedAccessToken")
            && let Err(e) = self.fs.delete_doc("accessTokens", at).await
        {
            tracing::error!(event = "code_reuse_revoke_failed", kind = "access", "{e}");
        }
        if let Some(rt) = fs_h::field_str(&f, "issuedRefreshToken") {
            crate::store::revoke_issued_refresh(self, rt).await;
        }
    }

    async fn link_issued_tokens(
        &self,
        code: &str,
        access_token: &str,
        refresh_token: Option<&str>,
    ) -> StoreResult<()> {
        let mut f = json!({ "issuedAccessToken": fs_h::s(access_token) });
        if let Some(rt) = refresh_token {
            f["issuedRefreshToken"] = fs_h::s(rt);
        }
        Ok(self.fs.merge_fields("authCodes", code, f, &[]).await?)
    }

    async fn save_access_token(&self, t: AccessToken) -> StoreResult<()> {
        let mut f = json!({
            "clientId": fs_h::s(&t.client_id),
            "accountId": fs_h::s(&t.account_id),
            "scope": fs_h::s(&t.scope),
            "expiresAt": fs_h::ts(&fs_h::rfc3339(now() + ACCESS_TTL)),
        });
        if let Some(jkt) = &t.jkt {
            f["jkt"] = fs_h::s(jkt);
        }
        if let Some(aud) = &t.aud {
            f["aud"] = fs_h::s(aud);
        }
        if let Some(acr) = &t.acr {
            f["acr"] = fs_h::s(acr);
        }
        if let Some(at) = t.auth_time {
            f["authTime"] = fs_h::int(at);
        }
        if let Some(ad) = &t.authorization_details {
            f["authorizationDetails"] = fs_h::s(ad);
        }
        if t.mandate_consumed {
            f["mandateConsumed"] = fs_h::b(true);
        }
        Ok(self.fs.set_doc("accessTokens", &t.token, f).await?)
    }

    async fn get_access_token(&self, token: &str) -> StoreResult<Option<AccessToken>> {
        if !issued_shape(token) {
            return Ok(None);
        }
        let Some(f) = self.fs.get_doc("accessTokens", token).await? else {
            return Ok(None);
        };
        if doc_expired(&f) {
            return Ok(None);
        }
        Ok(Some(AccessToken {
            token: token.to_string(),
            client_id: fs_h::field_str(&f, "clientId").unwrap_or("").to_string(),
            account_id: fs_h::field_str(&f, "accountId").unwrap_or("").to_string(),
            scope: fs_h::field_str(&f, "scope").unwrap_or("").to_string(),
            jkt: fs_h::field_str(&f, "jkt").map(str::to_string),
            aud: fs_h::field_str(&f, "aud").map(str::to_string),
            acr: fs_h::field_str(&f, "acr").map(str::to_string),
            auth_time: fs_h::field_u64(&f, "authTime"),
            authorization_details: fs_h::field_str(&f, "authorizationDetails")
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            mandate_consumed: fs_h::field_bool(&f, "mandateConsumed").unwrap_or(false),
        }))
    }

    async fn revoke_access_token(&self, token: &str) -> StoreResult<()> {
        if !issued_shape(token) {
            return Ok(());
        }
        Ok(self.fs.delete_doc("accessTokens", token).await?)
    }

    /// updateTime CAS で mandate_consumed: false → true を 1 回だけ成功させる。
    async fn consume_mandate_if_unused(&self, token: &str) -> Result<bool, String> {
        let (mut f, update_time) = match self
            .fs
            .get_doc_with_update_time("accessTokens", token)
            .await?
        {
            Some(x) => x,
            None => return Ok(false),
        };
        if doc_expired(&f) {
            return Ok(false);
        }
        if fs_h::field_bool(&f, "mandateConsumed").unwrap_or(false) {
            return Ok(false);
        }
        f["mandateConsumed"] = fs_h::b(true);
        self.fs
            .set_doc_if_unchanged("accessTokens", token, f, &update_time)
            .await
    }

    async fn save_refresh_token(&self, t: RefreshToken) -> StoreResult<()> {
        let mut f = json!({
            "clientId": fs_h::s(&t.client_id),
            "accountId": fs_h::s(&t.account_id),
            "scope": fs_h::s(&t.scope),
            "expiresAt": fs_h::ts(&fs_h::rfc3339(now() + REFRESH_TTL)),
        });
        if let Some(r) = &t.resource {
            f["resource"] = fs_h::s(r);
        }
        if let Some(jkt) = &t.jkt {
            f["jkt"] = fs_h::s(jkt);
        }
        if let Some(acr) = &t.acr {
            f["acr"] = fs_h::s(acr);
        }
        if let Some(at) = t.auth_time {
            f["authTime"] = fs_h::int(at);
        }
        f["familyId"] = fs_h::s(&t.family_id);
        f["used"] = fs_h::b(t.used);
        if let Some(rb) = &t.replaced_by {
            f["replacedBy"] = fs_h::s(rb);
        }
        Ok(self.fs.set_doc("refreshTokens", &t.token, f).await?)
    }

    async fn get_refresh_token(&self, token: &str) -> StoreResult<Option<RefreshToken>> {
        if !issued_shape(token) {
            return Ok(None);
        }
        let Some(f) = self.fs.get_doc("refreshTokens", token).await? else {
            return Ok(None);
        };
        if doc_expired(&f) {
            return Ok(None);
        }
        Ok(Some(rt_from_fields(token, &f)))
    }

    async fn mark_refresh_used(&self, token: &str, replaced_by: Option<&str>) -> StoreResult<bool> {
        if !issued_shape(token) {
            return Ok(false);
        }
        // 消費前の fields と updateTime を読み、used=false なら used=true + replacedBy を
        // updateTime 条件付き更新で書く（CAS）。並行ローテーションは高々 1 回成功。
        let Some((mut f, ut)) = self
            .fs
            .get_doc_with_update_time("refreshTokens", token)
            .await?
        else {
            return Ok(false);
        };
        if fs_h::field_bool(&f, "used").unwrap_or(false) {
            return Ok(false); // 既に使用済み（再利用/競合）
        }
        f["used"] = fs_h::b(true);
        if let Some(rb) = replaced_by {
            f["replacedBy"] = fs_h::s(rb);
        }
        Ok(self
            .fs
            .set_doc_if_unchanged("refreshTokens", token, f, &ut)
            .await?)
    }

    async fn refresh_family_revoked(&self, family_id: &str) -> StoreResult<bool> {
        Ok(self
            .fs
            .get_doc(FAMILY_REVOCATIONS, family_id)
            .await?
            .is_some_and(|f| !doc_expired(&f)))
    }

    async fn revoke_refresh_family(&self, family_id: &str, start_token: &str) {
        // 札の期限は RT の TTL に余裕を足したもの。札を書いた後はその系列に新しい RT を作らせないので、既存の
        // RT が全部切れるまで札が残れば足りる。余裕はインスタンスの間の時計のずれと書き込みの遅れの分。
        let mut written = false;
        for _ in 0..=REVOKE_RETRIES {
            // 期限は書き込みを試すたびに、その時刻から計算する（前の試みが遅れても札が短くならない）。
            let tomb = json!({ "expiresAt": fs_h::ts(&fs_h::rfc3339(now() + REFRESH_TTL + crate::store::FAMILY_REVOCATION_MARGIN_SECS)) });
            if self
                .fs
                .set_doc(FAMILY_REVOCATIONS, family_id, tomb)
                .await
                .is_ok()
            {
                written = true;
                break;
            }
        }
        if !written {
            tracing::error!(event = "refresh_family_tombstone_failed");
        }
        // 後片付け: start から replacedBy を辿って消す。札が使わせないので、消し漏れ・打ち切りは安全に関わらない。
        // 1 回の失効で扱う RT の数に上限を置き、続くローテーションに追われても必ず終わる。
        let mut seen = std::collections::HashSet::from([start_token.to_string()]);
        let mut queue = vec![start_token.to_string()];
        let mut failed = Vec::new();
        let mut handled = 0usize;
        for round in 0..=REVOKE_RETRIES {
            while let Some(t) = queue.pop() {
                handled += 1;
                if handled > REVOKE_MAX_RTS {
                    tracing::warn!(
                        event = "refresh_family_cleanup_truncated",
                        limit = REVOKE_MAX_RTS
                    );
                    return;
                }
                let (gone, next) = self.revoke_one_refresh(&t).await;
                if !gone {
                    failed.push(t);
                }
                if let Some(n) = next.filter(|n| seen.insert(n.clone())) {
                    queue.push(n);
                }
            }
            if failed.is_empty() || round == REVOKE_RETRIES {
                break;
            }
            queue = std::mem::take(&mut failed);
        }
        if !failed.is_empty() {
            tracing::warn!(
                event = "refresh_family_cleanup_incomplete",
                left = failed.len()
            );
        }
    }

    async fn revoke_refresh_token(&self, token: &str) -> StoreResult<()> {
        if !issued_shape(token) {
            return Ok(());
        }
        Ok(self.fs.delete_doc("refreshTokens", token).await?)
    }

    async fn find_account(&self, sub: &str) -> Account {
        crate::registration::account_from_documents(&*self.fs, sub).await
    }

    /// 下の DocumentStore に任せる。Firestore は何もしない（TTL ポリシーが消す）。SQLite は期限の過ぎた行を消す。
    async fn sweep_expired(&self) {
        if let Err(e) = self.fs.sweep_expired().await {
            tracing::warn!("sweep_expired: {e}");
        }
    }

    /// account_id → doc の逆引きを別に持たず、accountId の query_eq でその場で探して消す。
    /// 1 種類の検索が失敗しても他の種類の失効は続け、失敗した種類は query_errors に残す（存否不明）。
    /// 見つけたが消せなかった件数は delete_errors に数える。
    async fn revoke_account(&self, account_id: &str, keep_sid: &str) -> RevocationCounts {
        let mut counts = RevocationCounts::default();
        for (col, n) in [
            ("sessions", &mut counts.sessions),
            ("accessTokens", &mut counts.access_tokens),
            ("refreshTokens", &mut counts.refresh_tokens),
        ] {
            match self.fs.query_eq(col, "accountId", account_id).await {
                Ok(rows) => {
                    for (id, _) in rows
                        .iter()
                        .filter(|(id, _)| col != "sessions" || id != keep_sid)
                    {
                        match self.fs.delete_doc(col, id).await {
                            Ok(()) => *n += 1,
                            Err(e) => {
                                tracing::error!("account_admin: {col} revoke failed id={id}: {e}");
                                counts.delete_errors += 1;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "account_admin: {col} revocation query failed for {account_id}: {e}"
                    );
                    counts.query_errors.push(col);
                }
            }
        }
        counts
    }
}

#[cfg(all(test, feature = "gcp"))]
mod revoke_family_tests {
    use super::*;
    use crate::firestore::{Firestore, fake_firestore};

    fn rt(token: &str, replaced_by: Option<&str>) -> RefreshToken {
        RefreshToken {
            token: token.into(),
            client_id: "rp".into(),
            account_id: "acct".into(),
            scope: "openid offline_access".into(),
            resource: None,
            jkt: None,
            acr: None,
            auth_time: None,
            family_id: "F".into(),
            used: replaced_by.is_some(),
            replaced_by: replaced_by.map(str::to_string),
        }
    }

    /// 鎖を保存し、fail の RT の削除を 1 回だけ 503 にして start から失効させ、残った RT を返す。
    async fn left_after_revoke(
        chain: &[(&str, Option<&str>)],
        fail: &str,
        start: &str,
    ) -> Vec<String> {
        let (host, state) = fake_firestore::spawn().await;
        let s = FirestoreStore::new(Arc::new(Firestore::new_for_test("proj", host)));
        for (t, next) in chain {
            s.save_refresh_token(rt(t, *next)).await.unwrap();
        }
        state.fail_once("DELETE", "refreshTokens", Some(fail));
        s.revoke_refresh_family("F", start).await;
        let mut left = Vec::new();
        for (t, _) in chain {
            if s.get_refresh_token(t).await.unwrap().is_some() {
                left.push(t.to_string());
            }
        }
        left
    }

    #[tokio::test]
    async fn a_failed_delete_is_retried_in_a_self_pointing_chain() {
        assert_eq!(
            left_after_revoke(&[("C1", Some("C1"))], "C1", "C1").await,
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn a_failed_delete_is_retried_in_a_two_link_cycle() {
        assert_eq!(
            left_after_revoke(&[("C1", Some("C2")), ("C2", Some("C1"))], "C1", "C1").await,
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn a_failed_delete_in_the_middle_of_a_line_is_retried() {
        let chain = [("R1", Some("R2")), ("R2", Some("R3")), ("R3", None)];
        assert_eq!(
            left_after_revoke(&chain, "R2", "R1").await,
            Vec::<String>::new()
        );
    }

    /// 失効が RT1 を読んでから消すまでの間に、RT1 のローテーション（本物の RefreshTokenGrant）が来る。
    /// 失効は先に系列の札を書くので、そのローテーションは断られ、新しい RT は渡らない。
    #[tokio::test]
    async fn a_rotation_between_the_read_and_the_delete_does_not_let_the_new_rt_survive() {
        use crate::grants::{GrantHandler, RefreshTokenGrant};
        let (host, state) = fake_firestore::spawn().await;
        let store = Arc::new(FirestoreStore::new(Arc::new(Firestore::new_for_test(
            "proj", host,
        ))));
        let p = Arc::new(
            crate::provider::Provider::new("https://op.example").with_store(store.clone()),
        );
        let client = crate::model::Client {
            client_id: "rp".into(),
            redirect_uris: vec!["https://rp.example/cb".into()],
            post_logout_redirect_uris: vec![],
            initiate_login_uri: None,
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some("hash".into()),
            grant_types: vec!["refresh_token".into()],
            dpop_bound: false,
            jwks: vec![],
            jwks_uri: None,
            require_par: false,
            require_pkce: false,
            id_token_signed_response_alg: None,
            scope: None,
        };
        let form = |t: &str| {
            std::collections::HashMap::from([("refresh_token".to_string(), t.to_string())])
        };
        store.save_refresh_token(rt("RT0", None)).await.unwrap();
        let rt1 = RefreshTokenGrant
            .handle(&p, &client, &form("RT0"), None)
            .await
            .unwrap()
            .refresh_token
            .unwrap();

        let (reached, release) = state.gate("DELETE", "refreshTokens", &rt1);
        let revoking = tokio::spawn({
            let store = store.clone();
            async move { store.revoke_refresh_family("F", "RT0").await }
        });
        reached.notified().await;
        let during = RefreshTokenGrant
            .handle(&p, &client, &form(&rt1), None)
            .await;
        release.notify_one();
        revoking.await.unwrap();

        assert!(
            during.is_err(),
            "札を書いた後のローテーションが通った: {:?}",
            during.map(|r| r.refresh_token)
        );
        for t in ["RT0", rt1.as_str()] {
            assert!(
                store.get_refresh_token(t).await.unwrap().is_none(),
                "失効の後に {t} が残っている"
            );
        }
    }

    /// 札の期限は、書き込みが通った時刻から RT の TTL ＋ 2 日。1 回目の書き込みが遅れて失敗しても、期限は
    /// 最初に試した時刻で決まらない。
    #[tokio::test]
    async fn the_tombstone_expiry_counts_from_the_write_that_succeeded() {
        let (host, state) = fake_firestore::spawn().await;
        let fs = Arc::new(Firestore::new_for_test("proj", host));
        let store = Arc::new(FirestoreStore::new(fs.clone()));
        let (reached, release) = state.gate("PATCH", FAMILY_REVOCATIONS, "F");
        state.fail_once("PATCH", FAMILY_REVOCATIONS, Some("F"));
        let revoking = tokio::spawn({
            let store = store.clone();
            async move { store.revoke_refresh_family("F", "NONE").await }
        });
        reached.notified().await;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let released_at = now();
        release.notify_one();
        revoking.await.unwrap();
        let tomb = fs
            .get_doc(FAMILY_REVOCATIONS, "F")
            .await
            .unwrap()
            .expect("札が無い");
        let expires = fs_h::field_ts_secs(&tomb, "expiresAt").unwrap();
        assert!(
            expires >= released_at + REFRESH_TTL + 2 * 24 * 3600,
            "札の期限が短い: {expires} < {}",
            released_at + REFRESH_TTL + 2 * 24 * 3600
        );
    }
}

#[cfg(all(test, feature = "gcp"))]
mod tests {
    use super::*;
    use crate::firestore::{Firestore, fake_firestore};

    async fn store() -> FirestoreStore {
        store_and_fake().await.0
    }

    async fn store_and_fake() -> (FirestoreStore, Arc<fake_firestore::FakeState>) {
        let (host, state) = fake_firestore::spawn().await;
        (
            FirestoreStore::new(Arc::new(Firestore::new_for_test("proj", host))),
            state,
        )
    }

    crate::store_contract::store_contract_tests!(store);

    fn rt(token: &str, family: &str, replaced_by: Option<&str>) -> RefreshToken {
        RefreshToken {
            token: token.into(),
            client_id: "rp".into(),
            account_id: "acct".into(),
            scope: "openid offline_access".into(),
            resource: None,
            jkt: None,
            acr: None,
            auth_time: None,
            family_id: family.into(),
            used: replaced_by.is_some(),
            replaced_by: replaced_by.map(str::to_string),
        }
    }

    /// Firestore が ID として受け付けない値は、引かずに「無い」とする（400 を 5xx にしない）。
    #[tokio::test]
    async fn a_value_firestore_cannot_hold_is_simply_not_found() {
        let (s, fake) = store_and_fake().await;
        for bad in [
            "a/b".to_string(),
            "x".repeat(1501),
            "__x__".into(),
            String::new(),
            "a.b".into(),
        ] {
            // 引いてしまったら落ちるようにしておく。
            for col in ["authCodes", "accessTokens", "refreshTokens"] {
                for m in ["GET", "PATCH", "DELETE"] {
                    fake.fail_once_with(m, col, None, axum::http::StatusCode::BAD_REQUEST);
                }
            }
            assert!(matches!(
                s.take_code(&bad).await.unwrap(),
                CodeTake::Unknown
            ));
            assert!(s.get_access_token(&bad).await.unwrap().is_none());
            assert!(s.get_refresh_token(&bad).await.unwrap().is_none());
            assert!(!s.mark_refresh_used(&bad, None).await.unwrap());
            s.revoke_access_token(&bad).await.unwrap();
            s.revoke_refresh_token(&bad).await.unwrap();
            fake.clear_failures();
        }
        assert!(issued_shape(&uuid::Uuid::new_v4().simple().to_string()));
    }

    #[tokio::test]
    async fn rotation_fails_closed_when_the_store_errs() {
        for method in ["GET", "PATCH"] {
            let (s, fake) = store_and_fake().await;
            s.save_refresh_token(rt("R1", "F", None)).await.unwrap();
            fake.fail_once(method, "refreshTokens", Some("R1"));
            // 「使用済み」（false）ではなく誤りとして返す。false だと invalid_grant になり、RP が RT を捨てる。
            assert!(
                s.mark_refresh_used("R1", Some("R2")).await.is_err(),
                "{method} の 503 を誤りとして返さなかった"
            );
            assert!(
                !s.get_refresh_token("R1").await.unwrap().unwrap().used,
                "{method} の 503 で使用済みになった"
            );
        }
    }

    #[tokio::test]
    async fn consuming_an_interaction_fails_closed_when_the_store_errs() {
        for method in ["GET", "DELETE"] {
            let (s, fake) = store_and_fake().await;
            let i = Interaction {
                uid: "U1".into(),
                raw_query: String::new(),
                account_id: None,
                auth_time: None,
                request_uri: None,
                browser_binding: String::new(),
            };
            s.save_interaction(i).await;
            fake.fail_once(method, "interactions", Some("U1"));
            assert!(
                !s.consume_interaction("U1").await,
                "{method} の 503 で消費が通ってしまった"
            );
            assert!(
                s.get_interaction("U1").await.is_some(),
                "{method} の 503 で interaction が消えた"
            );
        }
    }

    /// 読んだ後の CAS 削除が 404（並行する削除に先を越された）なら、消費は通らない。
    #[tokio::test]
    async fn consuming_an_interaction_that_another_request_deleted_first_fails() {
        let (s, fake) = store_and_fake().await;
        let i = Interaction {
            uid: "U1".into(),
            raw_query: String::new(),
            account_id: None,
            auth_time: None,
            request_uri: None,
            browser_binding: String::new(),
        };
        s.save_interaction(i).await;
        fake.fail_once_with(
            "DELETE",
            "interactions",
            Some("U1"),
            axum::http::StatusCode::NOT_FOUND,
        );
        assert!(
            !s.consume_interaction("U1").await,
            "削除の 404 で消費が通ってしまった"
        );
    }
}
