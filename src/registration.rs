//! メール確認つき passkey 登録の永続化。Firestore を使う。
//! - emailChallenges/{token}: メール所有確認待ち（email, expiresAt）。30分・単回。
//! - webauthnChallenges/{challenge}: passkey セレモニーのチャレンジ（email, kind, uid, accountId, expiresAt）。5分・単回。
//! - accounts/{email}: 確認済みユーザー（accountId, disabled, credentialsMigrated, ...）。
//! - credentials/{credentialId}: passkey（email, accountId, pubX, pubY, signCount, aaguid, createdAt, lastUsedAt）。
//! - accountsByUuid/{accountId}: accounts/{email} への逆引き（email のみ）。discoverable な
//!   passkey ログイン（userHandle = accountId しか分からない）で email を引くために使う。
//!   sub/account_id は email ではなく accountId（登録時に発行する UUID v4）。

use crate::firestore::{self, Firestore};
use crate::jws::b64url;
use crate::webauthn::RegOutcome;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

// メール送信 → アプリ起動 → verify-email → options → Face ID → verify までを許容できる
// 余裕のある TTL。短すぎると passkey 作成中にトークン失効で 400 になる。
const EMAIL_TTL_SECS: u64 = 30 * 60;
// 招待リンクは管理者が送り、受け手がいつ開くか分からないので数日もたせる。
const INVITE_TTL_SECS: u64 = 7 * 24 * 60 * 60;
// 復旧のリンクは、メールを読める人に passkey を足させる。開いてすぐ使う前提で短くする。
pub(crate) const RECOVERY_TTL_SECS: u64 = 15 * 60;
/// emailChallenges の purpose。登録の token と取り違えないよう、登録と招待の口はこれを持つ token を受けない。
const PURPOSE_RECOVERY: &str = "recovery";
pub(crate) const CEREMONY_TTL_SECS: u64 = 5 * 60;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn random_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("OS の乱数源");
    b64url(buf)
}

fn token_ok(t: &str) -> bool {
    (20..=100).contains(&t.len())
        && t.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/* ===== email 所有確認チャレンジ ===== */

/// ログイン画面から来たときの、元の interaction（uid）と client。メールの token の文書に持ち、URL には載せない。
/// 呼び出し側が「このブラウザが始めた、生きた interaction」と確かめたものだけを入れる。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CameFrom {
    pub uid: String,
    pub client_id: String,
}

fn with_came_from(mut fields: serde_json::Value, from: &CameFrom) -> serde_json::Value {
    if !from.uid.is_empty() {
        fields["uid"] = firestore::s(&from.uid);
        fields["clientId"] = firestore::s(&from.client_id);
    }
    fields
}

#[cfg(all(test, feature = "gcp"))]
pub async fn create_email_challenge(fs: &Firestore, email: &str) -> Result<String, String> {
    create_email_challenge_from(fs, email, &CameFrom::default()).await
}

pub async fn create_email_challenge_from(fs: &Firestore, email: &str, from: &CameFrom) -> Result<String, String> {
    let token = random_token();
    let fields = json!({
        "email": firestore::s(email),
        "expiresAt": firestore::ts(&firestore::rfc3339(now() + EMAIL_TTL_SECS)),
    });
    fs.set_doc("emailChallenges", &token, with_came_from(fields, from)).await?;
    Ok(token)
}

/// token の文書が持つ CameFrom。無い・読めないときは空。
pub async fn came_from(fs: &Firestore, token: &str) -> CameFrom {
    if !token_ok(token) {
        return CameFrom::default();
    }
    match fs.get_doc("emailChallenges", token).await {
        Ok(Some(f)) => CameFrom {
            uid: firestore::field_str(&f, "uid").unwrap_or("").to_string(),
            client_id: firestore::field_str(&f, "clientId").unwrap_or("").to_string(),
        },
        _ => CameFrom::default(),
    }
}

/// 招待（RP の管理者が発行を頼む登録リンク）。emailChallenges に置くので、
/// passkey の options / verify は通常の登録と同じ口をそのまま使う。
/// returnTo は登録後の戻り先（RP の登録済み origin 配下であることは呼び出し側が確かめる）。
pub async fn create_invite_challenge(fs: &Firestore, email: &str, return_to: &str) -> Result<String, String> {
    let token = random_token();
    fs.set_doc(
        "emailChallenges",
        &token,
        json!({
            "email": firestore::s(email),
            "returnTo": firestore::s(return_to),
            "expiresAt": firestore::ts(&firestore::rfc3339(now() + INVITE_TTL_SECS)),
        }),
    )
    .await?;
    Ok(token)
}

/// 招待の token を消費せず覗き、(email, returnTo) を返す。returnTo を持たない（通常の登録の）token は None。
pub async fn peek_invite(fs: &Firestore, token: &str) -> Result<Option<(String, String)>, String> {
    if !token_ok(token) {
        return Ok(None);
    }
    let fields = match fs.get_doc("emailChallenges", token).await? {
        Some(f) => f,
        None => return Ok(None),
    };
    if challenge_expired(&fields) {
        return Ok(None);
    }
    match (firestore::field_str(&fields, "email"), firestore::field_str(&fields, "returnTo")) {
        (Some(e), Some(r)) if !r.is_empty() => Ok(Some((e.to_string(), r.to_string()))),
        _ => Ok(None),
    }
}

/// 復旧のリンク（登録済みの人が、メールで確かめて passkey を 1 本足す）。
#[cfg(all(test, feature = "gcp"))]
pub async fn create_recovery_challenge(fs: &Firestore, email: &str) -> Result<String, String> {
    create_recovery_challenge_from(fs, email, &CameFrom::default()).await
}

pub async fn create_recovery_challenge_from(fs: &Firestore, email: &str, from: &CameFrom) -> Result<String, String> {
    let token = random_token();
    let fields = json!({
        "email": firestore::s(email),
        "purpose": firestore::s(PURPOSE_RECOVERY),
        "expiresAt": firestore::ts(&firestore::rfc3339(now() + RECOVERY_TTL_SECS)),
    });
    fs.set_doc("emailChallenges", &token, with_came_from(fields, from)).await?;
    Ok(token)
}

fn token_email(fields: &serde_json::Value, recovery: bool) -> Option<String> {
    if challenge_expired(fields) {
        return None;
    }
    let is_recovery = firestore::field_str(fields, "purpose") == Some(PURPOSE_RECOVERY);
    if is_recovery != recovery {
        return None;
    }
    firestore::field_str(fields, "email").map(|s| s.to_string())
}

async fn peek_token(fs: &Firestore, token: &str, recovery: bool) -> Result<Option<String>, String> {
    if !token_ok(token) {
        return Ok(None);
    }
    Ok(fs.get_doc("emailChallenges", token).await?.and_then(|f| token_email(&f, recovery)))
}

async fn consume_token(fs: &Firestore, token: &str, recovery: bool) -> Result<Option<String>, String> {
    if !token_ok(token) {
        return Ok(None);
    }
    Ok(fs.take_doc("emailChallenges", token).await?.and_then(|f| token_email(&f, recovery)))
}

/// 消費せず email を覗く（passkey options 生成時に使用）。復旧の token は None。
pub async fn peek_email_challenge(fs: &Firestore, token: &str) -> Result<Option<String>, String> {
    peek_token(fs, token, false).await
}

/// 単回消費して email を返す（passkey verify 成功時）。復旧の token は None。
pub async fn consume_email_challenge(fs: &Firestore, token: &str) -> Result<Option<String>, String> {
    consume_token(fs, token, false).await
}

pub async fn peek_recovery(fs: &Firestore, token: &str) -> Result<Option<String>, String> {
    peek_token(fs, token, true).await
}

pub async fn consume_recovery(fs: &Firestore, token: &str) -> Result<Option<String>, String> {
    consume_token(fs, token, true).await
}

/* ===== WebAuthn セレモニーチャレンジ ===== */

/// passkey セレモニーの種別。文字列比較ミスを型で防ぐ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKind {
    Reg,
    Auth,
    CibaApprove,
}

impl ChallengeKind {
    fn as_str(self) -> &'static str {
        match self {
            ChallengeKind::Reg => "reg",
            ChallengeKind::Auth => "auth",
            ChallengeKind::CibaApprove => "ciba-approve",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "reg" => Some(ChallengeKind::Reg),
            "auth" => Some(ChallengeKind::Auth),
            "ciba-approve" => Some(ChallengeKind::CibaApprove),
            _ => None,
        }
    }
}

pub async fn create_webauthn_challenge(
    fs: &Firestore,
    email: &str,
    kind: ChallengeKind,
    uid: &str,
    account_id: &str,
) -> Result<String, String> {
    let challenge = random_token();
    fs.set_doc(
        "webauthnChallenges",
        &challenge,
        json!({
            "email": firestore::s(email),
            "kind": firestore::s(kind.as_str()),
            "uid": firestore::s(uid),
            "accountId": firestore::s(account_id),
            "expiresAt": firestore::ts(&firestore::rfc3339(now() + CEREMONY_TTL_SECS)),
        }),
    )
    .await?;
    Ok(challenge)
}

/// (email, kind, uid, accountId) を単回消費で返す。kind が未知なら None。
/// accountId は ChallengeKind::Reg のときのみ意味を持つ（登録時に払い出した/再利用する UUID）。
pub async fn consume_webauthn_challenge(
    fs: &Firestore,
    challenge: &str,
) -> Result<Option<(String, ChallengeKind, String, String)>, String> {
    if !token_ok(challenge) {
        return Ok(None);
    }
    let Some(fields) = fs.take_doc("webauthnChallenges", challenge).await? else {
        return Ok(None);
    };
    if challenge_expired(&fields) {
        return Ok(None);
    }
    let kind = match ChallengeKind::parse(firestore::field_str(&fields, "kind").unwrap_or("")) {
        Some(k) => k,
        None => return Ok(None),
    };
    let email = firestore::field_str(&fields, "email").unwrap_or("").to_string();
    let uid = firestore::field_str(&fields, "uid").unwrap_or("").to_string();
    let account_id = firestore::field_str(&fields, "accountId").unwrap_or("").to_string();
    Ok(Some((email, kind, uid, account_id)))
}

/* ===== アカウントと passkey ===== */
//
// accounts/{email} はアカウント（accountId・disabled など）。passkey は credentials/{credentialId} に
// 1 本 1 文書で置く（1 アカウントに複数）。
//
// 古い形では passkey を accounts/{email} のフィールド（credentialId・pubX・pubY・signCount・aaguid）に
// 1 本だけ持っていた。どちらで読むかは accounts の credentialsMigrated で決める（「credentials に
// 無ければ古いフィールド」とすると、消した passkey が古いフィールドから生き返るため）。
// 古いフィールドは、前の版へ戻す窓が閉じるまで消さない。新しいアカウントにも最初の 1 本を写しておく
// （前の版へ戻してもログインできるように）。

const MIGRATED: &str = "credentialsMigrated";

pub struct Account {
    pub email: String,
    /// 空なら移行前の壊れた文書（accountId 未発行）。呼び出し側で断る。
    pub account_id: String,
    /// 管理者による凍結フラグ。true ならログイン/CIBA承認を拒否する
    /// （[`crate::account_admin`] 参照）。欠落時は false。
    pub disabled: bool,
    pub created_at: u64,
    /// 最後にメールで passkey を足した（復旧した）時刻と、そのとき足した passkey。無ければ 0 と空。
    pub recovered_at: u64,
    pub recovered_with: String,
    migrated: bool,
    /// 移行前のアカウントが accounts のフィールドに持つ passkey。
    legacy: Option<Credential>,
}

#[derive(Clone)]
pub struct Credential {
    pub credential_id: String,
    pub pub_x: String,
    pub pub_y: String,
    pub sign_count: u32,
    pub aaguid: String,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
}

fn credential_from(id: &str, f: &serde_json::Value) -> Credential {
    Credential {
        credential_id: id.to_string(),
        pub_x: firestore::field_str(f, "pubX").unwrap_or("").to_string(),
        pub_y: firestore::field_str(f, "pubY").unwrap_or("").to_string(),
        sign_count: firestore::field_u64(f, "signCount").unwrap_or(0) as u32,
        aaguid: firestore::field_str(f, "aaguid").unwrap_or("").to_string(),
        created_at: firestore::field_ts_secs(f, "createdAt").unwrap_or(0),
        last_used_at: firestore::field_ts_secs(f, "lastUsedAt"),
    }
}

fn account_from(email: &str, f: &serde_json::Value) -> Account {
    let migrated = firestore::field_bool(f, MIGRATED).unwrap_or(false);
    let legacy = (!migrated)
        .then(|| firestore::field_str(f, "credentialId").map(|id| credential_from(id, f)))
        .flatten();
    Account {
        email: email.to_string(),
        account_id: firestore::field_str(f, "accountId").unwrap_or("").to_string(),
        disabled: firestore::field_bool(f, "disabled").unwrap_or(false),
        created_at: firestore::field_ts_secs(f, "createdAt").unwrap_or(0),
        recovered_at: firestore::field_ts_secs(f, "recoveredAt").unwrap_or(0),
        recovered_with: firestore::field_str(f, "recoveredWith").unwrap_or("").to_string(),
        migrated,
        legacy,
    }
}

pub async fn get_account(fs: &Firestore, email: &str) -> Result<Option<Account>, String> {
    Ok(fs.get_doc("accounts", email).await?.map(|f| account_from(email, &f)))
}

pub async fn list_credentials(fs: &Firestore, account: &Account) -> Result<Vec<Credential>, String> {
    if !account.migrated {
        return Ok(account.legacy.iter().cloned().collect());
    }
    if account.account_id.is_empty() {
        return Ok(vec![]);
    }
    let mut v: Vec<Credential> = fs
        .query_eq("credentials", "accountId", &account.account_id)
        .await?
        .iter()
        .map(|(id, f)| credential_from(id, f))
        .collect();
    v.sort_by(|a, b| (a.created_at, &a.credential_id).cmp(&(b.created_at, &b.credential_id)));
    Ok(v)
}

/// assertion が名乗った credential id を、このアカウントの passkey として引く。
/// 文書を id で直に引き、持ち主の accountId が合うことを確かめる。
pub async fn find_credential(fs: &Firestore, account: &Account, credential_id: &str) -> Result<Option<Credential>, String> {
    if !account.migrated {
        return Ok(account.legacy.clone().filter(|c| c.credential_id == credential_id));
    }
    if account.account_id.is_empty() || !credential_id_ok(credential_id) {
        return Ok(None);
    }
    Ok(fs
        .get_doc("credentials", credential_id)
        .await?
        .filter(|f| firestore::field_str(f, "accountId") == Some(account.account_id.as_str()))
        .map(|f| credential_from(credential_id, &f)))
}

/// 登録済み（passkey が 1 本以上ある）か。passkey を全部消したアカウントは、同じ accountId のまま
/// 登録し直せる。
/// accountId の無い壊れた文書は登録済みとして扱う（登録し直しで上書きさせない。前の版と同じ）。
pub async fn has_passkey(fs: &Firestore, email: &str) -> Result<bool, String> {
    match get_account(fs, email).await? {
        Some(a) if a.account_id.is_empty() => Ok(true),
        Some(a) => Ok(!list_credentials(fs, &a).await?.is_empty()),
        None => Ok(false),
    }
}

/// Firestore の文書 ID にできる credential id か（b64url の 1〜1023 バイト）。
/// Firestore が断るのは `__.*__` に当たる ID だけ。`__` で始まるだけの id は、乱数の id の
/// 4096 本に 1 本が当たるので、断ると正しい passkey の登録が失敗する。
fn credential_id_ok(id: &str) -> bool {
    (1..=1400).contains(&id.len())
        && !(id.len() >= 4 && id.starts_with("__") && id.ends_with("__"))
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn credential_fields(email: &str, account_id: &str, c: &Credential) -> serde_json::Value {
    let mut f = json!({
        "email": firestore::s(email),
        "accountId": firestore::s(account_id),
        "pubX": firestore::s(&c.pub_x),
        "pubY": firestore::s(&c.pub_y),
        "signCount": firestore::int(c.sign_count as u64),
        "aaguid": firestore::s(&c.aaguid),
        "createdAt": firestore::ts(&firestore::rfc3339(c.created_at)),
    });
    if let Some(t) = c.last_used_at {
        f["lastUsedAt"] = firestore::ts(&firestore::rfc3339(t));
    }
    f
}

/// credentials/{id} を新しく作る。同じ id の文書が既にあれば上書きせず誤りにする
/// （別のアカウントの passkey を、同じ id を名乗る登録で乗っ取らせない）。
/// まだ移していないアカウントの passkey は credentials に無いので、accounts の古いフィールドも見る
/// （id はログインの options で誰でも知れる。先に取られると、持ち主がいつまでも移れなくなる）。
async fn create_credential(fs: &Firestore, email: &str, account_id: &str, c: &Credential) -> Result<(), String> {
    if !credential_id_ok(&c.credential_id) {
        return Err(format!("credential id not storable (len {})", c.credential_id.len()));
    }
    let holders = fs.query_eq("accounts", "credentialId", &c.credential_id).await?;
    if holders.iter().any(|(_, f)| firestore::field_str(f, "accountId") != Some(account_id)) {
        return Err("credential id already registered".into());
    }
    if fs.create_if_absent("credentials", &c.credential_id, credential_fields(email, account_id, c)).await? {
        Ok(())
    } else {
        Err("credential id already registered".into())
    }
}

/// 移行前のアカウントの passkey を credentials へ写し、印を付ける。写し終えてから印を付けるので、
/// 途中で止まっても古い形のまま読める。既に写してあれば（前回の途中で止まった）その文書を使う。
/// 返り値は、このときに移したか。
#[cfg(feature = "gcp")]
pub async fn migrate_account(fs: &Firestore, email: &str) -> Result<bool, String> {
    let lock = lock_account(fs, email).await?;
    let r = migrate_locked(fs, email).await;
    lock.release().await;
    r
}

async fn migrate_locked(fs: &Firestore, email: &str) -> Result<bool, String> {
    let Some(a) = get_account(fs, email).await? else {
        return Ok(false);
    };
    if a.migrated {
        return Ok(false);
    }
    if a.account_id.is_empty() {
        return Err(format!("{email}: accountId missing"));
    }
    if let Some(c) = &a.legacy {
        match create_credential(fs, email, &a.account_id, c).await {
            Ok(()) => {}
            Err(e) => {
                let mine = fs
                    .get_doc("credentials", &c.credential_id)
                    .await?
                    .is_some_and(|f| firestore::field_str(&f, "accountId") == Some(a.account_id.as_str()));
                if !mine {
                    return Err(format!("{email}: {e}"));
                }
            }
        }
    }
    fs.update_field("accounts", email, MIGRATED, firestore::b(true)).await?;
    Ok(true)
}

/// passkey を 1 本足す。アカウントが無ければ作る（account_id は呼び出し側が払い出す）。
/// 在るアカウントには、accountId・disabled・createdAt を引き継いだまま足す。
/// 呼び出し側は、在るアカウントの account_id を渡すこと（登録の options で引き継いでいる）。
///
/// accountsByUuid の逆引きの書き込みが失敗しても登録自体は失敗させない（email 入力でのログインは
/// 影響を受けない、discoverable ログインのみ縮退する）。
pub async fn save_credential(fs: &Firestore, email: &str, account_id: &str, c: &RegOutcome) -> Result<(), String> {
    let lock = lock_account(fs, email).await?;
    let r = save_locked(fs, email, account_id, c).await;
    lock.release().await;
    r
}

async fn save_locked(fs: &Firestore, email: &str, account_id: &str, c: &RegOutcome) -> Result<(), String> {
    let cred = Credential {
        credential_id: c.credential_id.clone(),
        pub_x: c.pub_x.clone(),
        pub_y: c.pub_y.clone(),
        sign_count: c.sign_count,
        aaguid: c.aaguid.clone(),
        created_at: now(),
        last_used_at: None,
    };
    match get_account(fs, email).await? {
        Some(a) => {
            if a.account_id != account_id {
                return Err(format!("account_id mismatch for existing account ({} vs {account_id})", a.account_id));
            }
            if !a.migrated {
                migrate_locked(fs, email).await?;
            }
            let had_none = list_credentials(fs, &get_account(fs, email).await?.ok_or("account vanished")?).await?.is_empty();
            create_credential(fs, email, account_id, &cred).await?;
            if had_none {
                // passkey を全部消して登録し直したとき。古いフィールドを新しい 1 本に向ける
                // （前の版へ戻したとき、消した passkey が生き返らず、新しい passkey で入れるように）。
                point_mirror(fs, email, Some(&cred)).await?;
            }
        }
        None => {
            // アカウントを先に作る（同じ email の登録が重なったら、負けた側は何も残さない）。
            // 古いフィールド（前の版が読む形）も持たせる。新しい版は印を見て読まない。
            let mut f = credential_fields(email, account_id, &cred);
            f["credentialId"] = firestore::s(&cred.credential_id);
            f["verified"] = firestore::b(true);
            f["disabled"] = firestore::b(false);
            f[MIGRATED] = firestore::b(true);
            if !fs.create_if_absent("accounts", email, f).await? {
                return Err("account created concurrently".into());
            }
            if let Err(e) = create_credential(fs, email, account_id, &cred).await {
                if let Err(d) = fs.delete_doc("accounts", email).await {
                    tracing::error!("save_credential: account left without its passkey: {d}");
                }
                return Err(e);
            }
        }
    }
    if let Err(e) = fs
        .set_doc("accountsByUuid", account_id, json!({ "email": firestore::s(email) }))
        .await
    {
        tracing::error!("accountsByUuid index write failed for account_id={account_id}: {e}");
    }
    Ok(())
}

/// 古いフィールド（前の版が読む 1 本）を c に向ける。None なら空にする（前の版へ戻しても、
/// 消した passkey で入れないように）。createdAt はアカウントの登録日時なので書き換えない。
async fn point_mirror(fs: &Firestore, email: &str, c: Option<&Credential>) -> Result<(), String> {
    let (id, x, y, count, aaguid) = match c {
        Some(c) => (c.credential_id.as_str(), c.pub_x.as_str(), c.pub_y.as_str(), c.sign_count, c.aaguid.as_str()),
        None => ("", "", "", 0, ""),
    };
    fs.update_fields(
        "accounts",
        email,
        json!({
            "credentialId": firestore::s(id),
            "pubX": firestore::s(x),
            "pubY": firestore::s(y),
            "signCount": firestore::int(count as u64),
            "aaguid": firestore::s(aaguid),
        }),
    )
    .await
}

#[derive(Debug, PartialEq, Eq)]
pub enum RemoveOutcome {
    Removed,
    NotFound,
    /// 最後の 1 本は本人の操作では消さない（入る手段が無くなる）。
    LastOne,
}

/// 本人が passkey を 1 本消す。
pub async fn remove_credential(fs: &Firestore, email: &str, credential_id: &str) -> Result<RemoveOutcome, String> {
    let lock = lock_account(fs, email).await?;
    let r = remove_locked(fs, email, credential_id).await;
    lock.release().await;
    r
}

async fn remove_locked(fs: &Firestore, email: &str, credential_id: &str) -> Result<RemoveOutcome, String> {
    migrate_locked(fs, email).await?;
    let Some(a) = get_account(fs, email).await? else {
        return Ok(RemoveOutcome::NotFound);
    };
    let creds = list_credentials(fs, &a).await?;
    let rest: Vec<&Credential> = creds.iter().filter(|c| c.credential_id != credential_id).collect();
    // 古いフィールドが一覧に無い passkey を指していたら（前回の向け直しが途中で失敗した）、ここで直す。
    // 消すときは、消す前に向け直す（向け直しが失敗したら消さない）。
    let mirrored = fs
        .get_doc("accounts", email)
        .await?
        .and_then(|f| firestore::field_str(&f, "credentialId").map(str::to_string))
        .unwrap_or_default();
    if !mirrored.is_empty()
        && (mirrored == credential_id || !creds.iter().any(|c| c.credential_id == mirrored))
        && let Some(first) = rest.first()
    {
        point_mirror(fs, email, Some(first)).await?;
    }
    if rest.len() == creds.len() {
        return Ok(RemoveOutcome::NotFound);
    }
    if rest.is_empty() {
        return Ok(RemoveOutcome::LastOne);
    }
    fs.delete_doc("credentials", credential_id).await?;
    Ok(RemoveOutcome::Removed)
}

/// 足したばかりの passkey を取り消す（足している間にセッションが失効していたとき）。最後の 1 本でも消し、
/// 古いフィールドが指していれば、残りの 1 本へ向け直す（無ければ空にする）。
pub async fn discard_credential(fs: &Firestore, email: &str, credential_id: &str) -> Result<(), String> {
    let lock = lock_account(fs, email).await?;
    let r = async {
        let Some(a) = get_account(fs, email).await? else {
            return Ok(());
        };
        let rest: Vec<Credential> =
            list_credentials(fs, &a).await?.into_iter().filter(|c| c.credential_id != credential_id).collect();
        let mirrored = fs.get_doc("accounts", email).await?;
        if mirrored.as_ref().and_then(|f| firestore::field_str(f, "credentialId")) == Some(credential_id) {
            point_mirror(fs, email, rest.first()).await?;
        }
        fs.delete_doc("credentials", credential_id).await
    }
    .await;
    lock.release().await;
    r
}

/// passkey を全部消し、アカウントは残す（同じ accountId のまま登録し直せる）。消した本数を返す。
/// アカウントが無ければ None。
pub async fn remove_all_credentials(fs: &Firestore, email: &str) -> Result<Option<usize>, String> {
    let lock = lock_account(fs, email).await?;
    let r = remove_all_locked(fs, email).await;
    lock.release().await;
    r
}

async fn remove_all_locked(fs: &Firestore, email: &str) -> Result<Option<usize>, String> {
    migrate_locked(fs, email).await?;
    let Some(a) = get_account(fs, email).await? else {
        return Ok(None);
    };
    point_mirror(fs, email, None).await?;
    Ok(Some(delete_all_credentials(fs, &a).await?))
}

/* ===== アカウントごとの鍵 ===== */
//
// passkey を足す・消す・移す操作は、本数を読んでから書くまでが別々の要求になる。同じアカウントで重なると、
// 2 本を同時に消して 0 本になったり、全部消した直後に足した 1 本が残ったりする。accountLocks/{email} を
// 作れた操作だけを通し、終わったら消す。落ちた操作が残した鍵は期限で外す。

const LOCKS: &str = "accountLocks";
const LOCK_TTL_SECS: u64 = 30;

#[must_use]
struct AccountLock<'a> {
    fs: &'a Firestore,
    email: String,
}

impl AccountLock<'_> {
    async fn release(self) {
        if let Err(e) = self.fs.delete_doc(LOCKS, &self.email).await {
            tracing::warn!("account lock not released (expires in {LOCK_TTL_SECS}s): {e}");
        }
    }
}

async fn lock_account<'a>(fs: &'a Firestore, email: &str) -> Result<AccountLock<'a>, String> {
    for _ in 0..30 {
        let f = json!({ "expiresAt": firestore::ts(&firestore::rfc3339(now() + LOCK_TTL_SECS)) });
        if fs.create_if_absent(LOCKS, email, f).await? {
            return Ok(AccountLock { fs, email: email.to_string() });
        }
        if let Some((f, update_time)) = fs.get_doc_with_update_time(LOCKS, email).await?
            && firestore::field_ts_secs(&f, "expiresAt").is_none_or(|t| t <= now())
        {
            fs.delete_doc_if_unchanged(LOCKS, email, &update_time).await?;
            continue;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Err("account busy".into())
}

/// ログインで使った passkey の signCount と lastUsedAt を書く。文書が在るときだけ書く
/// （並行して消された passkey を作り直さない）。
pub async fn record_use(fs: &Firestore, account: &Account, c: &Credential, sign_count: u32) -> Result<(), String> {
    if !account.migrated {
        return fs.update_field("accounts", &account.email, "signCount", firestore::int(sign_count as u64)).await;
    }
    fs.update_fields(
        "credentials",
        &c.credential_id,
        json!({
            "signCount": firestore::int(sign_count as u64),
            "lastUsedAt": firestore::ts(&firestore::rfc3339(now())),
        }),
    )
    .await
}

pub struct AccountSummary {
    pub email: String,
    pub account_id: String,
    pub disabled: bool,
    pub passkeys: usize,
    pub created_at: u64,
}

/// accounts/ 全件を列挙する（管理UIの一覧表示用）。accountId が欠落/空の壊れたドキュメントは
/// tracing::error! で痕跡を残しつつスキップする（1件の壊れたドキュメントで一覧全体が失敗しないようにする）。
pub async fn list_accounts(fs: &Firestore) -> Result<Vec<AccountSummary>, String> {
    let (rows, creds) = tokio::try_join!(fs.list_collection("accounts"), fs.list_collection("credentials"))?;
    let mut counts: std::collections::HashMap<String, usize> = Default::default();
    for (_, f, _) in &creds {
        if let Some(a) = firestore::field_str(f, "accountId") {
            *counts.entry(a.to_string()).or_default() += 1;
        }
    }
    let mut out = Vec::with_capacity(rows.len());
    for (email, fields, _update_time) in rows {
        let a = account_from(&email, &fields);
        if a.account_id.is_empty() {
            tracing::error!("list_accounts: {email}: accountId missing/empty, skipping");
            continue;
        }
        let passkeys = if a.migrated { counts.get(&a.account_id).copied().unwrap_or(0) } else { a.legacy.iter().count() };
        out.push(AccountSummary { email, account_id: a.account_id, disabled: a.disabled, passkeys, created_at: a.created_at });
    }
    Ok(out)
}

/// 試験用: アカウントの passkey が 1 本ならそれを返す（0 本なら None、2 本以上なら panic）。
#[cfg(all(test, feature = "gcp"))]
pub async fn sole_credential(fs: &Firestore, email: &str) -> Option<Credential> {
    let a = get_account(fs, email).await.unwrap()?;
    let mut v = list_credentials(fs, &a).await.unwrap();
    assert!(v.len() <= 1, "{email}: passkey が {} 本", v.len());
    v.pop()
}

/// アカウントの passkey を全部消す（アカウントを消すとき）。
/// 印の有無に関わらず accountId で引く（写し終えて印を付ける前に止まったアカウントの分も消す）。
pub async fn delete_all_credentials(fs: &Firestore, account: &Account) -> Result<usize, String> {
    if account.account_id.is_empty() {
        return Ok(0);
    }
    let rows = fs.query_eq("credentials", "accountId", &account.account_id).await?;
    for (id, _) in &rows {
        fs.delete_doc("credentials", id).await?;
    }
    Ok(rows.len())
}

/// disabled フラグだけを部分更新する（全体置換にしない。並行するログインの signCount の書き込みと
/// 互いを巻き戻さないため）。account_admin::disable_account/enable_account から呼ばれる。
/// 呼び出し側が事前に get_account でアカウントの存在を確認している前提（重複読み取りを避けるため、
/// ここでは再確認しない。存在しなければ update_field が currentDocument.exists 制約で
/// エラーを返す）。
pub async fn set_disabled(fs: &Firestore, email: &str, disabled: bool) -> Result<(), String> {
    fs.update_field("accounts", email, "disabled", firestore::b(disabled)).await
}

/// メールで passkey を足す直前に、その時刻と足す passkey を残す。この時刻までに作られたほかの passkey は、
/// しばらく本人の画面から消せない（メールを奪った人が、本人の passkey を消して締め出せないように）。
pub async fn mark_recovered(fs: &Firestore, email: &str, credential_id: &str) -> Result<(), String> {
    fs.update_fields(
        "accounts",
        email,
        json!({
            "recoveredAt": firestore::ts(&firestore::rfc3339(now())),
            "recoveredWith": firestore::s(credential_id),
        }),
    )
    .await
}

/// accountId(UUID) -> email の逆引き。discoverable ログイン（userHandle=accountId のみ判明）で使う。
pub async fn find_email_by_account_id(
    fs: &Firestore,
    account_id: &str,
) -> Result<Option<String>, String> {
    let fields = match fs.get_doc("accountsByUuid", account_id).await? {
        Some(f) => f,
        None => return Ok(None),
    };
    Ok(firestore::field_str(&fields, "email").map(|s| s.to_string()))
}

/* ===== ユーザープロフィール（編集可能 claim、passkey とは別 collection） ===== */

/// profiles/{email} の編集可能 claim を返す（未保存なら空）。
pub async fn get_profile(
    fs: &Firestore,
    email: &str,
) -> Result<std::collections::HashMap<String, String>, String> {
    let mut out = std::collections::HashMap::new();
    let fields = match fs.get_doc("profiles", email).await? {
        Some(f) => f,
        None => return Ok(out),
    };
    for k in crate::claims::EDITABLE {
        // 空にする保存は field を消すが、それより前に空のまま保存された値も、未設定として扱う。
        if let Some(v) = firestore::field_str(&fields, k).filter(|v| !v.is_empty()) {
            out.insert(k.to_string(), v.to_string());
        }
    }
    Ok(out)
}

const PROFILE_VALUE_MAX_CHARS: usize = 80;

/// 表示の向きを変える書式文字（Unicode の Bidi_Control）。RP の画面で氏名などの見た目を偽れるので断る。
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// プロフィールの値を前後の空白を除いて受け取る。空なら None、長すぎる・制御文字や向きを変える文字を含むなら Err。
pub fn normalize_profile_value(raw: &str) -> Result<Option<String>, ()> {
    let v = raw.trim();
    if v.is_empty() {
        return Ok(None);
    }
    if v.chars().count() > PROFILE_VALUE_MAX_CHARS || v.chars().any(|c| c.is_control() || is_bidi_control(c)) {
        return Err(());
    }
    Ok(Some(v.to_string()))
}

#[derive(Debug)]
pub enum ProfileError {
    Invalid(String),
    Store(String),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileError::Invalid(k) => write!(f, "invalid {k}"),
            ProfileError::Store(e) => f.write_str(e),
        }
    }
}

/// profiles/{email} の、updates に在る field だけを書く（EDITABLE 以外は無視、空にした field は消す）。
/// 他の field には触れないので、RP の PUT /me/profile と /account の保存が重なっても互いの更新を消さない。
/// 値は登録の画面と同じ検査（normalize_profile_value）を通し、1 つでも通らなければ何も書かない。
pub async fn save_profile(
    fs: &Firestore,
    email: &str,
    updates: &std::collections::HashMap<String, String>,
) -> Result<(), ProfileError> {
    let mut fields = serde_json::Map::new();
    fields.insert("email".into(), firestore::s(email));
    let mut remove = Vec::new();
    for (k, v) in updates {
        if crate::claims::EDITABLE.contains(&k.as_str()) {
            match normalize_profile_value(v).map_err(|()| ProfileError::Invalid(k.clone()))? {
                Some(v) => {
                    fields.insert(k.clone(), firestore::s(&v));
                }
                None => remove.push(k.clone()),
            }
        }
    }
    fs.merge_fields("profiles", email, serde_json::Value::Object(fields), &remove)
        .await
        .map_err(ProfileError::Store)
}

fn challenge_expired(fields: &serde_json::Value) -> bool {
    let exp = fields
        .get("expiresAt")
        .and_then(|v| v.get("timestampValue"))
        .and_then(|v| v.as_str())
        .map(crate::firestore::parse_rfc3339_secs)
        .unwrap_or(0);
    exp < now()
}

#[cfg(all(test, feature = "gcp"))]
mod tests {
    use std::assert_matches;
    use super::*;
    use crate::firestore::fake_firestore;

    fn outcome(account_id: &str) -> RegOutcome {
        RegOutcome {
            credential_id: format!("cred-{account_id}"),
            pub_x: "x".into(),
            pub_y: "y".into(),
            sign_count: 0,
            aaguid: String::new(),
        }
    }

    #[test]
    fn an_id_that_only_starts_with_two_underscores_is_storable() {
        assert!(credential_id_ok("__Xq3v9mPf0aB1cD2eF3gH4"));
        assert!(credential_id_ok("___"), "`__.*__` は 4 文字から");
        assert!(!credential_id_ok("____"));
        assert!(!credential_id_ok("__abc__"));
        assert!(!credential_id_ok("a/b"));
    }

    #[tokio::test]
    async fn invite_token_is_consumed_once() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        let t = create_invite_challenge(&fs, "a@example.com", "https://rp.example/").await.unwrap();
        assert_eq!(consume_email_challenge(&fs, &t).await.unwrap().as_deref(), Some("a@example.com"));
        assert_eq!(consume_email_challenge(&fs, &t).await.unwrap(), None);
    }

    #[tokio::test]
    async fn two_concurrent_consumes_of_one_invite_let_only_one_through() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        let t = create_invite_challenge(&fs, "a@example.com", "https://rp.example/").await.unwrap();
        let (a, b) = tokio::join!(consume_email_challenge(&fs, &t), consume_email_challenge(&fs, &t));
        let through = [a.unwrap(), b.unwrap()].into_iter().flatten().count();
        assert_eq!(through, 1);
    }

    #[tokio::test]
    async fn webauthn_challenge_is_consumed_once() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        let c = create_webauthn_challenge(&fs, "a@example.com", ChallengeKind::Auth, "", "").await.unwrap();
        let first = consume_webauthn_challenge(&fs, &c).await.unwrap();
        assert_eq!(first.map(|(e, k, _, _)| (e, k)), Some(("a@example.com".to_string(), ChallengeKind::Auth)));
        assert_eq!(consume_webauthn_challenge(&fs, &c).await.unwrap(), None);
    }

    #[tokio::test]
    async fn two_concurrent_consumes_of_one_webauthn_challenge_let_only_one_through() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        let c = create_webauthn_challenge(&fs, "a@example.com", ChallengeKind::Auth, "", "").await.unwrap();
        let (a, b) = tokio::join!(consume_webauthn_challenge(&fs, &c), consume_webauthn_challenge(&fs, &c));
        let through = [a.unwrap(), b.unwrap()].into_iter().flatten().count();
        assert_eq!(through, 1);
    }

    #[tokio::test]
    async fn save_profile_refuses_what_the_registration_page_refuses_and_writes_nothing() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        let ok = std::collections::HashMap::from([("name".to_string(), "  山田 太郎 ".to_string())]);
        save_profile(&fs, "acc", &ok).await.unwrap();
        for bad in ["\u{202E}evil", "a\u{0007}b", &"x".repeat(81)] {
            let upd = std::collections::HashMap::from([
                ("nickname".to_string(), "ok".to_string()),
                ("name".to_string(), bad.to_string()),
            ]);
            assert_matches!(save_profile(&fs, "acc", &upd).await, Err(ProfileError::Invalid(k)) if k == "name", "{bad:?}");
        }
        let saved = get_profile(&fs, "acc").await.unwrap();
        assert_eq!(saved.get("name").map(String::as_str), Some("山田 太郎"));
        assert_eq!(saved.get("nickname"), None);
    }

    #[tokio::test]
    async fn list_accounts_returns_all_and_reflects_disabled() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        save_credential(&fs, "a@example.com", "acc-a", &outcome("acc-a")).await.unwrap();
        save_credential(&fs, "b@example.com", "acc-b", &outcome("acc-b")).await.unwrap();
        set_disabled(&fs, "b@example.com", true).await.unwrap();

        let mut list = list_accounts(&fs).await.unwrap();
        list.sort_by(|a, b| a.email.cmp(&b.email));
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].email, "a@example.com");
        assert_eq!(list[0].account_id, "acc-a");
        assert!(!list[0].disabled);
        assert_eq!(list[1].email, "b@example.com");
        assert!(list[1].disabled);
    }

    #[tokio::test]
    async fn list_accounts_skips_docs_missing_account_id() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        save_credential(&fs, "good@example.com", "acc-good", &outcome("acc-good")).await.unwrap();
        // accountId を持たない壊れたドキュメントを直接差し込む。
        fs.set_doc("accounts", "broken@example.com", json!({ "email": firestore::s("broken@example.com") }))
            .await
            .unwrap();

        let list = list_accounts(&fs).await.unwrap();
        assert_eq!(list.len(), 1, "壊れたドキュメントはスキップされ、正常な1件だけ返る");
        assert_eq!(list[0].email, "good@example.com");
    }

    #[tokio::test]
    async fn list_accounts_empty_when_no_accounts() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        assert!(list_accounts(&fs).await.unwrap().is_empty());
    }

    fn reg(id: &str, x: &str) -> RegOutcome {
        RegOutcome { credential_id: id.into(), pub_x: x.into(), ..outcome("") }
    }

    async fn fs() -> Firestore {
        let (host, _state) = fake_firestore::spawn().await;
        Firestore::new_for_test("proj", host)
    }

    /// #1 の前の版が書いた形（accounts のフィールドに passkey が 1 本）。
    async fn legacy_account(fs: &Firestore, email: &str, account_id: &str, cred_id: &str) {
        fs.set_doc(
            "accounts",
            email,
            json!({
                "email": firestore::s(email),
                "accountId": firestore::s(account_id),
                "credentialId": firestore::s(cred_id),
                "pubX": firestore::s("lx"),
                "pubY": firestore::s("ly"),
                "signCount": { "integerValue": "7" },
                "verified": firestore::b(true),
                "disabled": firestore::b(false),
            }),
        )
        .await
        .unwrap();
    }

    async fn ids(fs: &Firestore, email: &str) -> Vec<String> {
        let a = get_account(fs, email).await.unwrap().unwrap();
        list_credentials(fs, &a).await.unwrap().into_iter().map(|c| c.credential_id).collect()
    }

    #[tokio::test]
    async fn an_old_shape_account_is_read_as_is_and_migrated_once() {
        let fs = fs().await;
        legacy_account(&fs, "old@example.com", "acc-old", "C-OLD").await;
        let a = get_account(&fs, "old@example.com").await.unwrap().unwrap();
        let c = find_credential(&fs, &a, "C-OLD").await.unwrap().unwrap();
        assert_eq!((c.pub_x.as_str(), c.sign_count), ("lx", 7));
        assert!(find_credential(&fs, &a, "C-OTHER").await.unwrap().is_none());

        assert!(migrate_account(&fs, "old@example.com").await.unwrap());
        assert!(!migrate_account(&fs, "old@example.com").await.unwrap(), "2 回目は何もしない");
        assert_eq!(ids(&fs, "old@example.com").await, ["C-OLD"]);
        let doc = fs.get_doc("credentials", "C-OLD").await.unwrap().unwrap();
        assert_eq!(firestore::field_str(&doc, "accountId"), Some("acc-old"));
        assert!(fs.get_doc("accounts", "old@example.com").await.unwrap().unwrap().get("credentialId").is_some(), "古いフィールドは残す");
    }

    /// 移した後に消した passkey が、accounts に残る古いフィールドから生き返らない。
    #[tokio::test]
    async fn a_passkey_removed_after_migration_does_not_come_back_from_the_old_fields() {
        let fs = fs().await;
        legacy_account(&fs, "old@example.com", "acc-old", "C-OLD").await;
        migrate_account(&fs, "old@example.com").await.unwrap();
        fs.delete_doc("credentials", "C-OLD").await.unwrap();
        assert!(ids(&fs, "old@example.com").await.is_empty());
        assert!(!has_passkey(&fs, "old@example.com").await.unwrap());
    }

    #[tokio::test]
    async fn a_second_passkey_is_added_next_to_the_first() {
        let fs = fs().await;
        legacy_account(&fs, "old@example.com", "acc-old", "C-OLD").await;
        save_credential(&fs, "old@example.com", "acc-old", &reg("C-NEW", "nx")).await.unwrap();
        assert_eq!(ids(&fs, "old@example.com").await, ["C-OLD", "C-NEW"], "足す前に古い 1 本を移す");
        let a = get_account(&fs, "old@example.com").await.unwrap().unwrap();
        assert_eq!(find_credential(&fs, &a, "C-NEW").await.unwrap().unwrap().pub_x, "nx");
        assert_eq!(find_credential(&fs, &a, "C-OLD").await.unwrap().unwrap().pub_x, "lx");
    }

    #[tokio::test]
    async fn a_new_account_also_writes_the_old_fields_for_a_rollback() {
        let fs = fs().await;
        save_credential(&fs, "n@example.com", "acc-n", &reg("C1", "x1")).await.unwrap();
        let f = fs.get_doc("accounts", "n@example.com").await.unwrap().unwrap();
        assert_eq!(firestore::field_str(&f, "credentialId"), Some("C1"));
        assert_eq!(firestore::field_str(&f, "pubX"), Some("x1"));
        assert_eq!(ids(&fs, "n@example.com").await, ["C1"]);
        assert_eq!(find_email_by_account_id(&fs, "acc-n").await.unwrap().as_deref(), Some("n@example.com"));
    }

    /// 同じ credential id を名乗る登録で、別のアカウントの passkey を上書きさせない（C1）。
    /// id で直に引いても、持ち主の違う passkey は返さない（C5）。
    #[tokio::test]
    async fn a_credential_id_belongs_to_one_account() {
        let fs = fs().await;
        save_credential(&fs, "a@example.com", "acc-a", &reg("SAME", "ax")).await.unwrap();
        assert!(save_credential(&fs, "b@example.com", "acc-b", &reg("SAME", "bx")).await.is_err());
        let doc = fs.get_doc("credentials", "SAME").await.unwrap().unwrap();
        assert_eq!(firestore::field_str(&doc, "pubX"), Some("ax"));
        assert!(get_account(&fs, "b@example.com").await.unwrap().is_none(), "断った登録はアカウントも作らない");

        save_credential(&fs, "b@example.com", "acc-b", &reg("B1", "bx")).await.unwrap();
        let b = get_account(&fs, "b@example.com").await.unwrap().unwrap();
        assert!(find_credential(&fs, &b, "SAME").await.unwrap().is_none());
    }

    /// passkey を全部消したアカウントは、同じ accountId のまま登録し直せる。別の accountId では断る。
    #[tokio::test]
    async fn an_account_without_passkeys_keeps_its_id_and_flags() {
        let fs = fs().await;
        save_credential(&fs, "a@example.com", "acc-a", &reg("A1", "x")).await.unwrap();
        set_disabled(&fs, "a@example.com", true).await.unwrap();
        fs.delete_doc("credentials", "A1").await.unwrap();
        assert!(!has_passkey(&fs, "a@example.com").await.unwrap());
        assert!(save_credential(&fs, "a@example.com", "acc-other", &reg("A2", "x")).await.is_err());
        save_credential(&fs, "a@example.com", "acc-a", &reg("A2", "x")).await.unwrap();
        let a = get_account(&fs, "a@example.com").await.unwrap().unwrap();
        assert_eq!(a.account_id, "acc-a");
        assert!(a.disabled, "登録し直しても凍結は解けない");
        assert_eq!(ids(&fs, "a@example.com").await, ["A2"]);
    }

    /// 消された passkey の使用を書いても、文書を作り直さない（C6）。
    #[tokio::test]
    async fn recording_a_use_does_not_recreate_a_removed_passkey() {
        let fs = fs().await;
        save_credential(&fs, "a@example.com", "acc-a", &reg("A1", "x")).await.unwrap();
        let a = get_account(&fs, "a@example.com").await.unwrap().unwrap();
        let c = find_credential(&fs, &a, "A1").await.unwrap().unwrap();
        record_use(&fs, &a, &c, 3).await.unwrap();
        let c = find_credential(&fs, &a, "A1").await.unwrap().unwrap();
        assert_eq!(c.sign_count, 3);
        assert!(c.last_used_at.is_some());
        fs.delete_doc("credentials", "A1").await.unwrap();
        assert!(record_use(&fs, &a, &c, 4).await.is_err());
        assert!(fs.get_doc("credentials", "A1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_accounts_counts_passkeys_in_both_shapes() {
        let fs = fs().await;
        legacy_account(&fs, "old@example.com", "acc-old", "C-OLD").await;
        save_credential(&fs, "n@example.com", "acc-n", &reg("N1", "x")).await.unwrap();
        save_credential(&fs, "n@example.com", "acc-n", &reg("N2", "x")).await.unwrap();
        let mut v: Vec<_> = list_accounts(&fs).await.unwrap().into_iter().map(|a| (a.email, a.passkeys)).collect();
        v.sort();
        assert_eq!(v, [("n@example.com".to_string(), 2), ("old@example.com".to_string(), 1)]);
    }


    /// 移す前の passkey の id を、別のアカウントが先に名乗っても取れない（持ち主が移れなくならない）。
    #[tokio::test]
    async fn an_unmigrated_passkey_id_cannot_be_taken_first() {
        let fs = fs().await;
        legacy_account(&fs, "old@example.com", "acc-old", "C-OLD").await;
        assert!(save_credential(&fs, "evil@example.com", "acc-evil", &reg("C-OLD", "ex")).await.is_err());
        assert!(fs.get_doc("credentials", "C-OLD").await.unwrap().is_none());
        assert!(get_account(&fs, "evil@example.com").await.unwrap().is_none(), "断った登録はアカウントも残さない");
        assert!(migrate_account(&fs, "old@example.com").await.unwrap());
        assert_eq!(ids(&fs, "old@example.com").await, ["C-OLD"]);
    }

    /// passkey を全部消して登録し直すと、古いフィールドも新しい 1 本に向く（前の版へ戻しても、
    /// 消した passkey は生き返らず、新しい passkey で入れる）。
    #[tokio::test]
    async fn re_registering_points_the_old_fields_at_the_new_passkey() {
        let fs = fs().await;
        save_credential(&fs, "a@example.com", "acc-a", &reg("A1", "x1")).await.unwrap();
        let created = fs.get_doc("accounts", "a@example.com").await.unwrap().unwrap()["createdAt"].clone();
        fs.delete_doc("credentials", "A1").await.unwrap();
        save_credential(&fs, "a@example.com", "acc-a", &reg("A2", "x2")).await.unwrap();
        let f = fs.get_doc("accounts", "a@example.com").await.unwrap().unwrap();
        assert_eq!(firestore::field_str(&f, "credentialId"), Some("A2"));
        assert_eq!(firestore::field_str(&f, "pubX"), Some("x2"));
        assert_eq!(f["createdAt"], created, "アカウントの登録日時は変えない");
    }

    /// 2 本目を足しても、古いフィールドは最初の 1 本のまま（前の版はそれで入れる）。
    #[tokio::test]
    async fn a_second_passkey_leaves_the_old_fields_alone() {
        let fs = fs().await;
        save_credential(&fs, "a@example.com", "acc-a", &reg("A1", "x1")).await.unwrap();
        save_credential(&fs, "a@example.com", "acc-a", &reg("A2", "x2")).await.unwrap();
        let f = fs.get_doc("accounts", "a@example.com").await.unwrap().unwrap();
        assert_eq!(firestore::field_str(&f, "credentialId"), Some("A1"));
    }

    /// 写し終えて印を付ける前に止まっても、流し直せば移る。消すときは、その写しも消す。
    #[tokio::test]
    async fn a_migration_stopped_halfway_resumes_and_deletes_cleanly() {
        let fs = fs().await;
        legacy_account(&fs, "old@example.com", "acc-old", "C-OLD").await;
        let a = get_account(&fs, "old@example.com").await.unwrap().unwrap();
        create_credential(&fs, "old@example.com", "acc-old", a.legacy.as_ref().unwrap()).await.unwrap();
        assert!(migrate_account(&fs, "old@example.com").await.unwrap());
        assert_eq!(ids(&fs, "old@example.com").await, ["C-OLD"]);

        legacy_account(&fs, "half@example.com", "acc-half", "C-HALF").await;
        let h = get_account(&fs, "half@example.com").await.unwrap().unwrap();
        create_credential(&fs, "half@example.com", "acc-half", h.legacy.as_ref().unwrap()).await.unwrap();
        delete_all_credentials(&fs, &h).await.unwrap();
        assert!(fs.get_doc("credentials", "C-HALF").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_document_without_an_account_id_counts_as_registered() {
        let fs = fs().await;
        fs.set_doc("accounts", "broken@example.com", json!({ "email": firestore::s("broken@example.com") })).await.unwrap();
        assert!(has_passkey(&fs, "broken@example.com").await.unwrap());
    }

    /// 移す前のアカウントでも、本人の削除は最後の 1 本を残し、管理者の「パスキーだけ削除」は古いフィールドの
    /// 1 本まで消す（印を付けないまま消すと、古いフィールドから生き返る）。
    #[tokio::test]
    async fn removing_passkeys_of_an_old_shape_account() {
        let fs = fs().await;
        legacy_account(&fs, "old@example.com", "acc-old", "C-OLD").await;
        assert_eq!(remove_credential(&fs, "old@example.com", "C-OLD").await.unwrap(), RemoveOutcome::LastOne);
        assert_eq!(remove_credential(&fs, "old@example.com", "C-NONE").await.unwrap(), RemoveOutcome::NotFound);
        assert_eq!(ids(&fs, "old@example.com").await, ["C-OLD"]);

        legacy_account(&fs, "old2@example.com", "acc-old2", "C-OLD2").await;
        assert_eq!(remove_all_credentials(&fs, "old2@example.com").await.unwrap(), Some(1));
        assert!(ids(&fs, "old2@example.com").await.is_empty());
        assert!(!has_passkey(&fs, "old2@example.com").await.unwrap());
        assert_eq!(remove_all_credentials(&fs, "none@example.com").await.unwrap(), None);
    }
}
