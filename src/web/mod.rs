//! HTTP レイヤ。axum で各エンドポイントを provider のレジストリに配線する。

use crate::auth_checks::resolve_addressee;
use crate::client_auth::ClientAuthInput;
use crate::context::{AddressedRequest, RawAuthRequest};
use crate::error::OAuthError;
use crate::model::{AuthParams, AuthorizationCode, Interaction, Session};
use crate::provider::Provider;
use crate::store::StoreResult;
use axum::extract::{Form, Path, Query, RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use i18n::{Lang, localize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::Instrument;
use uuid::Uuid;

mod account;
mod admin;
mod ciba;
#[cfg(test)]
mod flow_tests;
pub(crate) mod i18n;
#[cfg(test)]
mod i18n_tests;
mod login;
mod oidc;
mod pages;
mod recover;
mod register;
#[cfg(test)]
mod routes_tests;

/// ブラウザは、`__Host-` の cookie を Secure・Path=/・Domain 無しの Set-Cookie でしか張らず、消しもしない。
#[cfg(test)]
fn assert_host_cookie(set: &str) {
    let c = Cookie::parse(set.to_string()).unwrap();
    assert!(c.name().starts_with("__Host-"), "{set}");
    assert_eq!(c.secure(), Some(true), "{set}");
    assert_eq!(c.path(), Some("/"), "{set}");
    assert_eq!(c.domain(), None, "{set}");
}

/// `__Host-` の名前は、Secure・Path=/・Domain 無しでしか張れない。sonrisa.co.jp の別のサブドメインから
/// `Domain=sonrisa.co.jp` で同じ名前の cookie を植えられない（Fable の査読 H2）。消すときも同じ属性が要る。
const SID_COOKIE: &str = "__Host-sid";

/// ログインを始めたブラウザの印。`/authorize` が interaction ごとに張り、login の完了と resume で照合する。
/// 照合が無いと、攻撃者が自分で始めた `/login/{uid}` を被害者に踏ませ、被害者の認証の直後に resume を取って
/// 被害者として RP に入れる。名前を uid ごとに分けるのは、別のタブで並行して始めたログインを上書きしないため。
fn browser_cookie_name(uid: &str) -> String {
    format!("__Host-ix_{uid}")
}

/// cookie に入れる値と、interaction に残すそのハッシュ。
fn new_browser_binding() -> (String, String) {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("OS の乱数源");
    let secret = crate::es256::b64url_encode(buf);
    let hash = browser_binding_hash(&secret);
    (secret, hash)
}

fn browser_binding_hash(secret: &str) -> String {
    use sha2::Digest;
    crate::es256::b64url_encode(sha2::Sha256::digest(secret.as_bytes()))
}

/// このブラウザがその interaction を始めたブラウザか。
/// 印の無い interaction は通さない（印は 11-20 の #92 から必ず張っている）。
fn started_in_this_browser(jar: &CookieJar, i: &crate::model::Interaction) -> bool {
    if i.browser_binding.is_empty() {
        return false;
    }
    jar.get(&browser_cookie_name(&i.uid)).is_some_and(|c| {
        use subtle::ConstantTimeEq;
        bool::from(
            browser_binding_hash(c.value())
                .as_bytes()
                .ct_eq(i.browser_binding.as_bytes()),
        )
    })
}

/// ログイン画面から来た uid を、このブラウザが始めた生きた interaction のときだけ受け取る。
async fn came_from(p: &Provider, jar: &CookieJar, uid: &str) -> crate::registration::CameFrom {
    let none = crate::registration::CameFrom::default;
    if uid.is_empty() {
        return none();
    }
    let Some(i) = p.store.get_interaction(uid).await else {
        return none();
    };
    if !started_in_this_browser(jar, &i) {
        return none();
    }
    crate::registration::CameFrom {
        uid: uid.to_string(),
        client_id: requested_client_id(&i),
    }
}

/// interaction の元の要求の client_id。利用者の入力でなく、/authorize が受けた要求から取る
/// （PAR では預けた本体。authorize は client_id の無い要求を断るので、interaction には必ず在る）。
fn requested_client_id(i: &crate::model::Interaction) -> String {
    serde_urlencoded::from_str::<HashMap<String, String>>(&i.raw_query)
        .ok()
        .and_then(|q| q.get("client_id").cloned())
        .unwrap_or_default()
}

/// このブラウザが別のアカウントでログイン中なら、そのメールアドレス。
/// メールのリンクで passkey を作ると、このブラウザのセッションはリンクのアカウントに替わる。
/// 攻撃者が自分のアカウントのリンクを踏ませると、被害者は気づかずに攻撃者として RP に入る（ログイン CSRF）。
/// session やそのメールアドレスを読めないときは誤り（ログイン中かどうか分からないまま、確認を出さずに進めない）。
async fn signed_in_as_other(
    p: &Provider,
    jar: &CookieJar,
    target_email: &str,
) -> StoreResult<Option<String>> {
    let (Some(fs), Some(c)) = (p.docs.as_deref(), jar.get(SID_COOKIE)) else {
        return Ok(None);
    };
    let Some(session) = p.store.get_session(c.value()).await? else {
        return Ok(None);
    };
    let Some(email) =
        crate::registration::find_email_by_account_id(fs, &session.account_id).await?
    else {
        return Ok(None);
    };
    Ok((!email.eq_ignore_ascii_case(target_email)).then_some(email))
}

/// signed_in_as_other のときに、passkey を作る画面（id="main"）の前に出す確認。
/// 押すまで main は隠しておく。文の訳は呼び手の localize に任せ、アドレスはその後で差し込む。
/// アドレスに `__TOKEN__` などの印を書かれても展開されないよう、fill_switch_notice はほかの置換の後に呼ぶ。
const SWITCH_NOTICE: &str = r#"<div id="switch"><h1>[[Switch accounts?]]</h1>
<p>[[This browser is signed in as {current}.]]</p>
<p>[[If you continue, it will be signed in as {target} instead. Continue only if you expected this email.]]</p>
<button class="primary" onclick="document.getElementById('switch').hidden=true;document.getElementById('main').hidden=false">[[Continue]]</button></div>"#;

fn fill_switch_notice(html: String, current: &str, target: &str) -> String {
    html.replace(
        "{current}",
        &format!("<strong>{}</strong>", admin::esc(current)),
    )
    .replace(
        "{target}",
        &format!("<strong>{}</strong>", admin::esc(target)),
    )
}

/// メールのリンクで passkey を作り終えた後の行き先。
/// 同じブラウザで元の interaction が生きていれば、そのログインを済ませて RP への続き（resume）へ。
/// でなければ /account。client_id を添え、その client の入口があれば /account がボタンを出す。
async fn continue_after_email(
    p: &Provider,
    jar: &CookieJar,
    from: &crate::registration::CameFrom,
    account_id: &str,
    recovered: bool,
) -> String {
    let interaction = if from.uid.is_empty() {
        None
    } else {
        p.store.get_interaction(&from.uid).await
    };
    if let Some(i) = interaction
        && started_in_this_browser(jar, &i)
        && p.store
            .complete_interaction(&from.uid, account_id, now())
            .await
    {
        tracing::info!(event = "login_success", sub = %pseudonymize_sub(account_id), via = "email");
        return p.path(&format!("/authorize/resume?uid={}", from.uid));
    }
    account_url(p, &from.client_id, recovered)
}

fn account_url(p: &Provider, client_id: &str, recovered: bool) -> String {
    let mut q: Vec<(&str, &str)> = Vec::new();
    if recovered {
        q.push(("recovered", "1"));
    }
    if !client_id.is_empty() {
        q.push(("client_id", client_id));
    }
    if q.is_empty() {
        return p.path("/account");
    }
    format!(
        "{}?{}",
        p.path("/account"),
        serde_urlencoded::to_string(q).unwrap_or_default()
    )
}

/// client の入口（initiate_login_uri）に iss を付けた URL。入口が無い client は None。
async fn client_entry(p: &Provider, client_id: &str) -> Option<String> {
    if client_id.is_empty() {
        return None;
    }
    let entry = p.resolve_client(client_id).await?.initiate_login_uri?;
    let sep = if entry.contains('?') { '&' } else { '?' };
    let iss = serde_urlencoded::to_string([("iss", &p.issuer)]).unwrap_or_default();
    Some(format!("{entry}{sep}{iss}"))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// SSO セッションを作り、sid cookie を張る。
/// passkey は保存できたが、前の session を消せずに新しい session を張らなかったときの 500。
/// 画面は SERVER_ERRORS で「もう一度ログインして」と訳す。
fn passkey_saved_sign_in_again(context: &str, e: &str) -> Response {
    tracing::error!("{context}: {e}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "passkey saved, sign in again",
    )
        .into_response()
}

async fn start_session(
    p: &Provider,
    jar: CookieJar,
    account_id: String,
    auth_time: u64,
) -> StoreResult<CookieJar> {
    let sid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_session(Session {
            sid: sid.clone(),
            account_id,
            auth_time,
        })
        .await?;
    let cookie = Cookie::build((SID_COOKIE, sid))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build();
    Ok(jar.add(cookie))
}

/// sid cookie からログイン済み account_id を引く（SSO セッション）。
/// OAuth の access token 認証（authenticate_token）とは別系統: ブラウザの画面系
/// エンドポイント（CIBA 承認画面・管理画面）が使う。
async fn session_account(p: &Provider, jar: &CookieJar) -> StoreResult<Option<String>> {
    let Some(c) = jar.get(SID_COOKIE) else {
        return Ok(None);
    };
    Ok(p.store.get_session(c.value()).await?.map(|s| s.account_id))
}

/// FIDO2 Conformance 用の /fido/* エンドポイントを公開するか。テスト専用。
/// 本番（環境変数未設定）では無効化し、攻撃面（本番の実フローに非接続なテスト面）を排除する。
/// FIDO2 Conformance を回すときだけ FIDO_CONFORMANCE_ENABLED=1 で有効化する。
fn fido_conformance_enabled() -> bool {
    matches!(
        std::env::var("FIDO_CONFORMANCE_ENABLED").as_deref(),
        Ok("1") | Ok("true")
    )
}

pub fn router(provider: Provider) -> Router {
    router_with_legacy_hosts(provider, &std::env::var("LEGACY_HOSTS").unwrap_or_default())
}

/// `legacy_hosts` は LEGACY_HOSTS の値（カンマ区切りのホスト名）。
fn router_with_legacy_hosts(provider: Provider, legacy_hosts: &str) -> Router {
    let legacy = LegacyHosts::new(legacy_hosts, provider.origin());
    let base_path = provider.base_path.clone();
    // FIDO2 Conformance 用エンドポイントは base_path に依らずトップレベル /fido/* に置く。
    // テスト専用面（本番の実 passkey フローは /signup・/login・/ciba 側）なので、
    // 本番（FIDO_CONFORMANCE_ENABLED 未設定）では空 Router にしてマウントしない＝攻撃面を排除。
    let fido = if fido_conformance_enabled() {
        crate::fido::router(Arc::new(crate::fido::FidoState::from_env()))
    } else {
        Router::new()
    };
    let shared = Arc::new(provider);
    // 期限切れストアの定期一掃を起動(60 秒周期)。In-memory の無制限成長=資源枯渇/DoS を防ぐ。
    // ランタイム上でのみ起動(runtime 外から router を組む単体テストでは spawn しない)。
    if tokio::runtime::Handle::try_current().is_ok() {
        shared.spawn_store_sweeper(std::time::Duration::from_secs(60));
    }
    let inner = Router::new()
        .route("/.well-known/openid-configuration", get(oidc::discovery))
        .route("/jwks", get(oidc::jwks))
        .route("/authorize", get(oidc::authorize))
        .route("/authorize/resume", get(oidc::authorize_resume))
        .route("/login/{uid}", get(login::login_form))
        .route("/login/{uid}/cancel", get(oidc::authorize_cancel))
        .route(
            "/login/{uid}/passkey/options",
            post(login::login_passkey_options),
        )
        .route(
            "/login/{uid}/passkey/verify",
            post(login::login_passkey_verify),
        )
        .route("/token", post(oidc::token))
        .route("/introspect", post(oidc::introspect))
        .route("/oauth/mandate/consume", post(oidc::mandate_consume))
        .route("/oauth/register", post(oidc::register))
        .route("/revoke", post(oidc::revoke))
        .route(
            "/end-session",
            get(oidc::end_session).post(oidc::end_session_post),
        )
        .route("/par", post(oidc::par))
        .route(
            "/userinfo",
            get(oidc::userinfo_get).post(oidc::userinfo_post),
        )
        .route("/me/profile", get(oidc::profile_get).put(oidc::profile_put))
        // CIBA
        .route("/backchannel-authentication", post(ciba::backchannel_auth))
        .route("/ciba", get(ciba::ciba_pending))
        .route("/ciba/pending", get(ciba::ciba_pending_list))
        .route("/ciba/history", get(ciba::ciba_history))
        .route("/ciba/fcm-tokens", post(ciba::fcm_token_register))
        .route(
            "/ciba/{auth_req_id}/passkey-options",
            post(ciba::ciba_approve_options),
        )
        .route("/ciba/{auth_req_id}/approve", post(ciba::ciba_approve))
        .route("/ciba/{auth_req_id}/reject", post(ciba::ciba_reject))
        // メール確認つきユーザー登録（Web HTML フロー + ネイティブ JSON API）。
        // OAuth の「クライアント登録(DCR)」と区別するため /signup/* に置く。
        .route(
            "/signup",
            get(register::register_form).post(register::register_submit),
        )
        .route("/signup/verify", get(register::verify_form))
        .route(
            "/signup/email-challenge",
            post(register::register_email_challenge),
        )
        .route(
            "/signup/verify-email",
            post(register::register_verify_email),
        )
        .route(
            "/signup/passkey/options",
            post(register::register_passkey_options),
        )
        .route(
            "/signup/passkey/verify",
            post(register::register_passkey_verify),
        )
        // 招待: RP（INVITE_CLIENT_IDS の confidential client）が登録リンクを発行し、受け手は /invite で登録する。
        .route("/account", get(account::account_page))
        .route("/account/signin/options", post(account::signin_options))
        .route("/account/signin/verify", post(account::signin_verify))
        .route("/account/passkeys/options", post(account::add_options))
        .route("/account/passkeys/verify", post(account::add_verify))
        .route("/account/passkeys/delete", post(account::delete_passkey))
        .route(
            "/recover",
            get(recover::recover_page).post(recover::recover_submit),
        )
        .route("/recover/options", post(recover::recover_options))
        .route("/recover/verify", post(recover::recover_verify))
        .route("/invites", post(register::invite_create))
        .route("/accounts/disable", post(register::account_disable))
        .route("/invite", get(register::invite_page))
        // ブラウザで完結する RP デモ。
        .route("/", get(pages::demo_start))
        .route("/callback", get(pages::demo_callback));

    // 管理者向け（sid セッション + admins/{account_id} の存在で判定）。
    // 自分の origin から来た POST だけを通す（CSRF の守り）。
    let admin = Router::new()
        .route("/admin/whoami", get(admin::whoami))
        .route("/admin", get(admin::admin_home))
        .route("/admin/users", get(admin::users_list))
        .route("/admin/users/{account_id}", get(admin::user_detail))
        .route(
            "/admin/users/{account_id}/disable",
            post(admin::user_disable),
        )
        .route("/admin/users/{account_id}/enable", post(admin::user_enable))
        .route("/admin/users/{account_id}/delete", post(admin::user_delete))
        .route(
            "/admin/users/{account_id}/delete-passkeys",
            post(admin::user_delete_passkeys),
        )
        .route(
            "/admin/users/{account_id}/grant-admin",
            post(admin::user_grant_admin),
        )
        .route(
            "/admin/users/{account_id}/revoke-admin",
            post(admin::user_revoke_admin),
        )
        .route("/admin/audit", get(admin::audit_list))
        .route("/admin/clients", get(admin::clients_list))
        .route("/admin/clients/{client_id}", get(admin::client_detail))
        .route(
            "/admin/clients/{client_id}/revoke",
            post(admin::client_revoke),
        )
        .route(
            "/admin/clients/{client_id}/post-logout",
            post(admin::client_set_post_logout),
        )
        .route(
            "/admin/clients/{client_id}/initiate-login",
            post(admin::client_set_initiate_login),
        )
        .route("/admin/iats", get(admin::iats_pending_list))
        .route(
            "/admin/iats/new",
            get(admin::iat_mint_form).post(admin::iat_mint_submit),
        )
        .route("/admin/iats/{hash}/revoke", post(admin::iat_revoke))
        .route("/admin/iats/flash/{flash_id}", get(admin::iat_show_once))
        .route_layer(axum::middleware::from_fn_with_state(
            shared.clone(),
            admin_same_origin,
        ));

    // 本人の画面の form の POST も、同じ門で自分の origin から来たものだけを通す。
    let account_forms = Router::new()
        .route("/account/profile", post(account::save_name))
        .route_layer(axum::middleware::from_fn_with_state(
            shared.clone(),
            admin_same_origin,
        ));

    let inner = inner
        .merge(admin)
        .merge(account_forms)
        .with_state(shared.clone());

    // メールリンク /r はトップレベル（base_path 非依存、AASA の paths と一致）。
    let magic = Router::new()
        .route("/r", get(register::magic_redirect))
        .route(
            "/.well-known/apple-app-site-association",
            get(register::apple_app_site_association),
        )
        .with_state(shared);

    let app = if base_path.is_empty() {
        inner.merge(fido).merge(magic).fallback(log_unmatched)
    } else {
        // ドメイン直下 `/` と末尾スラッシュ `/oidc/` を `/oidc`（サインイン画面）へ寄せる。
        // nest 配下では `/oidc/` が catch-all に一致せず 404 になるため明示リダイレクトする。
        let t_root = base_path.clone();
        let t_slash = base_path.clone();
        Router::new()
            .route(
                "/",
                get(move || {
                    let t = t_root.clone();
                    async move { Redirect::temporary(&t) }
                }),
            )
            .route(
                &format!("{base_path}/"),
                get(move || {
                    let t = t_slash.clone();
                    async move { Redirect::temporary(&t) }
                }),
            )
            .nest(&base_path, inner)
            .merge(fido)
            .merge(magic)
            .fallback(log_unmatched)
    };
    let app = app.layer(axum::middleware::from_fn(localize_rejections));
    // 経路より前で転送するので、表に無い path も新しいホストへ送る。転送にも HSTS を付け、request_trace に残す。
    let app = match legacy {
        Some(l) => app.layer(axum::middleware::from_fn_with_state(
            Arc::new(l),
            redirect_legacy_host,
        )),
        None => app,
    };
    // 全リクエストに request_id を付与し、構造化ログを相関させる（ZT Observability Foundation）。
    app.layer(axum::middleware::from_fn(security_headers))
        .layer(axum::middleware::from_fn(drop_encoded_cookie_names))
        .layer(axum::middleware::from_fn(request_trace))
}

/// 管理画面の状態を変える要求は、自分の origin の画面から送られたものだけを通す。
/// `__Host-sid` は SameSite=Lax なので、兄弟のサブドメインからの POST にも cookie が付く。
/// ブラウザは form の POST に Origin を付ける。付かない古い形には Referer で代える。
async fn admin_same_origin(
    State(p): State<Arc<Provider>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if req.method() != axum::http::Method::GET
        && req.method() != axum::http::Method::HEAD
        && !from_own_origin(req.headers(), &p.origin())
    {
        tracing::warn!(event = "admin_cross_origin_rejected", path = %req.uri().path());
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    next.run(req).await
}

fn from_own_origin(h: &HeaderMap, origin: &str) -> bool {
    if let Some(o) = h.get(header::ORIGIN) {
        return o.to_str().is_ok_and(|o| o == origin);
    }
    h.get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|r| {
            r == origin
                || r.strip_prefix(origin)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
}

/// 移す前のホスト（LEGACY_HOSTS）と、転送先の ORIGIN（scheme とホスト）。
struct LegacyHosts {
    hosts: Vec<String>,
    origin: String,
}

impl LegacyHosts {
    /// 転送するホストが 1 つも無ければ None（層を置かない）。
    fn new(list: &str, origin: String) -> Option<Self> {
        let own = origin.split("://").nth(1).and_then(host_of);
        let mut hosts = Vec::new();
        for h in list.split(',').map(str::trim).filter(|h| !h.is_empty()) {
            match host_of(h) {
                // ORIGIN 自身を入れると、自分へ転送し続ける。
                Some(h) if Some(&h) == own.as_ref() => {
                    tracing::warn!(event = "legacy_host_is_origin", host = %h, "LEGACY_HOSTS の ORIGIN のホストは転送しない");
                }
                Some(h) => hosts.push(h),
                None => {
                    tracing::warn!(event = "legacy_host_unparsable", host = %h, "LEGACY_HOSTS の読めない値を捨てる")
                }
            }
        }
        (!hosts.is_empty()).then_some(Self { hosts, origin })
    }
}

/// `Host` の値（`host[:port]`）から、比べるためのホスト名を取り出す。port を落とし、小文字にし、末尾の `.` を落とす。
fn host_of(authority: &str) -> Option<String> {
    let a: axum::http::uri::Authority = authority.parse().ok()?;
    Some(a.host().trim_end_matches('.').to_ascii_lowercase())
}

/// 要求の Host が LEGACY_HOSTS のどれかなら、ORIGIN の同じ path と query へ 308 で送る（308 は POST の body も保つ）。
/// AASA だけは転送しない。Apple は転送された AASA を読まないので、古いホストの Universal Link と
/// webcredentials が切れる。
async fn redirect_legacy_host(
    State(l): State<Arc<LegacyHosts>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // HTTP/2 では :authority が URI に入り、Host の見出しが無いことがある。
    let host = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            req.headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .and_then(|h| host_of(&h));
    let is_legacy = host.as_ref().is_some_and(|h| l.hosts.contains(h));
    if !is_legacy || req.uri().path() == "/.well-known/apple-app-site-association" {
        return next.run(req).await;
    }
    let pq = req.uri().path_and_query().map_or("/", |pq| pq.as_str());
    Redirect::permanent(&format!("{}{pq}", l.origin)).into_response()
}

/// 全応答に HSTS を付ける。includeSubDomains は付けない（同じ親ドメインの他の host に効かせない）。
/// HTML には、inline の script と style を壊さない範囲の CSP だけを付ける。
async fn security_headers(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    if !h.contains_key(header::STRICT_TRANSPORT_SECURITY) {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            header::HeaderValue::from_static("max-age=31536000"),
        );
    }
    let is_html = h
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/html"));
    if is_html && !h.contains_key(header::CONTENT_SECURITY_POLICY) {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            header::HeaderValue::from_static(
                "frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
            ),
        );
    }
    resp
}

/// 名前に `%` を含む cookie を、ハンドラが読む前に Cookie の見出しから落とす。
/// CookieJar は名前も %-符号から戻して読む（cookie crate の percent-encode）。`__Host%2Dsid` は `__Host-` で始まらないので
/// ブラウザは別のサブドメインからの `Domain=` 付きでも受け取るが、読むと `__Host-sid` になり、`__Host-` の守りを迂回される。
async fn drop_encoded_cookie_names(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // bytes のまま組に分ける。ASCII でない組が 1 つあるだけで見出しごと読めなくなると、別のサブドメインから
    // 植えた 1 つで印とセッションを読ませなくできるので、その組だけを落とす。
    let pairs: Vec<String> = req
        .headers()
        .get_all(header::COOKIE)
        .iter()
        .flat_map(|v| v.as_bytes().split(|b| *b == b';'))
        // ASCII だけかを先に見る。str::trim は Unicode の空白も削るので、先に削ると `\u{2000}__Host-sid` が
        // `__Host-sid` として残る（ブラウザは `__Host-` で始まらない名前として受け取る）。
        .filter(|kv| kv.iter().all(|b| *b == b'\t' || (0x20..0x7f).contains(b)))
        .filter_map(|kv| std::str::from_utf8(kv).ok())
        .map(|kv| kv.trim_matches([' ', '\t']))
        .filter(|kv| !kv.is_empty())
        .filter(|kv| !kv.split('=').next().unwrap_or("").contains('%'))
        .map(str::to_string)
        .collect();
    req.headers_mut().remove(header::COOKIE);
    if !pairs.is_empty()
        && let Ok(v) = header::HeaderValue::from_str(&pairs.join("; "))
    {
        req.headers_mut().insert(header::COOKIE, v);
    }
    next.run(req).await
}

/// axum の Query・Path・Form の取り出しの失敗は英語の説明を text/plain の本文に入れて返すので、
/// ブラウザの言語の文に差し替える。Content-Type 違いの 415 は RP の開発者向けなので英語のまま通す。
async fn localize_rejections(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let lang = Lang::from_headers(req.headers());
    let resp = next.run(req).await;
    let is_plain = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/plain"));
    if !resp.status().is_client_error() || !is_plain {
        return resp;
    }
    let (parts, body) = resp.into_parts();
    let bytes = match axum::body::to_bytes(body, 64 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                event = "rejection_body_unreadable",
                status = parts.status.as_u16(),
                "{e}"
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    };
    let detail = String::from_utf8_lossy(&bytes);
    let msg = if detail.starts_with("Failed to deserialize form") {
        "[[Some of the entered values are invalid. Please check them and try again.]]"
    } else if detail.starts_with("Failed to deserialize query string")
        || detail.starts_with("Invalid URL")
    {
        "[[The URL of this page is not valid. Please check the link and try again.]]"
    } else {
        return Response::from_parts(parts, axum::body::Body::from(bytes));
    };
    // serde の説明は値を含みうるので、どの取り出しで落ちたかだけを残す。
    let kind = detail.split(':').next().unwrap_or_default();
    tracing::warn!(
        event = "request_rejected",
        status = parts.status.as_u16(),
        kind
    );
    (parts.status, localize(msg, lang)).into_response()
}

/// リクエスト相関ミドルウェア（L4 Observability の Foundation 層）:
/// request_id を採番（または健全な inbound `X-Request-Id` を踏襲）し、span でハンドラを囲んで
/// 既存のドメインログ（`event=token_issued` 等）に request_id を継承させる。応答後に
/// method/path/status/latency を1行記録し、応答ヘッダにも request_id を返す。
///
/// 秘密はログに出さない: **query を含めず path のみ**（query には code 等が乗りうる）、
/// ヘッダ・ボディ・Authorization・DPoP proof・トークン類は一切記録しない。
async fn request_trace(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string(); // query は付けない（秘密が乗りうる）
    // inbound の X-Request-Id は健全（短い ASCII 図形文字のみ）な場合だけ踏襲。ログ注入を防ぐ。
    let rid = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| (1..=200).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic()))
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let span = tracing::info_span!("http", request_id = %rid);
    let start = Instant::now();
    let mut resp = next.run(req).instrument(span).await;

    tracing::info!(
        event = "http_request",
        request_id = %rid,
        method = %method,
        path = %path,
        status = resp.status().as_u16(),
        latency_ms = start.elapsed().as_millis() as u64,
    );
    if let Ok(v) = axum::http::HeaderValue::from_str(&rid) {
        resp.headers_mut().insert("x-request-id", v);
    }
    resp
}

/// ログ用の sub 擬似化（ZT output-control）。平文 PII（メール）をログに出さず、subject ごとに
/// **安定な相関トークン**（`h:` 接頭辞付き）を返す。`LOG_PSEUDONYM_KEY` が設定されていれば salt として
/// 混ぜ、オフライン推測に耐える。未設定なら平文 SHA256（PII 平文は消えるが、メール空間は列挙可能ゆえ
/// 推測耐性は弱い）。incident 時の逆引きは salt＋候補ハッシュ照合か別の安全な対応表で行う。
pub(crate) fn pseudonymize_sub(sub: &str) -> String {
    let salt = std::env::var("LOG_PSEUDONYM_KEY").unwrap_or_default();
    let digest = Sha256::digest(format!("{salt}\0{sub}").as_bytes());
    format!("h:{}", &crate::es256::b64url_encode(digest)[..16])
}

/// 未マッチのリクエストをログする（MDS3 等が叩く未実装パスの特定用）。
async fn log_unmatched(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    // query は出さない（パスが少し違うだけで、メール確認の token や code が載りうる）。
    tracing::info!("UNMATCHED {} {}", method, uri.path());
    (
        StatusCode::NOT_FOUND,
        localize("[[Page not found]]", Lang::from_headers(&headers)),
    )
}

fn plain_error(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, msg.to_string()).into_response()
}

/* ===== interaction (login) ===== */

/// b64url <-> ArrayBuffer のブラウザ側ヘルパー（passkey ページ共通）。
const WEBAUTHN_JS: &str = r##"
function b64ToBuf(b){b=b.replace(/-/g,'+').replace(/_/g,'/');while(b.length%4)b+='=';const s=atob(b);const a=new Uint8Array(s.length);for(let i=0;i<s.length;i++)a[i]=s.charCodeAt(i);return a.buffer;}
function bufToB64(buf){const a=new Uint8Array(buf);let s='';for(let i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
"##;

/// passkey の API が返す失敗の文言を画面の言語に置き換える JS。API の応答はアプリも読むので
/// 英語の固定文のまま変えず、ページの側で訳す。表に無い文言はそのまま出す。
/// `passkeyErrorText` は passkey の操作中の例外を訳す（例外の文はブラウザの言語で出るので画面には出さない）。
/// 印を含むので `localize` を通す前のテンプレートに差し込む。
const SERVER_ERROR_JS: &str = r##"
const SERVER_ERRORS={
 'challenge invalid/expired':'[[This took too long. Please try again.]]',
 'cannot resolve user':'[[This passkey is not registered.]]',
 'credential not found':'[[This passkey is not registered.]]',
 'credential id mismatch':'[[This passkey is not registered.]]',
 'passkey verify failed':'[[The passkey could not be verified.]]',
 'account disabled':'[[This account is disabled.]]',
 'account needs re-registration':'[[This account needs to be registered again.]]',
 'interaction not found':'[[This sign-in has expired. Please start again.]]',
 'started in another browser':'[[This sign-in was started in another browser. Please start again from the app.]]',
 'invalid or expired token':'[[This link has expired or has already been used.]]',
 'already registered':'[[This email address is already registered. Please sign in.]]',
 'registration failed':'[[The passkey could not be created.]]',
 'invalid name':'[[The name is too long or contains characters that cannot be used.]]',
 'name required':'[[Enter your name]]',
 'request not found':'[[This request was not found or has expired.]]',
 'no passkey':'[[No passkey is registered for this account.]]',
 'already handled':'[[This request has already been handled.]]',
 'sign-in required':'[[Please sign in again.]]',
 'confirmation required':'[[Please confirm it is you with a passkey again.]]',
 'too many passkeys':'[[You can add up to 10 passkeys. Remove one first.]]',
 'last passkey':'[[You cannot remove your only passkey. Add another passkey first.]]',
 'passkey not found':'[[This passkey was not found. Please reload the page.]]',
 'recovery unavailable':'[[A passkey cannot be added with email for this account. Contact the administrator.]]',
 'no passkey to recover':'[[This account has no passkey. Sign up again with the same email address.]]',
 'recently recovered':'[[This passkey can be removed 24 hours after a passkey was added with email.]]',
 'no challenge':'[[Something went wrong. Please try again.]]',
 'challenge context mismatch':'[[Something went wrong. Please try again.]]',
 'no firestore':'[[Something went wrong. Please try again.]]',
 'error':'[[Something went wrong. Please try again.]]',
 'passkey saved, sign in again':'[[The passkey was registered. Please sign in again.]]',
 'access token required':'[[Your session has expired. Please sign in again.]]',
 'invalid token':'[[Your session has expired. Please sign in again.]]',
 'DPoP scheme required':'[[Your session has expired. Please sign in again.]]',
 'DPoP proof required':'[[Your session has expired. Please sign in again.]]',
 'DPoP jkt mismatch':'[[Your session has expired. Please sign in again.]]',
 'DPoP':'[[Your session has expired. Please sign in again.]]'
};
async function errorText(r){const t=await r.text();const k=Object.keys(SERVER_ERRORS).find(k=>t===k||t.startsWith(k+': '));if(k)return SERVER_ERRORS[k];console.error(t);return '[[Something went wrong. Please try again.]]';}
function passkeyErrorText(e){if(e&&e.name==='NotAllowedError')return '[[The passkey was canceled or timed out. If you opened this page inside another app, open it in the standard Safari or Chrome app.]]';console.error(e);return '[[Something went wrong. Please try again.]]';}
"##;

#[derive(serde::Deserialize)]
pub(super) struct AuthResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    signature: String,
    #[serde(default, rename = "userHandle")]
    user_handle: Option<String>,
}

#[derive(serde::Deserialize)]
pub(super) struct AuthVerifyReq {
    id: String,
    response: AuthResponse,
}

fn dpop_header(headers: &HeaderMap) -> Option<String> {
    // RFC 9449 §4.3: DPoP ヘッダは 1 リクエストに高々 1 つ。複数あれば不正なので
    // 「使用可能な proof 無し」として None を返し、各 endpoint で拒否させる。
    let mut it = headers.get_all("dpop").iter();
    let first = it.next()?;
    if it.next().is_some() {
        return None;
    }
    first.to_str().ok().map(|s| s.to_string())
}

/// X-Forwarded-For の先頭 IP（Cloud Run の前段が付与）。無ければ "unknown"。
/// 注意: 先頭値はクライアント申告で詐称可能。レート制限の弱いキーにしかならない
/// （素朴な単一 IP からの連発を抑える backstop。詐称ローテーションには無力）。
/// レート制限に使う送り手の IP。Cloud Run は自分が見た送り手の IP を X-Forwarded-For の末尾に足し、
/// 送り手が書いた値はその前に残る。先頭を使うと、送り手が好きな値で制限をすり抜けられる。
pub(super) fn client_ip(headers: &HeaderMap) -> String {
    let xff = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // 末尾が本当に送り手かを本番の前段で確かめるための数（値は出さない）。
    tracing::info!(
        event = "forwarded_for_hops",
        hops = xff.split(',').filter(|s| !s.trim().is_empty()).count()
    );
    xff.rsplit(',')
        .map(str::trim)
        .find(|s| !s.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let h = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = h.strip_prefix("Basic ")?;
    let decoded = B64.decode(b64).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (id, secret) = s.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

/* ===== CIBA ===== */

/// confidential クライアント認証（token/backchannel 共通）。
async fn authenticate_client(
    p: &Provider,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> Result<crate::model::Client, Response> {
    let basic = parse_basic_auth(headers);
    let assertion_is_jwt = form
        .get("client_assertion_type")
        .map(|s| s.contains("jwt-bearer"))
        .unwrap_or(false);
    let method = if assertion_is_jwt {
        "private_key_jwt"
    } else if basic.is_some() {
        "client_secret_basic"
    } else {
        "none"
    };
    let input = ClientAuthInput {
        basic,
        body_client_id: form.get("client_id").cloned(),
        client_assertion: form.get("client_assertion").cloned(),
    };
    let auth = p.client_auth.get(method).ok_or_else(|| {
        OAuthError::InvalidClient("unsupported auth method".into()).into_response()
    })?;
    auth.authenticate(p, &input).await.map_err(|e| {
        tracing::warn!(event = "client_auth_failed", method = method);
        e.into_response()
    })
}

/* ===== userinfo ===== */

/// Authorization ヘッダから (scheme, token) を取り出す（Bearer / DPoP）。
fn auth_scheme_token(headers: &HeaderMap) -> Option<(String, String)> {
    let h = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    // RFC 7235: 認証スキーム名は case-insensitive。スキーム正規化して返す。
    let (scheme, rest) = h.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        return Some(("Bearer".into(), rest.trim().to_string()));
    }
    if scheme.eq_ignore_ascii_case("dpop") {
        return Some(("DPoP".into(), rest.trim().to_string()));
    }
    None
}

/// Bearer/DPoP の access token を検証して返す。失敗時はエラー Response。
/// path_suffix は DPoP htu 構築用（例 "/userinfo", "/me/profile"）。
async fn authenticate_token(
    p: &Provider,
    headers: &HeaderMap,
    method: &str,
    path_suffix: &str,
    body_token: Option<String>,
) -> Result<crate::model::AccessToken, Response> {
    let (scheme, token) = match auth_scheme_token(headers) {
        Some(x) => x,
        None => match body_token {
            Some(t) => ("Bearer".into(), t),
            None => return Err((StatusCode::UNAUTHORIZED, "access token required").into_response()),
        },
    };
    let at = match p.store.get_access_token(&token).await {
        Ok(Some(at)) => at,
        Err(e) => {
            // 401 にすると、RP は生きているトークンを捨ててログインし直させる。
            tracing::error!(
                event = "store_error",
                "token auth [{method} {path_suffix}]: {e}"
            );
            return Err(
                (StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable").into_response()
            );
        }
        Ok(None) => {
            tracing::warn!("token auth failed [{method} {path_suffix}]: invalid/expired token");
            return Err((StatusCode::UNAUTHORIZED, "invalid token").into_response());
        }
    };
    // DPoP 束縛トークンは DPoP scheme + proof（jkt 一致 / ath 一致）を要求。
    if let Some(jkt) = &at.jkt {
        if scheme != "DPoP" {
            tracing::warn!(
                "token auth failed [{path_suffix}]: DPoP scheme required (got {scheme})"
            );
            return Err((StatusCode::UNAUTHORIZED, "DPoP scheme required").into_response());
        }
        let proof = match dpop_header(headers) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    "token auth failed [{path_suffix}]: DPoP proof missing or duplicated"
                );
                return Err((StatusCode::UNAUTHORIZED, "DPoP proof required").into_response());
            }
        };
        let htu = format!("{}{}", p.issuer, path_suffix);
        let want_ath = crate::dpop::ath(&token);
        match p.dpop.verify(&proof, method, &htu, Some(&want_ath)).await {
            Ok(got) if &got == jkt => {}
            Ok(_) => {
                tracing::warn!(
                    "token auth failed [{path_suffix}]: DPoP jkt mismatch (token bound to different key)"
                );
                return Err((StatusCode::UNAUTHORIZED, "DPoP jkt mismatch").into_response());
            }
            Err(e) => {
                tracing::warn!("token auth failed [{path_suffix}]: DPoP proof invalid: {e}");
                return Err((StatusCode::UNAUTHORIZED, format!("DPoP: {e}")).into_response());
            }
        }
    }
    Ok(at)
}

#[cfg(test)]
mod browser_guard_tests {
    use super::*;
    use tower::ServiceExt;

    fn app() -> Router {
        router(Provider::new("https://idp.example/oidc".to_string()).with_base_path("/oidc"))
    }

    async fn post_admin(origin: Option<&str>, referer: Option<&str>) -> StatusCode {
        let mut req = axum::http::Request::post("/oidc/admin/users/acc-1/disable");
        if let Some(o) = origin {
            req = req.header(header::ORIGIN, o);
        }
        if let Some(r) = referer {
            req = req.header(header::REFERER, r);
        }
        app()
            .oneshot(req.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    /// 他の origin からの POST、どこから来たか分からない POST は、管理者の確かめより前に断る。
    #[tokio::test]
    async fn an_admin_post_from_another_origin_is_refused() {
        assert_eq!(post_admin(None, None).await, StatusCode::FORBIDDEN);
        assert_eq!(
            post_admin(Some("https://test.idp.example"), None).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(post_admin(Some("null"), None).await, StatusCode::FORBIDDEN);
        assert_eq!(
            post_admin(None, Some("https://idp.example.evil/oidc/admin")).await,
            StatusCode::FORBIDDEN
        );
        // Origin があれば Referer より先に見る。
        assert_eq!(
            post_admin(
                Some("https://evil.example"),
                Some("https://idp.example/oidc/admin")
            )
            .await,
            StatusCode::FORBIDDEN
        );
    }

    /// 自分の origin からなら門を通り、その先の管理者の確かめ（ここではサインインへの案内）に進む。
    #[tokio::test]
    async fn an_admin_post_from_its_own_origin_passes_the_gate() {
        for s in [
            post_admin(Some("https://idp.example"), None).await,
            post_admin(None, Some("https://idp.example/oidc/admin/users/acc-1")).await,
        ] {
            assert!(
                s != StatusCode::FORBIDDEN && s != StatusCode::NOT_FOUND,
                "{s}"
            );
        }
    }

    #[tokio::test]
    async fn html_gets_hsts_and_a_frame_ban_and_json_gets_only_hsts() {
        let html = app()
            .oneshot(
                axum::http::Request::get("/oidc/signup")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            html.headers()[header::STRICT_TRANSPORT_SECURITY],
            "max-age=31536000"
        );
        let csp = html.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        let json = app()
            .oneshot(
                axum::http::Request::get("/oidc/.well-known/openid-configuration")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            json.headers()[header::STRICT_TRANSPORT_SECURITY],
            "max-age=31536000"
        );
        assert!(!json.headers().contains_key(header::CONTENT_SECURITY_POLICY));
    }
}

#[cfg(test)]
mod client_ip_tests {
    use super::*;

    fn ip(xff: Option<&str>) -> String {
        let mut h = HeaderMap::new();
        if let Some(v) = xff {
            h.insert("x-forwarded-for", v.parse().unwrap());
        }
        client_ip(&h)
    }

    /// 送り手が書いた値は先頭に残り、Cloud Run が見た送り手は末尾に足される。
    #[test]
    fn the_sender_cannot_choose_its_own_ip() {
        assert_eq!(ip(Some("192.0.2.1, 198.51.100.7")), "198.51.100.7");
        assert_eq!(ip(Some("198.51.100.7")), "198.51.100.7");
        assert_eq!(ip(Some("198.51.100.7, ")), "198.51.100.7");
        assert_eq!(ip(None), "unknown");
    }
}

#[cfg(test)]
mod token_auth_tests {
    use super::*;
    use crate::model::AccessToken;

    // proof の署名検証は dpop.rs の試験が見る。ここでは「proof の鍵 = token の cnf.jkt」の照合だけを見たいので、
    // proof の文字列をそのまま jkt として返す検証器に差し替える。
    struct ProofIsItsJkt;

    #[async_trait::async_trait]
    impl crate::dpop::DpopVerifier for ProofIsItsJkt {
        async fn verify(
            &self,
            proof: &str,
            _: &str,
            _: &str,
            _: Option<&str>,
        ) -> Result<String, String> {
            Ok(proof.to_string())
        }
    }

    async fn provider_with_token_bound_to(jkt: &str) -> Provider {
        let p = Provider::new("https://op.example.com").with_dpop(Arc::new(ProofIsItsJkt));
        p.store
            .save_access_token(AccessToken {
                token: "AT".into(),
                client_id: "rp".into(),
                account_id: "user@example.com".into(),
                scope: "openid".into(),
                jkt: Some(jkt.into()),
                aud: None,
                acr: None,
                auth_time: None,
                authorization_details: None,
                mandate_consumed: false,
            })
            .await
            .unwrap();
        p
    }

    fn headers(scheme: &str, proof: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("{scheme} AT").parse().unwrap(),
        );
        if let Some(pr) = proof {
            h.insert("dpop", pr.parse().unwrap());
        }
        h
    }

    #[tokio::test]
    async fn bound_token_needs_a_proof_from_the_key_it_was_bound_to() {
        let p = provider_with_token_bound_to("JKT-OWNER").await;
        let ok = authenticate_token(
            &p,
            &headers("DPoP", Some("JKT-OWNER")),
            "GET",
            "/userinfo",
            None,
        )
        .await;
        assert!(ok.is_ok());
        let stolen = authenticate_token(
            &p,
            &headers("DPoP", Some("JKT-ATTACKER")),
            "GET",
            "/userinfo",
            None,
        )
        .await;
        assert_eq!(stolen.unwrap_err().status(), StatusCode::UNAUTHORIZED);
        let bearer = authenticate_token(
            &p,
            &headers("Bearer", Some("JKT-OWNER")),
            "GET",
            "/userinfo",
            None,
        )
        .await;
        assert_eq!(bearer.unwrap_err().status(), StatusCode::UNAUTHORIZED);
    }
}

#[cfg(test)]
mod obs_tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct VecWriter(Arc<Mutex<Vec<u8>>>);
    impl io::Write for VecWriter {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for VecWriter {
        type Writer = VecWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// `request_trace` の肝＝span の request_id が、span 内で出る既存ドメインログ
    /// （`event=token_issued` 等）に**継承される**ことを、本番と同じ `fmt().json()` 構成で確認する。
    /// これは型検査では分からず subscriber 構成依存（http_request 行は明示フィールドなので常に出るが、
    /// 相関先のドメインログが span 継承で出るかは別問題）なので、ここで明示的に検証する。
    #[test]
    fn request_id_span_field_propagates_to_domain_logs() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(VecWriter(buf.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("http", request_id = "RID-TEST-123");
            let _g = span.enter();
            tracing::info!(event = "token_issued"); // 既存ドメインログ相当
        });
        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            out.contains("RID-TEST-123"),
            "span の request_id がドメインログに継承される必要がある: {out}"
        );
        assert!(out.contains("token_issued"));
    }

    /// 要求の Authorization の値（Bearer の token・Basic の資格情報・DCR の IAT）は、本番と同じ
    /// `fmt().json()` の記録のどこにも出ない。router を丸ごと通し、中間層とハンドラの両方の記録を見る。
    #[tokio::test]
    async fn the_authorization_header_value_never_reaches_the_log() {
        use axum::http::{Request, header};
        use tower::ServiceExt;

        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(VecWriter(buf.clone()))
            .finish();
        // tracing-core は、生きている Dispatch が 1 つだけだと、新しい callsite の interest をそれを最初に
        // 踏んだ thread の既定の subscriber だけで決めて固定する。同時に走るほかの試験（subscriber 無し）が
        // `request_trace` の callsite を先に踏むと Never で固定され、ここの http_request が記録されない。
        // 2 つ目の Dispatch を生かしておき、interest をすべての Dispatch から決めさせる。
        let _second_dispatch = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        let _guard = tracing::subscriber::set_default(subscriber);

        const BEARER: &str = "SECRET-BEARER-7f3a9c";
        const CLIENT_SECRET: &str = "SECRET-CLIENT-2b8e41";
        let basic = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("rp:{CLIENT_SECRET}"),
        );
        let p = crate::provider::Provider::new("https://op.example").with_client(
            crate::model::Client {
                client_id: "rp".into(),
                redirect_uris: vec![],
                token_endpoint_auth_method: "client_secret_basic".into(),
                client_secret: Some(crate::dcr::hash_token("other")),
                grant_types: vec!["authorization_code".into()],
                post_logout_redirect_uris: vec![],
                initiate_login_uri: None,
                dpop_bound: false,
                jwks: vec![],
                jwks_uri: None,
                require_par: false,
                require_pkce: false,
                id_token_signed_response_alg: None,
                scope: None,
            },
        );
        let app = super::router_with_legacy_hosts(p, "");
        let form = "application/x-www-form-urlencoded";
        let requests = [
            ("GET", "/userinfo", format!("Bearer {BEARER}"), None),
            ("GET", "/me/profile", format!("DPoP {BEARER}"), None),
            (
                "POST",
                "/oauth/register",
                format!("Bearer {BEARER}"),
                Some(("application/json", "{}")),
            ),
            (
                "POST",
                "/token",
                format!("Basic {basic}"),
                Some((form, "grant_type=authorization_code&code=C")),
            ),
            (
                "POST",
                "/introspect",
                format!("Basic {basic}"),
                Some((form, "token=AT")),
            ),
            (
                "POST",
                "/oauth/mandate/consume",
                format!("Basic {basic}"),
                Some((form, "token=AT")),
            ),
        ];
        for (method, path, authorization, body) in requests {
            let mut req = Request::builder()
                .method(method)
                .uri(path)
                .header(header::AUTHORIZATION, authorization);
            if let Some((ct, _)) = body {
                req = req.header(header::CONTENT_TYPE, ct);
            }
            let body = body.map(|(_, b)| b.to_string()).unwrap_or_default();
            app.clone()
                .oneshot(req.body(axum::body::Body::from(body)).unwrap())
                .await
                .unwrap();
        }

        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert_eq!(
            out.matches("\"http_request\"").count(),
            6,
            "要求の記録が出ていない: {out}"
        );
        for secret in [BEARER, CLIENT_SECRET, basic.as_str()] {
            assert!(
                !out.contains(secret),
                "Authorization の値 {secret} が記録に出た: {out}"
            );
        }
    }

    /// sub 擬似化: 同じ sub は安定、異なる sub は別、生メールを含まない。
    #[test]
    fn pseudonymize_sub_is_stable_and_not_plaintext() {
        let a = super::pseudonymize_sub("alice@example.com");
        let b = super::pseudonymize_sub("alice@example.com");
        let c = super::pseudonymize_sub("other@example.com");
        assert_eq!(a, b, "同じ sub は安定な相関トークン");
        assert_ne!(a, c, "異なる sub は異なる");
        assert!(
            !a.contains("alice") && !a.contains('@'),
            "生メールを含まない: {a}"
        );
        assert!(a.starts_with("h:"), "擬似化マーカー h: 付き: {a}");
    }
}

#[cfg(test)]
mod legacy_host_tests {
    use super::*;
    use tower::ServiceExt;

    fn app(legacy: &str) -> Router {
        router_with_legacy_hosts(
            Provider::new("https://new.example/oidc".to_string()).with_base_path("/oidc"),
            legacy,
        )
    }

    async fn send(app: Router, method: &str, uri: &str, host: Option<&str>) -> Response {
        let mut req = axum::http::Request::builder().method(method).uri(uri);
        if let Some(h) = host {
            req = req.header(header::HOST, h);
        }
        app.oneshot(req.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap()
    }

    fn location(r: &Response) -> &str {
        r.headers().get(header::LOCATION).unwrap().to_str().unwrap()
    }

    #[tokio::test]
    async fn get_on_a_legacy_host_goes_to_the_origin_with_the_same_path_and_query() {
        let r = send(
            app("old.example"),
            "GET",
            "/oidc/authorize?client_id=a&state=x%20y",
            Some("old.example"),
        )
        .await;
        assert_eq!(r.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            location(&r),
            "https://new.example/oidc/authorize?client_id=a&state=x%20y"
        );
        assert!(r.headers().contains_key(header::STRICT_TRANSPORT_SECURITY));
    }

    /// 308 なので、RP の POST（token の交換など）は body ごと送り直される。
    #[tokio::test]
    async fn post_on_a_legacy_host_is_redirected_with_308() {
        let r = send(
            app("old.example"),
            "POST",
            "/oidc/token?x=1",
            Some("old.example"),
        )
        .await;
        assert_eq!(r.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(location(&r), "https://new.example/oidc/token?x=1");
    }

    #[tokio::test]
    async fn host_is_compared_without_case_port_or_trailing_dot() {
        for host in ["OLD.Example", "old.example:443", "old.example."] {
            let r = send(
                app(" Old.Example , other.example"),
                "GET",
                "/oidc/jwks",
                Some(host),
            )
            .await;
            assert_eq!(r.status(), StatusCode::PERMANENT_REDIRECT, "{host}");
            assert_eq!(location(&r), "https://new.example/oidc/jwks", "{host}");
        }
        let r = send(
            app("old.example,other.example"),
            "GET",
            "/oidc/jwks",
            Some("other.example"),
        )
        .await;
        assert_eq!(r.status(), StatusCode::PERMANENT_REDIRECT);
    }

    /// HTTP/2 では Host の見出しが無く、URI の authority にホストが入る。
    #[tokio::test]
    async fn the_authority_of_the_uri_is_used_when_there_is_no_host_header() {
        let r = send(
            app("old.example"),
            "GET",
            "https://old.example/oidc/jwks?a=1",
            None,
        )
        .await;
        assert_eq!(r.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(location(&r), "https://new.example/oidc/jwks?a=1");
    }

    /// 表に無い path も、経路より前で転送する。
    #[tokio::test]
    async fn unknown_paths_on_a_legacy_host_are_redirected_too() {
        let r = send(
            app("old.example"),
            "GET",
            "/no/such/path",
            Some("old.example"),
        )
        .await;
        assert_eq!(r.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(location(&r), "https://new.example/no/such/path");
    }

    fn with_app(p: Provider) -> Provider {
        p.with_mobile_app(crate::MobileApp {
            name: "Demo".into(),
            scheme: "com.example.demo".into(),
            android_package: "com.example.demo".into(),
            apple_app_id: "TEAM123456.com.example.demo".into(),
        })
    }

    #[tokio::test]
    async fn aasa_is_served_on_a_legacy_host_without_redirect() {
        let p =
            with_app(Provider::new("https://new.example/oidc".to_string()).with_base_path("/oidc"));
        let r = send(
            router_with_legacy_hosts(p, "old.example"),
            "GET",
            "/.well-known/apple-app-site-association",
            Some("old.example"),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let body = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            r#"{"applinks":{"apps":[],"details":[{"appID":"TEAM123456.com.example.demo","paths":["/r","/r?*"]}]},"webcredentials":{"apps":["TEAM123456.com.example.demo"]}}"#
        );
    }

    /// アプリを設定していなければ AASA を出さない（他社のアプリを名乗らない）。
    #[tokio::test]
    async fn aasa_is_not_found_without_a_mobile_app() {
        let r = send(
            app(""),
            "GET",
            "/.well-known/apple-app-site-association",
            None,
        )
        .await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn nothing_is_redirected_when_legacy_hosts_is_empty() {
        for legacy in ["", " , "] {
            let r = send(
                app(legacy),
                "GET",
                "/oidc/.well-known/openid-configuration",
                Some("old.example"),
            )
            .await;
            assert_eq!(r.status(), StatusCode::OK, "{legacy:?}");
            let r = send(app(legacy), "POST", "/oidc/token", Some("old.example")).await;
            assert_ne!(r.status(), StatusCode::PERMANENT_REDIRECT, "{legacy:?}");
        }
    }

    /// run.app など、ORIGIN でも LEGACY_HOSTS でもないホストは今までどおり。
    #[tokio::test]
    async fn other_hosts_pass_through() {
        for host in [
            Some("rust-idp-xyz-an.a.run.app"),
            Some("new.example"),
            Some("sub.old.example"),
            None,
        ] {
            let r = send(
                app("old.example"),
                "GET",
                "/oidc/.well-known/openid-configuration",
                host,
            )
            .await;
            assert_eq!(r.status(), StatusCode::OK, "{host:?}");
        }
    }

    /// ORIGIN のホストを LEGACY_HOSTS に入れても、自分へ転送し続けない。
    #[tokio::test]
    async fn the_origin_host_in_legacy_hosts_is_ignored() {
        let r = send(
            app("NEW.example"),
            "GET",
            "/oidc/.well-known/openid-configuration",
            Some("new.example"),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
    }
}
