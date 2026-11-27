use super::*;

/* ===== discovery / jwks ===== */

pub(super) async fn discovery(State(p): State<Arc<Provider>>) -> Json<serde_json::Value> {
    let i = &p.issuer;
    Json(serde_json::json!({
        "issuer": i,
        "authorization_endpoint": format!("{i}/authorize"),
        "token_endpoint": format!("{i}/token"),
        "introspection_endpoint": format!("{i}/introspect"),
        "revocation_endpoint": format!("{i}/revoke"),
        "userinfo_endpoint": format!("{i}/userinfo"),
        "jwks_uri": format!("{i}/jwks"),
        "response_types_supported": ["code"],
        "grant_types_supported": p.grants.keys().collect::<Vec<_>>(),
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": p.all_signers().map(|s| s.alg()).collect::<Vec<_>>(),
        "scopes_supported": ["openid", "profile", "email", "address", "phone", "offline_access"],
        "claims_supported": crate::claims::all_supported_claims(),
        "claims_parameter_supported": false,
        "token_endpoint_auth_methods_supported": p.client_auth.keys().collect::<Vec<_>>(),
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        // JAR (RFC 9101): signed request object 対応。request_uri は PAR 経由のみ（SSRF 回避で false）。
        "request_parameter_supported": true,
        "request_uri_parameter_supported": false,
        "require_request_uri_registration": false,
        "request_object_signing_alg_values_supported": ["ES256"],
        "backchannel_authentication_request_signing_alg_values_supported": ["ES256"],
        "pushed_authorization_request_endpoint": format!("{i}/par"),
        "registration_endpoint": format!("{i}/oauth/register"),
        "end_session_endpoint": format!("{i}/end-session"),
        "authorization_response_iss_parameter_supported": true,
        "backchannel_authentication_endpoint": format!("{i}/backchannel-authentication"),
        "backchannel_token_delivery_modes_supported": ["poll"],
        "backchannel_user_code_parameter_supported": false,
        // 独自エンドポイント（OIDC 標準外）。RP/アプリはここから URL を引き、
        // パスをハードコードしない（OP 側の改名にアプリ無改修で追従できる）。
        // 標準名前空間を汚さないようベンダー名前空間にまとめる。
        "custom_endpoints": custom_endpoints(i),
    }))
}

/// 独自エンドポイント（OIDC 標準外）の URL 群。アプリはここから引く。
/// アプリ側の期待キー/パスとの契約なので、各値は対応する route と一致させること。
fn custom_endpoints(i: &str) -> serde_json::Value {
    serde_json::json!({
        "signup_email_challenge": format!("{i}/signup/email-challenge"),
        "signup_verify_email": format!("{i}/signup/verify-email"),
        "signup_passkey_options": format!("{i}/signup/passkey/options"),
        "signup_passkey_verify": format!("{i}/signup/passkey/verify"),
        "profile": format!("{i}/me/profile"),
        "fcm_token": format!("{i}/ciba/fcm-tokens"),
        "mandate_consume": format!("{i}/oauth/mandate/consume"),
        // 承認インボックス（fido2demo）が自分宛の pending CIBA 依頼を取得する（access token 認証）。
        "ciba_pending": format!("{i}/ciba/pending"),
        // 承認履歴（承認/拒否/期限切れ）。
        "ciba_history": format!("{i}/ciba/history"),
    })
}

pub(super) async fn jwks(State(p): State<Arc<Provider>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "keys": p.published_jwks() }))
}
/* ===== authorize ===== */

/// redirect_uri を信用できない段階の失敗を、ブラウザの言語で表示する。英語の詳細は
/// RP の開発者が運営に問い合わせたときに引けるようにログへ残し、画面には OAuth のエラーコードだけ添える。
fn app_error(lang: Lang, code: &str, detail: &str) -> Response {
    tracing::warn!(event = "authorize_rejected", code, detail);
    let msg = match code {
        "invalid_client" => {
            "[[This app is not registered. Please contact the app provider. (error code: {code})]]"
        }
        "invalid_request_uri" => {
            "[[The request from the app could not be verified. Please start again from the app. (error code: {code})]]"
        }
        "server_error" => "[[Something went wrong. Please try again. (error code: {code})]]",
        _ => {
            "[[The request from the app is invalid. Please contact the app provider. (error code: {code})]]"
        }
    };
    let status = if code == "server_error" {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, localize(msg, lang).replace("{code}", code)).into_response()
}

pub(super) async fn authorize(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    jar: CookieJar,
    RawQuery(raw): RawQuery,
) -> Response {
    let lang = Lang::from_headers(&headers);
    let raw = raw.unwrap_or_default();
    // 非 PAR の素の request_uri は run_checks 後に拒否する（SSRF 回避、PAR-only 維持）。
    let q0: HashMap<String, String> = serde_urlencoded::from_str(&raw).unwrap_or_default();
    let has_nonpar_request_uri = q0
        .get("request_uri")
        .map(|u| !u.starts_with(crate::par::URN_PREFIX))
        .unwrap_or(false);
    // PAR: urn 形式の request_uri があれば保存済みパラメータを復元する。
    let mut par_used = false;
    let mut par_creator: Option<String> = None;
    let mut par_request_uri: Option<String> = None;
    let raw = if let Some(req) = q0.get("request") {
        // JAR (RFC 9101): 直接の request object。client_id で client を引き署名検証する。
        let cid = q0.get("client_id").map(|s| s.as_str()).unwrap_or("");
        let client = match p.resolve_client(cid).await {
            Some(c) => c,
            None => return app_error(lang, "invalid_client", "unknown client for request object"),
        };
        match crate::request_object::verify(&client, req, &p.issuer, &p.jar_jti).await {
            Ok(params) => serde_urlencoded::to_string(&params).unwrap_or_default(),
            Err(e) => return app_error(lang, "invalid_request_object", &e.description()),
        }
    } else {
        match q0.get("request_uri") {
            Some(request_uri) if request_uri.starts_with(crate::par::URN_PREFIX) => {
                let fs = match p.docs.as_deref() {
                    Some(fs) => fs,
                    None => {
                        return app_error(lang, "server_error", "PAR unavailable (no Firestore)");
                    }
                };
                // peek: 削除しない。認可完了前は再利用可。コード発行時に delete で単回化する。
                match crate::par::peek(fs, request_uri).await {
                    Ok(Some((cid, params))) => {
                        par_used = true;
                        par_creator = Some(cid);
                        par_request_uri = Some(request_uri.clone());
                        params
                    }
                    Ok(None) => {
                        return app_error(
                            lang,
                            "invalid_request_uri",
                            "invalid or expired request_uri",
                        );
                    }
                    Err(e) => {
                        return app_error(lang, "server_error", &format!("PAR lookup failed: {e}"));
                    }
                }
            }
            _ => raw,
        }
    };
    // RFC 9126: request_uri は発行先クライアントに束縛される。authorize の client_id が
    // PAR 作成クライアントと異なる場合は拒否する（別クライアントによる request_uri 流用防止）。
    if let (Some(creator), Some(req_cid)) = (&par_creator, q0.get("client_id"))
        && req_cid != creator
    {
        return app_error(
            lang,
            "invalid_request_uri",
            "request_uri was issued to a different client",
        );
    }
    let params: AuthParams = match serde_urlencoded::from_str(&raw) {
        Ok(p) => p,
        Err(e) => return app_error(lang, "invalid_request", &format!("invalid query: {e}")),
    };
    // Phase 0→1: client 解決 + redirect_uri 検証。ここで失敗した場合は redirect_uri を
    // 一切信用できないため plain 表示のみ（authorize_error は型的に呼べない）。
    let req = match resolve_addressee(
        &p,
        RawAuthRequest {
            params,
            request_uri: par_request_uri.clone(),
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_error(lang, e.code(), &e.description()),
    };
    // フロントチャネルが client_id を省いた場合も含め、code の宛先は PAR を作った client に限る。
    // /par の client_id の一致の確認や、本体の欄の重なりの読み方に依らないよう、ここでも比べる。
    if let Some(creator) = &par_creator
        && &req.client.client_id != creator
    {
        return app_error(
            lang,
            "invalid_request_uri",
            "request_uri was issued to a different client",
        );
    }
    // Phase 1: 可換なポリシーチェック群。以降のエラーは検証済み redirect へ返せる。
    if let Err(e) = run_checks(&p, &req).await {
        return authorize_error(&p, &req, e);
    }
    if has_nonpar_request_uri {
        return authorize_error(
            &p,
            &req,
            OAuthError::RequestUriNotSupported("request_uri is not supported".into()),
        );
    }
    // FAPI: PAR 必須クライアントが request_uri 経由でないなら拒否。
    if req.client.require_par && !par_used {
        return authorize_error(
            &p,
            &req,
            OAuthError::InvalidRequest("pushed authorization request required".into()),
        );
    }

    // prompt / max_age を解釈して「セッションで進む / 再ログイン / エラー」を判定。
    let session = match jar.get(SID_COOKIE).map(|c| c.value().to_string()) {
        Some(sid) => match p.store.get_session(&sid).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("authorize: get_session: {e}");
                return authorize_error(
                    &p,
                    &req,
                    OAuthError::ServerError("session store unavailable".into()),
                );
            }
        },
        None => None,
    };
    match crate::interaction_policy::decide(&req.params, session.as_ref(), now()) {
        crate::interaction_policy::AuthDecision::UseSession {
            account_id,
            auth_time,
        } => {
            return issue_code(&p, &req, account_id, Some(auth_time)).await;
        }
        crate::interaction_policy::AuthDecision::Error(e) => {
            return authorize_error(&p, &req, e);
        }
        crate::interaction_policy::AuthDecision::Login => { /* fall through to interaction */ }
    }

    // 未ログイン or 再認証要求 → interaction を作って login 画面へ。
    let uid = uuid::Uuid::new_v4().to_string();
    let (browser_secret, browser_binding) = new_browser_binding();
    p.store
        .save_interaction(Interaction {
            uid: uid.clone(),
            raw_query: raw,
            account_id: None,
            auth_time: None,
            request_uri: par_request_uri,
            browser_binding,
        })
        .await;
    let browser_cookie = Cookie::build((browser_cookie_name(&uid), browser_secret))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        // 途中でやめたログインの cookie が溜まらないよう、interaction と同じだけで消える。
        .max_age(time::Duration::seconds(
            crate::store::INTERACTION_TTL_SECS as i64,
        ))
        .build();
    // client_id を URL に残す: 期限切れの後は interaction が掃除されて client を引けないが、
    // ログイン画面はその client の入口（initiate_login_uri）へ送り直したい。
    let q = serde_urlencoded::to_string([("client_id", &req.client.client_id)]).unwrap_or_default();
    (
        jar.add(browser_cookie),
        Redirect::to(&p.path(&format!("/login/{uid}?{q}"))),
    )
        .into_response()
}

pub(super) async fn authorize_resume(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    jar: CookieJar,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let lang = Lang::from_headers(&headers);
    let expired = || {
        plain_error(&localize(
            "[[This sign-in has expired. Please start again.]]",
            lang,
        ))
    };
    let uid = match q.get("uid") {
        Some(u) => u,
        None => return expired(),
    };
    let interaction = match p.store.get_interaction(uid).await {
        Some(i) => i,
        None => return expired(),
    };
    if !started_in_this_browser(&jar, &interaction) {
        tracing::warn!(event = "resume_from_another_browser");
        return plain_error(&localize(
            "[[This sign-in was started in another browser. Please start again from the app.]]",
            lang,
        ));
    }
    let account_id = match interaction.account_id {
        Some(a) => a,
        None => return expired(),
    };

    let params: AuthParams = match serde_urlencoded::from_str(&interaction.raw_query) {
        Ok(p) => p,
        Err(e) => return app_error(lang, "server_error", &format!("invalid stored query: {e}")),
    };
    let req = match resolve_addressee(
        &p,
        RawAuthRequest {
            params,
            request_uri: interaction.request_uri.clone(),
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_error(lang, e.code(), &e.description()),
    };
    if let Err(e) = run_checks(&p, &req).await {
        return authorize_error(&p, &req, e);
    }
    // 完了済み interaction を単回消費してからコード発行。失敗（既に消費＝リプレイ/二重投入）なら
    // 再発行しない（1認証=1コード、PAR request_uri の単回化も保つ）。
    if !p.store.consume_interaction(uid).await {
        return expired();
    }
    let done = Cookie::build(browser_cookie_name(uid))
        .path("/")
        .secure(true)
        .build();
    (
        jar.remove(done),
        issue_code(&p, &req, account_id, interaction.auth_time).await,
    )
        .into_response()
}

/// ユーザーがログイン画面で「キャンセル」した場合に、登録済み redirect_uri へ
/// access_denied を返す（OIDC Core 3.1.2.6 / RFC 6749 §4.1.2.1）。
pub(super) async fn authorize_cancel(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(uid): Path<String>,
) -> Response {
    let lang = Lang::from_headers(&headers);
    let interaction = match p.store.get_interaction(&uid).await {
        Some(i) => i,
        None => {
            return plain_error(&localize(
                "[[This sign-in has expired. Please start again.]]",
                lang,
            ));
        }
    };
    if !started_in_this_browser(&jar, &interaction) {
        return plain_error(&localize(
            "[[This sign-in was started in another browser. Please start again from the app.]]",
            lang,
        ));
    }
    let params: AuthParams = match serde_urlencoded::from_str(&interaction.raw_query) {
        Ok(p) => p,
        Err(e) => return app_error(lang, "server_error", &format!("invalid stored query: {e}")),
    };
    // redirect_uri を検証してから error redirect する（未登録 URI には返さない）。
    // AddressedRequest を得られない限り authorize_error は呼べない = 規律が型で強制される。
    let req = match resolve_addressee(
        &p,
        RawAuthRequest {
            params,
            request_uri: interaction.request_uri.clone(),
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return app_error(lang, e.code(), &e.description()),
    };
    if let Err(e) = run_checks(&p, &req).await {
        return authorize_error(&p, &req, e);
    }
    authorize_error(
        &p,
        &req,
        OAuthError::AccessDenied("end-user denied the request".into()),
    )
}

async fn run_checks(p: &Provider, req: &AddressedRequest) -> Result<(), OAuthError> {
    for check in &p.checks {
        check.check(p, req).await?;
    }
    Ok(())
}

/// Resource Indicators (RFC 8707): resource は fragment 無しの絶対 URI。
fn valid_resource(r: &str) -> bool {
    !r.contains('#')
        && r.split_once("://")
            .is_some_and(|(s, rest)| !s.is_empty() && !rest.is_empty())
}

/// 検証通過後、認可コードを発行して redirect_uri に返す。
/// `&AddressedRequest` を要求するため、redirect 検証前のコード発行は型的に不可能。
async fn issue_code(
    p: &Provider,
    req: &AddressedRequest,
    account_id: String,
    auth_time: Option<u64>,
) -> Response {
    let redirect_uri = req.redirect_uri.clone();
    if let Some(r) = &req.params.resource
        && !valid_resource(r)
    {
        return authorize_error(
            p,
            req,
            OAuthError::InvalidTarget("resource must be an absolute URI without fragment".into()),
        );
    }
    // 認可完了: PAR の request_uri をコードを作る前に単回消費する（RFC 9126）。
    // 並行した完了のうち消費に勝った 1 つだけがコードを受け取る。
    if let (Some(ru), Some(fs)) = (&req.request_uri, p.docs.as_deref()) {
        match crate::par::consume(fs, ru).await {
            Ok(true) => {}
            Ok(false) => {
                return authorize_error(
                    p,
                    req,
                    OAuthError::InvalidRequest("request_uri already used".into()),
                );
            }
            Err(e) => {
                tracing::error!("par consume: {e}");
                return authorize_error(
                    p,
                    req,
                    OAuthError::ServerError("request_uri consume failed".into()),
                );
            }
        }
    }
    let code = uuid::Uuid::new_v4().simple().to_string();
    if let Err(e) = p
        .store
        .save_code(AuthorizationCode {
            code: code.clone(),
            client_id: req.client.client_id.clone(),
            account_id,
            redirect_uri: redirect_uri.clone(),
            scope: req.params.scope.clone().unwrap_or_default(),
            nonce: req.params.nonce.clone(),
            code_challenge: req.params.code_challenge.clone(),
            code_challenge_method: req.params.code_challenge_method.clone(),
            auth_time: auth_time.unwrap_or_else(now),
            // acr_values は任意の要求なので受け流す（AuthParams に持たない）。ログインで UV を求めて
            // いないので、満たした acr として言える値が無い。要求をそのまま写すと、確かめていない
            // 保証を名乗ることになる（Fable の査読 A2）。
            acr: None,
            dpop_jkt: req.params.dpop_jkt.clone(),
            resource: req.params.resource.clone(),
            expires_at: now() + 60,
        })
        .await
    {
        return authorize_error(p, req, e.into());
    }

    let mut out = vec![("code".to_string(), code)];
    if let Some(state) = &req.params.state {
        out.push(("state".to_string(), state.clone()));
    }
    // RFC 9207: 認可レスポンスに issuer を付与（FAPI 2.0 必須）。
    out.push(("iss".to_string(), p.issuer.clone()));
    let mode = req
        .params
        .response_mode
        .as_deref()
        .and_then(|m| p.response_modes.get(m))
        .unwrap_or_else(|| p.response_modes.get("query").unwrap());
    mode.build(&redirect_uri, &out)
}

/// 検証済み redirect_uri へ error を redirect で返す。`&AddressedRequest` を要求するため、
/// 未検証 redirect への error redirect（open redirector 化）は型的に不可能。
/// Phase 0（resolve_addressee 前後）のエラーは plain_error を使うこと。
fn authorize_error(p: &Provider, req: &AddressedRequest, e: OAuthError) -> Response {
    let ru = &req.redirect_uri;
    let mut out = vec![
        ("error".to_string(), e.code().to_string()),
        ("error_description".to_string(), e.description()),
        ("iss".to_string(), p.issuer.clone()),
    ];
    if let Some(state) = &req.params.state {
        out.push(("state".to_string(), state.clone()));
    }
    let qs = serde_urlencoded::to_string(&out).unwrap_or_default();
    let sep = if ru.contains('?') { '&' } else { '?' };
    Redirect::to(&format!("{ru}{sep}{qs}")).into_response()
}
/* ===== token ===== */

pub(super) async fn token(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let grant_type = match form.get("grant_type") {
        Some(g) => g.clone(),
        None => return OAuthError::InvalidRequest("grant_type required".into()).into_response(),
    };
    let grant = match p.grants.get(&grant_type) {
        Some(g) => g,
        None => return OAuthError::UnsupportedGrantType(grant_type).into_response(),
    };

    // クライアント認証。提示された材料で方式を選ぶ。
    let client = match authenticate_client(&p, &headers, &form).await {
        Ok(c) => c,
        Err(r) => return r,
    };

    if !client.allows_grant(&grant_type) {
        return OAuthError::UnauthorizedClient(format!("grant {grant_type} not allowed"))
            .into_response();
    }

    // DPoP: proof があれば検証して jkt を得る。client が dpop_bound なら必須。
    let dpop_jkt = match dpop_header(&headers) {
        Some(proof) => {
            let htu = format!("{}/token", p.issuer);
            match p.dpop.verify(&proof, "POST", &htu, None).await {
                Ok(jkt) => Some(jkt),
                Err(e) => return OAuthError::InvalidDpopProof(e).into_response(),
            }
        }
        None if client.dpop_bound => {
            return OAuthError::InvalidDpopProof("DPoP proof required".into()).into_response();
        }
        None => None,
    };

    match grant.handle(&p, &client, &form, dpop_jkt).await {
        Ok(resp) => ([(header::CACHE_CONTROL, "no-store")], Json(resp)).into_response(),
        Err(e) => e.into_response(),
    }
}

/* ===== Token Introspection (RFC 7662) ===== */

/// introspect は資格情報で認証できる confidential クライアント(RS)のみ許可する。
/// public(none) は認証不可なのでトークン有効性オラクルを与えない。
fn require_confidential(client: &crate::model::Client) -> Result<(), OAuthError> {
    if client.is_public() {
        return Err(OAuthError::InvalidClient(
            "confidential client authentication required".into(),
        ));
    }
    Ok(())
}

/// 呼び出し元がこの token を引けるか。token を受けた client 自身か、INTROSPECTION_CLIENT_IDS に
/// 挙げた RS だけ。ほかの confidential client には、ほかの RP の利用者の token を見せない。
fn may_inspect(
    p: &Provider,
    caller: &crate::model::Client,
    at: &crate::model::AccessToken,
) -> bool {
    at.client_id == caller.client_id
        || p.introspection_clients
            .iter()
            .any(|id| id == &caller.client_id)
}

/// 有効トークンの introspection 応答本体（active=true）。
/// DPoP 束縛トークンは cnf.jkt を含め、RS が proof と照合できるようにする。
fn introspection_active_body(at: &crate::model::AccessToken) -> serde_json::Value {
    let mut body = serde_json::json!({
        "active": true,
        "scope": at.scope,
        "client_id": at.client_id,
        "sub": at.account_id,
        "token_type": if at.jkt.is_some() { "DPoP" } else { "Bearer" },
    });
    if let Some(jkt) = &at.jkt {
        body["cnf"] = serde_json::json!({ "jkt": jkt });
    }
    if let Some(aud) = &at.aud {
        body["aud"] = serde_json::json!(aud);
    }
    // Step-up Authentication Challenge (RFC 9470): RS が acr/auth_time で十分性を判断する。
    if let Some(acr) = &at.acr {
        body["acr"] = serde_json::json!(acr);
    }
    if let Some(t) = at.auth_time {
        body["auth_time"] = serde_json::json!(t);
    }
    // RFC 9396: 承認済み mandate を RS に伝える。RS は request body と照合する。
    if let Some(ad) = at.authorization_details.as_deref()
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(ad)
    {
        body["authorization_details"] = v;
    }
    body
}

/// 分離した RS 向けのトークン検証窓口。同居エンドポイント(/profile, /userinfo)は
/// 従来どおり store 直引きで検証するため、これは外部 RS だけが使う。
/// 呼び出し元(RS)は confidential クライアント認証必須。無効トークンと、呼び出し元が引けない
/// トークン（[`may_inspect`]）は active=false のみ返す。
pub(super) async fn introspect(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    // RFC 7662 §2.1: 呼び出し元は認証必須。public(none) は不可（資格情報で認証できる RS のみ）。
    let client = match authenticate_client(&p, &headers, &form).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(e) = require_confidential(&client) {
        return e.into_response();
    }
    let token = match form.get("token") {
        Some(t) => t,
        None => return OAuthError::InvalidRequest("token required".into()).into_response(),
    };
    // RFC 7662 §2.2: 無効/未知/失効は active=false のみ（それ以外の情報は漏らさない）。
    // access token のみ対象。期限切れ/未知は get_access_token が None を返す。
    let body = match p.store.get_access_token(token).await {
        Ok(Some(at)) if may_inspect(&p, &client, &at) => introspection_active_body(&at),
        Ok(_) => serde_json::json!({ "active": false }),
        // active=false と答えると、RS は生きているトークンを失効扱いにする。
        Err(e) => return OAuthError::from(e).into_response(),
    };
    ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}
/// RFC 9396 mandate の単回消費窓口。RS が introspection で mandate を確認 → body と一致したら
/// この endpoint を CAS 呼び出し → 成功した呼び出しだけ実行に進む。
/// 認証は introspection と同じ confidential client 必須で、消費できる token も introspection と同じく絞る。
pub(super) async fn mandate_consume(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let client = match authenticate_client(&p, &headers, &form).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(e) = require_confidential(&client) {
        return e.into_response();
    }
    let token = match form.get("token") {
        Some(t) => t,
        None => return OAuthError::InvalidRequest("token required".into()).into_response(),
    };
    match p.store.get_access_token(token).await {
        Ok(Some(at)) if may_inspect(&p, &client, &at) => {}
        Ok(_) => {
            return (
                [(header::CACHE_CONTROL, "no-store")],
                Json(serde_json::json!({ "consumed": false })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("mandate_consume: get_access_token: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    }
    let consumed = match p.store.consume_mandate_if_unused(token).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("consume_mandate_if_unused: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    };
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({ "consumed": consumed })),
    )
        .into_response()
}

/* ===== Token Revocation (RFC 7009) ===== */

/// クライアントが自分のトークンを失効する。token endpoint と同じクライアント認証。
/// public クライアントも自分のトークンを失効できる（RFC 7009）。
/// 所有者でない/未知トークンでも 200 を返す（情報を漏らさない）。
pub(super) async fn revoke(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let client = match authenticate_client(&p, &headers, &form).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let token = match form.get("token") {
        Some(t) => t,
        None => return OAuthError::InvalidRequest("token required".into()).into_response(),
    };
    // token_type_hint は最適化のみ。access/refresh の両方を試す。
    // 自分(client_id 一致)のトークンだけ失効する。
    // 失効できなかったのに 200 を返すと、RP はトークンが死んだと思い込む。RFC 7009 §2.2.1 の 503 で試し直させる。
    if let Err(e) = revoke_own_token(&p, &client, token).await {
        tracing::error!(event = "revoke_failed", "{e}");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "1")],
        )
            .into_response();
    }
    // RFC 7009 §2.2: 成功・無効トークンいずれも 200。
    ([(header::CACHE_CONTROL, "no-store")], StatusCode::OK).into_response()
}
async fn revoke_own_token(
    p: &Provider,
    client: &crate::model::Client,
    token: &str,
) -> crate::store::StoreResult<()> {
    if let Some(at) = p.store.get_access_token(token).await?
        && at.client_id == client.client_id
    {
        p.store.revoke_access_token(token).await?;
    }
    if let Some(rt) = p.store.get_refresh_token(token).await?
        && rt.client_id == client.client_id
    {
        p.store.revoke_refresh_token(token).await?;
    }
    Ok(())
}

/* ===== RP-Initiated Logout (OpenID Connect RP-Initiated Logout 1.0) ===== */

#[derive(serde::Deserialize)]
pub(super) struct EndSessionQuery {
    id_token_hint: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
    client_id: Option<String>,
    /// 確かめの画面の form だけが付ける。POST でしか効かない。
    confirm: Option<String>,
}

struct IdTokenHint {
    sub: String,
    aud: String,
}

/// 自分の鍵で署名し、自分が発行した ID Token なら、その sub と aud を返す。
/// 期限は見ない。仕様第 2 節は、exp を過ぎた ID Token も受けることを SHOULD としている。
fn own_id_token(p: &Provider, jwt: &str) -> Option<IdTokenHint> {
    let mut parts = jwt.split('.');
    let (h, b, s) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let dec = |x: &str| crate::es256::b64url_decode(x).ok();
    let header: serde_json::Value = serde_json::from_slice(&dec(h)?).ok()?;
    let alg = header.get("alg")?.as_str()?;
    let kid = header.get("kid")?.as_str()?;
    let jwk = p
        .published_jwks()
        .into_iter()
        .find(|k| k["alg"] == alg && k["kid"] == kid)?;
    let part = |name: &str| jwk.get(name).and_then(|v| v.as_str()).and_then(dec);
    let input = format!("{h}.{b}");
    let sig = dec(s)?;
    let signed_by_us = match alg {
        "ES256" => {
            use p256::ecdsa::signature::Verifier;
            let vk = crate::es256::verifying_key_from_xy(&part("x")?, &part("y")?).ok()?;
            let sig = p256::ecdsa::Signature::from_slice(&sig).ok()?;
            vk.verify(input.as_bytes(), &sig).is_ok()
        }
        "RS256" => {
            crate::sig::verify_rs256(&part("n")?, &part("e")?, input.as_bytes(), &sig).is_ok()
        }
        _ => false,
    };
    if !signed_by_us {
        return None;
    }
    let claims: serde_json::Value = serde_json::from_slice(&dec(b)?).ok()?;
    if claims.get("iss")?.as_str()? != p.issuer {
        return None;
    }
    // aud は 1 つの client_id の文字列で発行している（grants.rs）。
    Some(IdTokenHint {
        sub: claims.get("sub")?.as_str()?.to_string(),
        aud: claims.get("aud")?.as_str()?.to_string(),
    })
}

/// RP からの GET。確かめの画面の confirm は GET では効かない。
pub(super) async fn end_session(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    jar: CookieJar,
    Query(q): Query<EndSessionQuery>,
) -> Response {
    sign_out(&p, &headers, jar, q, false).await
}

/// RP からの POST（form）と、確かめの画面からの POST。RP からの POST は他の origin から来るので
/// 管理画面の門は掛けず、確かめの画面の POST（confirm 付き）だけを、門と同じ考え方で自分の origin に限る。
pub(super) async fn end_session_post(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(q): Form<EndSessionQuery>,
) -> Response {
    let confirmed = q.confirm.is_some();
    if confirmed && !from_own_origin(&headers, &p.origin()) {
        tracing::warn!(event = "end_session_cross_origin_confirm_rejected");
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    sign_out(&p, &headers, jar, q, confirmed).await
}

async fn sign_out(
    p: &Provider,
    headers: &HeaderMap,
    jar: CookieJar,
    q: EndSessionQuery,
    confirmed: bool,
) -> Response {
    let lang = Lang::from_headers(headers);

    // id_token_hint は、自分の鍵の署名・iss・aud（登録済みの client）を確かめ、client_id があれば aud と比べる。
    let mut hint_failed = false;
    let hint = match q.id_token_hint.as_deref() {
        None => None,
        Some(t) => match own_id_token(p, t) {
            Some(h)
                if q.client_id.as_deref().is_none_or(|c| c == h.aud)
                    && p.resolve_client(&h.aud).await.is_some() =>
            {
                Some(h)
            }
            _ => {
                tracing::warn!(event = "end_session_hint_rejected");
                hint_failed = true;
                None
            }
        },
    };
    let client_id = q
        .client_id
        .clone()
        .or_else(|| hint.as_ref().map(|h| h.aud.clone()));

    // post_logout_redirect_uri は client 登録値のみ許可（オープンリダイレクト防止）。
    // hint が確かめに失敗した要求は、仕様第 4 節に従い RP へ戻さない（ログアウトは確かめの画面を経て行う）。
    // 戻り先が登録と食い違う要求も、hint の確かめに失敗したときと同じに扱う: 戻り先は捨て、確かめの画面へ回す。
    // 誤りで終わらせてセッションを残すと、共用の端末で OP にログインしたままになる。
    let mut unregistered = false;
    let return_to = match &q.post_logout_redirect_uri {
        Some(uri) if !hint_failed => {
            let registered = match client_id.as_deref() {
                Some(id) => match p.resolve_client(id).await {
                    Some(c) => c.post_logout_redirect_uris.iter().any(|u| u == uri),
                    None => false,
                },
                None => false,
            };
            if registered {
                Some(uri.clone())
            } else {
                tracing::warn!("end_session: post_logout_redirect_uri not registered: {uri}");
                unregistered = true;
                None
            }
        }
        _ => None,
    };
    let notice = if unregistered {
        "<p>[[The return address after sign-out is not registered for this app. Please contact the app provider.]]</p>"
    } else {
        ""
    };

    // 仕様第 2 節: hint が無い・確かめに失敗した・今のセッションの利用者の ID Token でない、のどれかなら、
    // ログアウトしてよいか利用者に確かめる。他のサイトから遷移させるだけでログアウトさせられないように。
    // 確かめの画面と、消せなかったときのもう一度の form が、RP への戻り先を引き継ぐ。
    let carried = match (&return_to, &client_id) {
        (Some(uri), Some(id)) => {
            let mut f = hidden("client_id", id) + &hidden("post_logout_redirect_uri", uri);
            if let Some(st) = &q.state {
                f += &hidden("state", st);
            }
            f
        }
        _ => String::new(),
    };
    let action = admin::esc(&p.path("/end-session"));
    let sid = jar.get(SID_COOKIE).map(|c| c.value().to_string());
    // 読めないときを「session が無い」と扱うと、確かめずに RP へ戻してしまう。
    let session = match &sid {
        Some(s) => match p.store.get_session(s).await {
            Ok(s) => s,
            Err(e) => return could_not_sign_out(lang, &action, &carried, "get_session", &e),
        },
        None => None,
    };
    let needs_confirm = !confirmed
        && session
            .as_ref()
            .is_some_and(|s| unregistered || hint.as_ref().is_none_or(|h| h.sub != s.account_id));
    if needs_confirm {
        let html = format!(
            r##"<!doctype html><html lang="__LANG__"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>[[Sign out]]</title>
<style>body{{font-family:Roboto,-apple-system,sans-serif;max-width:360px;margin:0 auto;padding:80px 24px;text-align:center;color:#1a1a1a}}
button{{font:inherit;padding:10px 24px;border:0;border-radius:4px;background:#3f51b5;color:#fff;cursor:pointer}}</style></head><body>
<h1 style="font-size:1.3rem;font-weight:500">[[Do you want to sign out?]]</h1>
{notice}<p>[[You will need to sign in again to use apps that sign in with this account.]]</p>
<form method="post" action="{action}"><input type="hidden" name="confirm" value="1">__CARRIED__
<button type="submit">[[Sign out]]</button></form></body></html>"##
        );
        // 訳は、RP から来た値（state など）を差し込む前に掛ける。後に掛けると、値の中の `__LANG__` や訳の印が書き換わる。
        let html = localize(&html, lang).replacen("__CARRIED__", &carried, 1);
        return ([(header::CACHE_CONTROL, "no-store")], Html(html)).into_response();
    }

    // 消せなかったら、ログアウトしたとは返さない。cookie は残す: 消すと、保存先に残った session を
    // この端末から消し直す手が無くなる。残せば、もう一度押せば同じ session を消しに行ける。
    if let Some(sid) = &sid
        && let Err(e) = p.store.delete_session(sid).await
    {
        return could_not_sign_out(lang, &action, &carried, "delete_session", &e);
    }
    let jar = jar.remove(
        Cookie::build((SID_COOKIE, ""))
            .path("/")
            .secure(true)
            .build(),
    );

    if let Some(mut target) = return_to {
        if let Some(state) = &q.state {
            let sep = if target.contains('?') { '&' } else { '?' };
            let qs = serde_urlencoded::to_string([("state", state)]).unwrap_or_default();
            target = format!("{target}{sep}{qs}");
        }
        return (jar, Redirect::to(&target)).into_response();
    }

    // リダイレクト先指定なし → 完了ページ。IdP のホームは /account（/ は demo RP）。
    let home = p.path("/account");
    let html = format!(
        r##"<!doctype html><html lang="__LANG__"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>[[Sign out]]</title>
<style>body{{font-family:Roboto,-apple-system,sans-serif;max-width:360px;margin:0 auto;padding:80px 24px;text-align:center;color:#1a1a1a}}
a{{color:#3f51b5}}</style></head><body>
<h1 style="font-size:1.3rem;font-weight:500">[[You have signed out]]</h1>
{notice}<p><a href="{home}">[[Go to sign in]]</a></p></body></html>"##
    );
    (jar, Html(localize(&html, lang))).into_response()
}

/// session を読めない・消せないときの 500。cookie は残し、確かめの画面と同じ form でもう一度押せるようにする。
fn could_not_sign_out(
    lang: Lang,
    action: &str,
    carried: &str,
    context: &str,
    e: &crate::store::StoreError,
) -> Response {
    tracing::error!("end_session: {context}: {e}");
    let html = format!(
        r##"<!doctype html><html lang="__LANG__"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>[[Sign out]]</title>
<style>body{{font-family:Roboto,-apple-system,sans-serif;max-width:360px;margin:0 auto;padding:80px 24px;text-align:center;color:#1a1a1a}}
button{{font:inherit;padding:10px 24px;border:0;border-radius:4px;background:#3f51b5;color:#fff;cursor:pointer}}</style></head><body>
<h1 style="font-size:1.3rem;font-weight:500">[[Could not sign out. Please try again.]]</h1>
<form method="post" action="{action}"><input type="hidden" name="confirm" value="1">__CARRIED__
<button type="submit">[[Sign out]]</button></form></body></html>"##
    );
    let html = localize(&html, lang).replacen("__CARRIED__", carried, 1);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(header::CACHE_CONTROL, "no-store")],
        Html(html),
    )
        .into_response()
}

fn hidden(name: &str, value: &str) -> String {
    format!(
        r#"<input type="hidden" name="{name}" value="{}">"#,
        admin::esc(value)
    )
}
/* ===== PAR (RFC 9126) ===== */

pub(super) async fn par(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let fs = match p.docs.as_deref() {
        Some(f) => f,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let form: HashMap<String, String> = serde_urlencoded::from_str(&body).unwrap_or_default();
    // RFC 9126 §2.1: PAR リクエスト自体に request_uri を含めてはならない。
    if form.contains_key("request_uri") {
        return OAuthError::InvalidRequest("request_uri must not be used in a PAR request".into())
            .into_response();
    }
    let client = match authenticate_client(&p, &headers, &form).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    // JAR (RFC 9101): request object があれば検証し、保存パラメータをその claims で
    // 置き換える（以後の処理・/authorize は検証済みパラメータを使う）。
    let body = if let Some(req) = form.get("request") {
        match crate::request_object::verify(&client, req, &p.issuer, &p.jar_jti).await {
            Ok(params) => serde_urlencoded::to_string(&params).unwrap_or_default(),
            Err(e) => return e.into_response(),
        }
    } else {
        body
    };
    let form: HashMap<String, String> = serde_urlencoded::from_str(&body).unwrap_or_default();
    // PAR 本体の client_id は認証済みクライアントと一致すること。
    if let Some(cid) = form.get("client_id")
        && cid != &client.client_id
    {
        return OAuthError::InvalidRequest("client_id mismatch".into()).into_response();
    }
    // DPoP at PAR (RFC 9449 §10): PAR が DPoP 署名されていれば、その proof の jkt に
    // 認可を束縛する。dpop_jkt パラメータがあれば proof と一致必須。proof のみなら
    // jkt を dpop_jkt として注入し、token endpoint で束縛を強制する。
    let body = if let Some(proof) = dpop_header(&headers) {
        let htu = format!("{}/par", p.issuer);
        let jkt = match p.dpop.verify(&proof, "POST", &htu, None).await {
            Ok(j) => j,
            Err(e) => return OAuthError::InvalidDpopProof(e).into_response(),
        };
        match form.get("dpop_jkt") {
            Some(req) if req != &jkt => {
                return OAuthError::InvalidDpopProof(
                    "dpop_jkt does not match the DPoP proof presented to the PAR endpoint".into(),
                )
                .into_response();
            }
            Some(_) => body,                          // 一致: そのまま
            None => format!("{body}&dpop_jkt={jkt}"), // proof の jkt を束縛として注入
        }
    } else {
        body
    };
    // client の資格情報は認可要求の値ではない。保存した要求（authorize の raw_query にも写る）に
    // 残すと、記録から漏れた assertion を jti の記録が消えた後に使い直せる。
    let body = match serde_urlencoded::from_str::<Vec<(String, String)>>(&body) {
        Ok(pairs) => serde_urlencoded::to_string(
            pairs
                .into_iter()
                .filter(|(k, _)| {
                    !matches!(
                        k.as_str(),
                        "client_assertion" | "client_assertion_type" | "client_secret"
                    )
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_default(),
        Err(_) => {
            return OAuthError::InvalidRequest("invalid PAR body".into()).into_response();
        }
    };
    match crate::par::create(fs, &client.client_id, &body).await {
        Ok(ru) => (
            StatusCode::CREATED,
            [(header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({ "request_uri": ru.0, "expires_in": 60 })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("par create: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response()
        }
    }
}
async fn userinfo_respond(
    p: &Provider,
    headers: &HeaderMap,
    method: &str,
    body_token: Option<String>,
) -> Response {
    let at = match authenticate_token(p, headers, method, "/userinfo", body_token).await {
        Ok(at) => at,
        Err(r) => return r,
    };
    let account = p.store.find_account(&at.account_id).await;
    let allowed = crate::claims::claim_names_for_scopes(&at.scope);
    let filtered: HashMap<&str, &serde_json::Value> = allowed
        .iter()
        .filter_map(|name| account.claims.get(*name).map(|v| (*name, v)))
        .collect();
    Json(filtered).into_response()
}

/* ===== profile（編集可能 claim の表示・更新） ===== */

/// 保存済みの編集可能 claim のみを返す（未設定は欠落させ、画面側で空表示にする）。
/// userinfo 用の account_for ダミーは混ぜない。
fn profile_view(sub: &str, profile: &HashMap<String, String>) -> serde_json::Value {
    serde_json::json!({
        "sub": sub,
        "editable_fields": crate::claims::EDITABLE,
        "profile": profile,
    })
}

pub(super) async fn profile_get(State(p): State<Arc<Provider>>, headers: HeaderMap) -> Response {
    let at = match authenticate_token(&p, &headers, "GET", "/me/profile", None).await {
        Ok(at) => at,
        Err(r) => return r,
    };
    let profile = match p.docs.as_deref() {
        Some(fs) => crate::registration::get_profile(fs, &at.account_id)
            .await
            .unwrap_or_default(),
        None => HashMap::new(),
    };
    Json(profile_view(&at.account_id, &profile)).into_response()
}

pub(super) async fn profile_put(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let at = match authenticate_token(&p, &headers, "PUT", "/me/profile", None).await {
        Ok(at) => at,
        Err(r) => return r,
    };
    let fs = match p.docs.as_deref() {
        Some(f) => f,
        None => return (StatusCode::NOT_IMPLEMENTED, "profile store unavailable").into_response(),
    };
    let updates: HashMap<String, String> = match serde_json::from_str(&body) {
        Ok(m) => m,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid body: {e}")).into_response(),
    };
    match crate::registration::save_profile(fs, &at.account_id, &updates).await {
        Ok(()) => {}
        Err(e @ crate::registration::ProfileError::Invalid(_)) => {
            return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("save: {e}")).into_response(),
    }
    let profile = crate::registration::get_profile(fs, &at.account_id)
        .await
        .unwrap_or_default();
    Json(profile_view(&at.account_id, &profile)).into_response()
}

pub(super) async fn userinfo_get(State(p): State<Arc<Provider>>, headers: HeaderMap) -> Response {
    userinfo_respond(&p, &headers, "GET", None).await
}

/// POST userinfo（Bearer/DPoP ヘッダ、無ければ body の access_token）。
pub(super) async fn userinfo_post(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let body_token = serde_urlencoded::from_str::<HashMap<String, String>>(&body)
        .ok()
        .and_then(|m| m.get("access_token").cloned());
    userinfo_respond(&p, &headers, "POST", body_token).await
}

/* ===== Dynamic Client Registration (RFC 7591, IAT 制御つき) ===== */

/// POST /oauth/register。Initial Access Token(Bearer) を単回消費し、制約内のクライアントを
/// Firestore に登録する。認証方式(token_endpoint_auth_method)は RP のリクエストではなく
/// IAT に埋め込まれた [`crate::dcr::ClientProfile`] で決まる（Public/ConfidentialSecret/
/// ConfidentialKey）。ConfidentialSecret の場合のみ、生成した client_secret を登録
/// レスポンスへ一度だけ平文で載せる（保存は常にハッシュのみ）。
///
/// 消費順序: peek(削除しない) → 期限 → validate → consume_iat(CAS 削除=単回) →
/// save_client。検証失敗では IAT を消費しないので RP はメタデータを直して再試行できる。
/// 生 IAT・Authorization ヘッダはログに出さない（相関はハッシュ先頭のみ）。
pub(super) async fn register(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let fs = match p.docs.as_deref() {
        Some(f) => f,
        None => {
            return dcr_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "registration unavailable (no Firestore)",
            );
        }
    };
    let raw_iat = match auth_scheme_token(&headers) {
        Some((scheme, tok)) if scheme == "Bearer" => tok,
        _ => {
            return dcr_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "initial access token required",
            );
        }
    };
    let hash = crate::dcr::hash_token(&raw_iat);
    let tag = &hash[..8]; // 相関用の安全なハンドル（生トークンは出さない）。

    // IAT を読む（消費はしない）。不明・期限切れは Firestore read 1 回で 401 に落とす。
    let iat = match crate::dcr_store::peek_iat(fs, &hash).await {
        Ok(Some(x)) => x,
        Ok(None) => {
            // 不明トークンも IP レート制限に数えて無効 Bearer 連発を bounding する。
            let _ = p
                .register_rate
                .check_and_record(fs, "dcr-register", &client_ip(&headers))
                .await;
            return dcr_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "unknown initial access token",
            );
        }
        Err(e) => {
            tracing::error!("dcr peek_iat [{tag}]: {e}");
            return dcr_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "registration failed",
            );
        }
    };
    if now() >= iat.expires_at {
        return dcr_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "initial access token expired",
        );
    }

    // 素朴な単一 IP からの連発 backstop。本番の単回 IAT のみ throttle する。
    // reusable(conformance 専用・短 TTL)はスイートがモジュール毎に多数登録するため免除。
    // 数は保存先に置くので台をまたいで 1 つ。X-F-F は詐称できるので増幅防御ではない——IAT 必須が本来の門。
    if !iat.reusable {
        match p
            .register_rate
            .check_and_record(fs, "dcr-register", &client_ip(&headers))
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return dcr_error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too_many_requests",
                    "registration rate limit exceeded; retry later",
                );
            }
            Err(e) => {
                tracing::error!("dcr rate limit [{tag}]: {e}");
                return dcr_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "registration failed",
                );
            }
        }
    }

    let v: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => {
            return dcr_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "request body is not valid JSON",
            );
        }
    };
    let req = registration_request_from_json(&v);

    let client_id = format!("dcr-{}", uuid::Uuid::new_v4().simple());
    let outcome = match crate::dcr::validate_registration(&client_id, &req, &iat.constraints) {
        Ok(o) => o,
        // 検証失敗では IAT を消費しない（メタデータ修正後に再試行可能）。
        Err(e) => return dcr_error(StatusCode::BAD_REQUEST, e.code(), &e.description()),
    };
    let client = outcome.client;

    // 単回消費: 検証成功後にだけ CAS 削除する。負け＝並行/再利用なので拒否。
    // reusable IAT は消費せず残す（期限内は再登録可能。conformance 専用）。
    if !iat.reusable {
        match crate::dcr_store::consume_iat(fs, &hash, &iat.update_time).await {
            Ok(true) => {}
            Ok(false) => {
                return dcr_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_token",
                    "initial access token already used",
                );
            }
            Err(e) => {
                tracing::error!("dcr consume_iat [{tag}]: {e}");
                return dcr_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "registration failed",
                );
            }
        }
    }

    if let Err(e) = crate::dcr_store::save_client(fs, &client).await {
        // CAS には勝ったが保存に失敗。IAT は焼かれた（管理者が再発行）。fail-closed。
        tracing::error!("dcr save_client [{tag}] {}: {e}", client.client_id);
        return dcr_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "registration failed",
        );
    }
    tracing::info!(event = "dcr_client_registered", client_id = %client.client_id);

    (
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, "no-store")],
        Json(register_response(
            &client,
            outcome.raw_client_secret.as_deref(),
        )),
    )
        .into_response()
}

fn dcr_error(status: StatusCode, error: &str, desc: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({ "error": error, "error_description": desc })),
    )
        .into_response()
}

/// 登録要求の JSON を RegistrationRequest に写す。
///
/// ハンドラから切り出してあるのは、この**配線**を試験で押さえるため。検証側
/// （dcr::validate_registration）に試験が在っても、ここで項目を読み落とすと
/// 黙って既定値（空）で登録される——実際、post_logout_redirect_uris はこの
/// 配線が無かったために「登録しても必ず空」になり、サインアウトが落ちていた。
fn registration_request_from_json(v: &serde_json::Value) -> crate::dcr::RegistrationRequest {
    crate::dcr::RegistrationRequest {
        redirect_uris: json_string_array(v, "redirect_uris"),
        post_logout_redirect_uris: json_string_array(v, "post_logout_redirect_uris"),
        initiate_login_uri: v
            .get("initiate_login_uri")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from),
        grant_types: json_string_array(v, "grant_types"),
        jwks: crate::dcr::jwks_from_jwk_set(v.get("jwks")),
        jwks_uri: v.get("jwks_uri").and_then(|x| x.as_str()).map(String::from),
    }
}

fn json_string_array(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// RFC 7591 §3.2.1 client information response（登録済みメタデータをエコー）。
/// raw_client_secret は ConfidentialSecret プロファイルの場合のみ Some
/// （登録レスポンスに一度だけ平文を載せる。RFC 7591 §3.2.1 の client_secret）。
/// Client 自体にはハッシュしか無いので、平文はここで別に受け取る。
fn register_response(
    c: &crate::model::Client,
    raw_client_secret: Option<&str>,
) -> serde_json::Value {
    let mut resp = serde_json::json!({
        "client_id": c.client_id,
        "client_id_issued_at": now(),
        "token_endpoint_auth_method": c.token_endpoint_auth_method,
        "grant_types": c.grant_types,
        "redirect_uris": c.redirect_uris,
        "post_logout_redirect_uris": c.post_logout_redirect_uris,
        "require_pushed_authorization_requests": c.require_par,
    });
    if let Some(uri) = &c.initiate_login_uri {
        resp["initiate_login_uri"] = serde_json::json!(uri);
    }
    if let Some(uri) = &c.jwks_uri {
        resp["jwks_uri"] = serde_json::json!(uri);
    }
    if let Some(secret) = raw_client_secret {
        resp["client_secret"] = serde_json::json!(secret);
        // RFC 7591 §3.2.1: client_secret を返す場合は必須。secret のローテーション/失効を
        // 実装していないため 0（=失効しない）で固定する。
        resp["client_secret_expires_at"] = serde_json::json!(0);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AccessToken;

    fn client_with_post_logout(uris: &[&str]) -> crate::model::Client {
        crate::model::Client {
            client_id: "dcr-x".into(),
            redirect_uris: vec!["https://rp.example.com/cb".into()],
            post_logout_redirect_uris: uris.iter().map(|s| s.to_string()).collect(),
            initiate_login_uri: None,
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some("hash".into()),
            grant_types: vec!["authorization_code".into()],
            dpop_bound: false,
            jwks: vec![],
            jwks_uri: None,
            require_par: false,
            require_pkce: true,
            id_token_signed_response_alg: None,
        }
    }

    #[cfg(feature = "gcp")]
    #[tokio::test]
    async fn a_request_uri_cannot_be_used_by_another_client() {
        let (host, _state) = crate::firestore::fake_firestore::spawn().await;
        let fs = Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
        let p = Arc::new(Provider::new("https://op.example").with_firestore(fs.clone()));
        let ru = crate::par::create(
            &*fs,
            "dcr-y",
            "client_id=dcr-y&response_type=code&scope=openid",
        )
        .await
        .unwrap();
        let authorize_as = |client: &str| {
            let q = serde_urlencoded::to_string([
                ("client_id", client),
                ("request_uri", ru.0.as_str()),
            ])
            .unwrap();
            authorize(
                State(p.clone()),
                HeaderMap::new(),
                CookieJar::default(),
                RawQuery(Some(q)),
            )
        };
        async fn text(r: Response) -> String {
            String::from_utf8(
                axum::body::to_bytes(r.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap()
        }

        for other in ["dcr-x", "dcr-yy", "dcr-", "DCR-Y", "dcr-y "] {
            let stolen = authorize_as(other).await;
            assert_eq!(stolen.status(), StatusCode::BAD_REQUEST, "{other:?}");
            // 画面には訳した文と error code だけが出る（詳細はログ）。request_uri は在るので、
            // invalid_request_uri になるのは発行先の不一致だけ。
            assert!(
                text(stolen)
                    .await
                    .ends_with("(error code: invalid_request_uri)"),
                "{other:?}"
            );
        }
        let own = text(authorize_as("dcr-y").await).await;
        assert!(!own.contains("invalid_request_uri"), "{own}");
    }

    #[tokio::test]
    async fn end_session_redirects_only_to_the_clients_own_registered_uri() {
        let other = crate::model::Client {
            client_id: "dcr-y".into(),
            post_logout_redirect_uris: vec!["https://other.example/bye".into()],
            ..client_with_post_logout(&[])
        };
        let p = Arc::new(
            Provider::new("https://op.example")
                .with_client(client_with_post_logout(&["https://rp.example.com/bye"]))
                .with_client(other),
        );
        let end = |client_id: Option<&str>, uri: &str| {
            let q = EndSessionQuery {
                id_token_hint: None,
                post_logout_redirect_uri: Some(uri.to_string()),
                state: Some("s1".into()),
                client_id: client_id.map(str::to_string),
                confirm: None,
            };
            end_session(
                State(p.clone()),
                HeaderMap::new(),
                CookieJar::default(),
                Query(q),
            )
        };

        let ok = end(Some("dcr-x"), "https://rp.example.com/bye").await;
        assert!(ok.status().is_redirection());
        assert_eq!(
            ok.headers().get(header::LOCATION).unwrap(),
            "https://rp.example.com/bye?state=s1"
        );

        for (client, uri) in [
            (Some("dcr-x"), "https://other.example/bye"),
            (Some("dcr-x"), "https://rp.example.com/bye/../evil"),
            (Some("dcr-x"), "https://rp.example.com/bye?x=1"),
            (
                Some("dcr-x"),
                "https://evil.example/#https://rp.example.com/bye",
            ),
            (Some("dcr-x"), "https://rp.example.co"),
            (Some("dcr-x"), "https://rp.example.com/BYE"),
            (Some("dcr-x"), "https://rp.example.com/bye/"),
            (Some("unknown"), "https://rp.example.com/bye"),
            (None, "https://rp.example.com/bye"),
        ] {
            // 戻さずにログアウトを済ませ、戻り先が登録されていないことを画面で知らせる。
            let resp = end(client, uri).await;
            assert_eq!(resp.status(), StatusCode::OK, "{client:?} {uri}");
            assert!(resp.headers().get(header::LOCATION).is_none());
            let body = String::from_utf8(
                axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            assert!(
                body.contains("is not registered for this app"),
                "{client:?} {uri}: {body}"
            );
        }
    }

    /// RP-Initiated Logout 1.0 の確かめ。router を通し、セッションが残ったか消えたかまで見る。
    mod rp_initiated_logout {
        use super::*;
        use crate::jws::JwsSigner;
        use tower::ServiceExt;

        const OP: &str = "https://op.example";
        const BYE: &str = "https://rp.example.com/bye";

        struct World {
            app: Router,
            store: Arc<dyn crate::store::Store>,
            /// 自分の鍵で署名した正しい hint。
            hint: String,
            /// RS256 で発行する client 向けの、正しい hint。
            rs_hint: String,
            /// 自分の鍵で署名したが、iss・aud・sub のどれかが違う hint。
            off: Vec<(&'static str, String)>,
        }

        async fn world() -> World {
            let other = crate::model::Client {
                client_id: "dcr-y".into(),
                ..client_with_post_logout(&[])
            };
            let p = Provider::new(OP)
                .with_client(client_with_post_logout(&[BYE]))
                .with_client(other)
                .add_signer(Arc::new(crate::jws::Rs256Signer::generate()));
            let hint = id_token(&p, serde_json::json!({})).await;
            let rs_claims =
                serde_json::json!({"iss": OP, "sub": "acc-1", "aud": "dcr-x", "iat": 1, "exp": 2});
            let rs_hint = p.signer_for(Some("RS256")).unwrap().sign(&rs_claims).await;
            let mut off = Vec::new();
            for (name, over) in [
                (
                    "other iss",
                    serde_json::json!({"iss": "https://op.example.evil"}),
                ),
                ("unregistered aud", serde_json::json!({"aud": "nope"})),
                ("aud list", serde_json::json!({"aud": ["dcr-x"]})),
            ] {
                off.push((name, id_token(&p, over).await));
            }
            World {
                store: p.store.clone(),
                app: super::super::router(p),
                hint,
                rs_hint,
                off,
            }
        }

        /// 自分の鍵で署名した、acc-1 が dcr-x に入ったときの ID Token。exp は過ぎている。
        async fn id_token(p: &Provider, over: serde_json::Value) -> String {
            let mut claims =
                serde_json::json!({"iss": OP, "sub": "acc-1", "aud": "dcr-x", "iat": 1, "exp": 2});
            for (k, v) in over.as_object().unwrap() {
                claims[k] = v.clone();
            }
            p.signer_for(None).unwrap().sign(&claims).await
        }

        impl World {
            async fn signed_in(&self, sid: &str) {
                self.store
                    .save_session(Session {
                        sid: sid.into(),
                        account_id: "acc-1".into(),
                        auth_time: 0,
                    })
                    .await
                    .unwrap();
            }
            async fn still_signed_in(&self, sid: &str) -> bool {
                self.store.get_session(sid).await.unwrap().is_some()
            }
            async fn send(
                &self,
                method: &str,
                sid: &str,
                params: &[(&str, &str)],
                origin: Option<&str>,
            ) -> Response {
                let qs = serde_urlencoded::to_string(params).unwrap();
                let mut req = axum::http::Request::builder()
                    .method(method)
                    .header(header::COOKIE, format!("{SID_COOKIE}={sid}"));
                if let Some(o) = origin {
                    req = req.header(header::ORIGIN, o);
                }
                let req = if method == "GET" {
                    req.uri(format!("/end-session?{qs}"))
                        .body(axum::body::Body::empty())
                } else {
                    req.uri("/end-session")
                        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                        .body(axum::body::Body::from(qs))
                };
                self.app.clone().oneshot(req.unwrap()).await.unwrap()
            }
        }

        async fn body(r: Response) -> String {
            String::from_utf8(
                axum::body::to_bytes(r.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap()
        }

        fn signed_out_to_rp(r: &Response) {
            assert!(r.status().is_redirection(), "{}", r.status());
            assert_eq!(r.headers()[header::LOCATION], format!("{BYE}?state=s1"));
            let set = r.headers()[header::SET_COOKIE].to_str().unwrap();
            assert!(set.starts_with(&format!("{SID_COOKIE}=;")), "{set}");
        }

        async fn asks_first(r: Response) -> String {
            assert_eq!(r.status(), StatusCode::OK);
            assert!(
                r.headers().get(header::SET_COOKIE).is_none(),
                "確かめる前に cookie を消した"
            );
            let html = body(r).await;
            assert!(html.contains("Do you want to sign out?"), "{html}");
            assert!(html.contains(r#"<form method="post" action="/end-session"><input type="hidden" name="confirm" value="1">"#), "{html}");
            html
        }

        /// AMATE の形（GET、client_id・post_logout_redirect_uri・期限切れの id_token_hint）は、確かめずにログアウトして戻す。
        #[tokio::test]
        async fn a_valid_hint_signs_out_without_asking_even_after_it_expired() {
            let w = world().await;
            w.signed_in("s-get").await;
            let r = w
                .send(
                    "GET",
                    "s-get",
                    &[
                        ("id_token_hint", &w.hint),
                        ("client_id", "dcr-x"),
                        ("post_logout_redirect_uri", BYE),
                        ("state", "s1"),
                    ],
                    None,
                )
                .await;
            signed_out_to_rp(&r);
            assert!(!w.still_signed_in("s-get").await);

            // client_id が無くても、hint の aud から client を引く。
            w.signed_in("s-aud").await;
            let r = w
                .send(
                    "GET",
                    "s-aud",
                    &[
                        ("id_token_hint", &w.hint),
                        ("post_logout_redirect_uri", BYE),
                        ("state", "s1"),
                    ],
                    None,
                )
                .await;
            signed_out_to_rp(&r);
            assert!(!w.still_signed_in("s-aud").await);

            w.signed_in("s-rs").await;
            let r = w
                .send(
                    "GET",
                    "s-rs",
                    &[
                        ("id_token_hint", &w.rs_hint),
                        ("post_logout_redirect_uri", BYE),
                        ("state", "s1"),
                    ],
                    None,
                )
                .await;
            signed_out_to_rp(&r);
            assert!(!w.still_signed_in("s-rs").await);
        }

        /// RP は form の POST でも呼べる（仕様第 2 節）。RP の origin から来るので、Origin は問わない。
        #[tokio::test]
        async fn an_rp_can_post_the_logout_request_from_its_own_origin() {
            let w = world().await;
            w.signed_in("s-post").await;
            let r = w
                .send(
                    "POST",
                    "s-post",
                    &[
                        ("id_token_hint", &w.hint),
                        ("client_id", "dcr-x"),
                        ("post_logout_redirect_uri", BYE),
                        ("state", "s1"),
                    ],
                    Some("https://rp.example.com"),
                )
                .await;
            signed_out_to_rp(&r);
            assert!(!w.still_signed_in("s-post").await);

            // hint の無い POST は、GET と同じく確かめる。
            w.signed_in("s-post2").await;
            asks_first(
                w.send(
                    "POST",
                    "s-post2",
                    &[("client_id", "dcr-x")],
                    Some("https://rp.example.com"),
                )
                .await,
            )
            .await;
            assert!(w.still_signed_in("s-post2").await);
        }

        /// hint が無ければ確かめる。戻り先は form に載せて引き継ぐ。GET に confirm を付けても確かめは飛ばせない。
        #[tokio::test]
        async fn without_a_hint_the_user_is_asked_first() {
            let w = world().await;
            w.signed_in("s-none").await;
            let params = [
                ("client_id", "dcr-x"),
                ("post_logout_redirect_uri", BYE),
                ("state", "s1"),
            ];
            let html = asks_first(w.send("GET", "s-none", &params, None).await).await;
            for f in [
                r#"name="client_id" value="dcr-x""#,
                r#"name="post_logout_redirect_uri" value="https://rp.example.com/bye""#,
                r#"name="state" value="s1""#,
            ] {
                assert!(html.contains(f), "{f}: {html}");
            }
            assert!(w.still_signed_in("s-none").await);

            let mut with_confirm = params.to_vec();
            with_confirm.push(("confirm", "1"));
            asks_first(w.send("GET", "s-none", &with_confirm, None).await).await;
            assert!(w.still_signed_in("s-none").await);

            // セッションが無ければ、消すものが無いので確かめない。
            let r = w.send("GET", "s-gone", &params, None).await;
            signed_out_to_rp(&r);
        }

        /// 確かめの画面の POST は、自分の origin から来たときだけ通す。
        #[tokio::test]
        async fn the_confirmation_post_must_come_from_our_own_origin() {
            let w = world().await;
            w.signed_in("s-c").await;
            let params = [
                ("confirm", "1"),
                ("client_id", "dcr-x"),
                ("post_logout_redirect_uri", BYE),
                ("state", "s1"),
            ];
            for origin in [
                Some("https://rp.example.com"),
                Some("https://op.example.evil"),
                Some("null"),
                None,
            ] {
                let r = w.send("POST", "s-c", &params, origin).await;
                assert_eq!(r.status(), StatusCode::FORBIDDEN, "{origin:?}");
                assert!(w.still_signed_in("s-c").await, "{origin:?}");
            }
            let r = w.send("POST", "s-c", &params, Some(OP)).await;
            signed_out_to_rp(&r);
            assert!(!w.still_signed_in("s-c").await);
        }

        /// 他の鍵の署名・他の iss・他の aud・client_id と食い違う aud・他の利用者の hint は、確かめに回す。
        /// 確かめに失敗した hint の要求は、RP へ戻さない（仕様第 4 節）。
        #[tokio::test]
        async fn a_hint_that_fails_verification_does_not_skip_the_question() {
            let w = world().await;
            let stranger = crate::jws::Es256Signer::generate();
            let claims =
                serde_json::json!({"iss": OP, "sub": "acc-1", "aud": "dcr-x", "iat": 1, "exp": 2});
            let other_key = stranger.sign(&claims).await;
            // 自分の kid を名乗り、他の鍵で署名したもの。
            let our_header = w.hint.split('.').next().unwrap();
            let forged = format!("{our_header}.{}", other_key.split_once('.').unwrap().1);
            let mut cases = vec![
                ("other key", other_key, Some("dcr-x")),
                ("forged kid", forged, Some("dcr-x")),
                ("client_id is not the aud", w.hint.clone(), Some("dcr-y")),
                ("not a jwt", "abc".to_string(), None),
            ];
            for (name, hint) in &w.off {
                cases.push((*name, hint.clone(), None));
            }
            for (name, hint, client) in cases {
                let sid = format!("s-{name}");
                w.signed_in(&sid).await;
                let mut params = vec![
                    ("id_token_hint", hint.as_str()),
                    ("post_logout_redirect_uri", BYE),
                    ("state", "s1"),
                ];
                if let Some(c) = client {
                    params.push(("client_id", c));
                }
                let html = asks_first(w.send("GET", &sid, &params, None).await).await;
                assert!(
                    !html.contains("post_logout_redirect_uri"),
                    "{name}: 戻り先を引き継いだ"
                );
                assert!(w.still_signed_in(&sid).await, "{name}");
            }
        }

        /// 署名鍵を入れ替えた後も、前の鍵を検証用に残している間は、前の鍵の ID Token が /jwks で
        /// 確かめられ、hint としても通る。前の鍵は署名には使わない。外した後は、確かめに回す。
        #[tokio::test]
        async fn a_hint_signed_by_the_previous_key_passes_while_that_key_is_kept() {
            let old = crate::jws::Es256Signer::generate();
            let old_jwk = old.public_jwk();
            let claims =
                serde_json::json!({"iss": OP, "sub": "acc-1", "aud": "dcr-x", "iat": 1, "exp": 2});
            let hint = old.sign(&claims).await;
            let rotated = |keep: bool| {
                let p = Provider::new(OP).with_client(client_with_post_logout(&[BYE]));
                if keep {
                    p.add_verify_only_jwk(old_jwk.clone())
                } else {
                    p
                }
            };
            let world_of = |p: Provider| World {
                store: p.store.clone(),
                app: super::super::router(p),
                hint: hint.clone(),
                rs_hint: String::new(),
                off: vec![],
            };

            let p = Arc::new(rotated(true));
            assert_ne!(
                p.signer_for(None).unwrap().public_jwk()["kid"],
                old_jwk["kid"]
            );
            assert_eq!(p.all_signers().count(), 1, "前の鍵を署名の鍵に数えた");
            let keys = jwks(State(p.clone())).await.0["keys"].clone();
            let old_kid = old_jwk["kid"].clone();
            let published = keys
                .as_array()
                .unwrap()
                .iter()
                .find(|k| k["kid"] == old_kid);
            assert_eq!(published, Some(&old_jwk), "{keys}");
            // RP の確かめ方: header の kid で /jwks の鍵を選び、署名を確かめる。
            let (input, sig) = hint.rsplit_once('.').unwrap();
            let jwk = published.unwrap();
            let x = crate::es256::b64url_decode(jwk["x"].as_str().unwrap()).unwrap();
            let y = crate::es256::b64url_decode(jwk["y"].as_str().unwrap()).unwrap();
            let vk = crate::es256::verifying_key_from_xy(&x, &y).unwrap();
            let sig = crate::es256::b64url_decode(sig).unwrap();
            let sig = p256::ecdsa::Signature::from_slice(&sig).unwrap();
            use p256::ecdsa::signature::Verifier;
            assert!(vk.verify(input.as_bytes(), &sig).is_ok());

            let params = [
                ("id_token_hint", hint.as_str()),
                ("post_logout_redirect_uri", BYE),
                ("state", "s1"),
            ];
            let w = world_of(rotated(true));
            w.signed_in("s-kept").await;
            signed_out_to_rp(&w.send("GET", "s-kept", &params, None).await);

            let w = world_of(rotated(false));
            w.signed_in("s-removed").await;
            asks_first(w.send("GET", "s-removed", &params, None).await).await;
            assert!(w.still_signed_in("s-removed").await);
        }

        /// 戻り先が登録と食い違えば、正しい hint があっても戻り先を捨てて確かめに回す。誤りで終わらせてセッションを残さない。
        #[tokio::test]
        async fn an_unregistered_return_address_asks_first_and_does_not_return() {
            let w = world().await;
            w.signed_in("s-bad-uri").await;
            let html = asks_first(
                w.send(
                    "GET",
                    "s-bad-uri",
                    &[
                        ("id_token_hint", &w.hint),
                        ("client_id", "dcr-x"),
                        ("post_logout_redirect_uri", "https://evil.example/"),
                        ("state", "s1"),
                    ],
                    None,
                )
                .await,
            )
            .await;
            assert!(
                !html.contains("post_logout_redirect_uri"),
                "戻り先を引き継いだ: {html}"
            );
            assert!(html.contains("is not registered for this app"), "{html}");
            assert!(w.still_signed_in("s-bad-uri").await);

            let r = w
                .send("POST", "s-bad-uri", &[("confirm", "1")], Some(OP))
                .await;
            assert_eq!(r.status(), StatusCode::OK);
            assert!(r.headers().get(header::LOCATION).is_none());
            assert!(!w.still_signed_in("s-bad-uri").await);
        }

        /// RP から来た state は、訳の印や言語の差し込み口に見えても書き換えずに引き継ぐ。
        #[tokio::test]
        async fn the_carried_state_is_not_touched_by_translation() {
            let w = world().await;
            w.signed_in("s-state").await;
            let state = "__LANG__[[Sign out]]";
            let html = asks_first(
                w.send(
                    "GET",
                    "s-state",
                    &[
                        ("client_id", "dcr-x"),
                        ("post_logout_redirect_uri", BYE),
                        ("state", state),
                    ],
                    None,
                )
                .await,
            )
            .await;
            assert!(
                html.contains(r#"name="state" value="__LANG__[[Sign out]]""#),
                "{html}"
            );
        }

        /// 正しい hint でも、今ログインしている利用者のものでなければ確かめる（仕様第 2 節）。
        #[tokio::test]
        async fn a_hint_for_someone_else_than_the_signed_in_user_asks_first() {
            let w = world().await;
            w.store
                .save_session(Session {
                    sid: "s-2".into(),
                    account_id: "acc-2".into(),
                    auth_time: 0,
                })
                .await
                .unwrap();
            let html = asks_first(
                w.send(
                    "GET",
                    "s-2",
                    &[
                        ("id_token_hint", &w.hint),
                        ("post_logout_redirect_uri", BYE),
                        ("state", "s1"),
                    ],
                    None,
                )
                .await,
            )
            .await;
            assert!(html.contains(r#"name="client_id" value="dcr-x""#), "{html}");
            assert!(w.store.get_session("s-2").await.unwrap().is_some());
        }

        /// session を読めて消せないときは、消す所に届くどの道も、500 ともう一度押す form を返す。
        /// RP へ戻さず、cookie も消さない（残せば、もう一度押して同じ session を消しに行ける）。
        #[cfg(feature = "gcp")]
        #[tokio::test]
        async fn every_path_that_reaches_the_delete_refuses_when_the_session_cannot_be_deleted() {
            let (host, fake) = crate::firestore::fake_firestore::spawn().await;
            let fs = Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
            let p = Provider::new(OP)
                .with_store(Arc::new(crate::firestore_store::FirestoreStore::new(fs)))
                .with_client(client_with_post_logout(&[BYE]));
            let hint = id_token(&p, serde_json::json!({})).await;
            let w = World {
                store: p.store.clone(),
                app: super::super::router(p),
                hint,
                rs_hint: String::new(),
                off: vec![],
            };
            let to_rp = [
                ("client_id", "dcr-x"),
                ("post_logout_redirect_uri", BYE),
                ("state", "s1"),
            ];
            let with_hint = |rest: &[(&'static str, &'static str)]| {
                let mut v = vec![("id_token_hint", w.hint.as_str())];
                v.extend_from_slice(rest);
                v
            };
            let confirm = |rest: &[(&'static str, &'static str)]| {
                let mut v = vec![("confirm", "1")];
                v.extend_from_slice(rest);
                v
            };
            let unregistered = [
                ("client_id", "dcr-x"),
                (
                    "post_logout_redirect_uri",
                    "https://rp.example.com/elsewhere",
                ),
            ];
            // (道, method, params, Origin, 戻り先を引き継ぐか, session があるか)
            let cases = vec![
                (
                    "hint の GET・戻り先あり",
                    "GET",
                    with_hint(&to_rp),
                    None,
                    true,
                    true,
                ),
                (
                    "hint の GET・戻り先なし",
                    "GET",
                    with_hint(&[]),
                    None,
                    false,
                    true,
                ),
                (
                    "hint の RP の POST・戻り先あり",
                    "POST",
                    with_hint(&to_rp),
                    Some("https://rp.example.com"),
                    true,
                    true,
                ),
                (
                    "hint の RP の POST・戻り先なし",
                    "POST",
                    with_hint(&[]),
                    Some("https://rp.example.com"),
                    false,
                    true,
                ),
                (
                    "確かめの POST・戻り先あり",
                    "POST",
                    confirm(&to_rp),
                    Some(OP),
                    true,
                    true,
                ),
                (
                    "確かめの POST・戻り先なし",
                    "POST",
                    confirm(&[]),
                    Some(OP),
                    false,
                    true,
                ),
                (
                    "確かめの POST・登録に無い戻り先",
                    "POST",
                    confirm(&unregistered),
                    Some(OP),
                    false,
                    true,
                ),
                (
                    "session の無い cookie の GET",
                    "GET",
                    to_rp.to_vec(),
                    None,
                    true,
                    false,
                ),
            ];
            for (i, (path, method, params, origin, carried, has_session)) in
                cases.into_iter().enumerate()
            {
                let sid = format!("s-del-{i}");
                if has_session {
                    w.signed_in(&sid).await;
                }
                fake.fail_once("DELETE", "sessions", Some(&sid));
                let r = w.send(method, &sid, &params, origin).await;
                assert_eq!(
                    r.status(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "{path}: 消せないのにログアウトしたと返した"
                );
                assert!(
                    r.headers().get(header::LOCATION).is_none(),
                    "{path}: RP へ戻した"
                );
                assert!(
                    r.headers().get(header::SET_COOKIE).is_none(),
                    "{path}: 消せない session の cookie を消した"
                );
                let html = body(r).await;
                assert!(html.contains("Could not sign out"), "{path}: {html}");
                assert!(
                    html.contains(r#"<form method="post" action="/end-session"><input type="hidden" name="confirm" value="1">"#),
                    "{path}: もう一度押す form が無い: {html}"
                );
                let fields = [
                    r#"name="client_id" value="dcr-x""#,
                    r#"name="post_logout_redirect_uri" value="https://rp.example.com/bye""#,
                    r#"name="state" value="s1""#,
                ];
                for f in fields {
                    assert_eq!(html.contains(f), carried, "{path}: {f}: {html}");
                }
                assert_eq!(w.still_signed_in(&sid).await, has_session, "{path}");
            }
        }
    }

    /// 登録要求の配線。ここで読み落とすと、検証側に試験が在っても黙って空で登録される
    /// （post_logout_redirect_uris で実際に起きた事故の形）。
    #[test]
    fn registration_request_reads_post_logout_redirect_uris() {
        let v = serde_json::json!({
            "redirect_uris": ["https://rp.example.com/cb"],
            "post_logout_redirect_uris": ["https://rp.example.com/", "https://rp.example.com/bye"],
        });
        let req = registration_request_from_json(&v);
        assert_eq!(
            req.post_logout_redirect_uris,
            vec!["https://rp.example.com/", "https://rp.example.com/bye"]
        );
        assert_eq!(req.redirect_uris, vec!["https://rp.example.com/cb"]);
        // 省略時は空（従来どおり）。
        let none = registration_request_from_json(&serde_json::json!({
            "redirect_uris": ["https://rp.example.com/cb"]
        }));
        assert!(none.post_logout_redirect_uris.is_empty());
    }

    /// RFC 7591 §3.2.1: 登録応答は登録されたメタデータをエコーする。
    /// RP はここを読んで「戻り先が登録された」ことを確かめられる。
    #[test]
    fn register_response_echoes_post_logout_redirect_uris() {
        let c = client_with_post_logout(&["https://rp.example.com/"]);
        let resp = register_response(&c, None);
        assert_eq!(
            resp["post_logout_redirect_uris"],
            serde_json::json!(["https://rp.example.com/"])
        );
        assert_eq!(
            resp["redirect_uris"],
            serde_json::json!(["https://rp.example.com/cb"])
        );
        // 戻り先が無い client では空配列（項目自体は在る）。
        let empty = register_response(&client_with_post_logout(&[]), None);
        assert_eq!(empty["post_logout_redirect_uris"], serde_json::json!([]));
    }

    #[test]
    fn initiate_login_uri_is_read_from_the_request_and_echoed() {
        let req = registration_request_from_json(&serde_json::json!({
            "redirect_uris": ["https://rp.example.com/cb"],
            "initiate_login_uri": "https://rp.example.com/auth/login",
        }));
        assert_eq!(
            req.initiate_login_uri.as_deref(),
            Some("https://rp.example.com/auth/login")
        );
        let mut c = client_with_post_logout(&[]);
        assert!(
            register_response(&c, None)
                .get("initiate_login_uri")
                .is_none()
        );
        c.initiate_login_uri = req.initiate_login_uri;
        assert_eq!(
            register_response(&c, None)["initiate_login_uri"],
            "https://rp.example.com/auth/login"
        );
        // 空文字は省略と同じ（管理画面で空にすると外れるのと揃える）。
        let empty =
            registration_request_from_json(&serde_json::json!({ "initiate_login_uri": "" }));
        assert!(empty.initiate_login_uri.is_none());
    }

    /// discovery で発行する独自エンドポイント＝アプリ(fido2demo)が読むキー/パスの契約。
    /// route を改名したらここも一致させる（clean-cut 運用での divergence を検出する）。
    #[test]
    fn custom_endpoints_contract() {
        let v = custom_endpoints("https://op.example/oidc");
        assert_eq!(
            v["signup_email_challenge"],
            "https://op.example/oidc/signup/email-challenge"
        );
        assert_eq!(
            v["signup_verify_email"],
            "https://op.example/oidc/signup/verify-email"
        );
        assert_eq!(
            v["signup_passkey_options"],
            "https://op.example/oidc/signup/passkey/options"
        );
        assert_eq!(
            v["signup_passkey_verify"],
            "https://op.example/oidc/signup/passkey/verify"
        );
        assert_eq!(v["profile"], "https://op.example/oidc/me/profile");
        assert_eq!(v["fcm_token"], "https://op.example/oidc/ciba/fcm-tokens");
        assert_eq!(
            v["mandate_consume"],
            "https://op.example/oidc/oauth/mandate/consume"
        );
    }

    #[cfg(feature = "gcp")]
    #[tokio::test]
    async fn a_par_request_uri_yields_a_code_only_once() {
        let (host, _state) = crate::firestore::fake_firestore::spawn().await;
        let fs = Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
        let p = Provider::new("https://op.example").with_firestore(fs.clone());
        let ru = crate::par::create(&*fs, "dcr-x", "response_type=code")
            .await
            .unwrap();
        let req = crate::context::AddressedRequest {
            params: crate::model::AuthParams {
                client_id: Some("dcr-x".into()),
                redirect_uri: Some("https://rp.example.com/cb".into()),
                response_type: Some("code".into()),
                scope: Some("openid".into()),
                state: None,
                nonce: None,
                prompt: None,
                max_age: None,
                response_mode: None,
                code_challenge: None,
                code_challenge_method: None,
                dpop_jkt: None,
                resource: None,
            },
            client: client_with_post_logout(&[]),
            redirect_uri: "https://rp.example.com/cb".into(),
            request_uri: Some(ru.0),
        };
        let location = |r: Response| {
            r.headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        };
        let first = location(issue_code(&p, &req, "acct".into(), None).await);
        let second = location(issue_code(&p, &req, "acct".into(), None).await);
        assert!(first.contains("code="), "{first}");
        assert!(
            !second.contains("code=") && second.contains("error=invalid_request"),
            "{second}"
        );
    }

    /// PAR の要求は、預けた値だけで進む。フロントチャネルに並べた値（PKCE の challenge、scope）で上書きできない。
    /// formal/composition_code_par_pkjwt.spthy の par_integrity が置く前提（P-PARSTORED）。
    #[cfg(feature = "gcp")]
    #[tokio::test]
    async fn a_par_request_proceeds_with_the_pushed_values_only() {
        let (host, _state) = crate::firestore::fake_firestore::spawn().await;
        let fs = Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
        let p = Arc::new(
            Provider::new("https://op.example")
                .with_firestore(fs.clone())
                .with_client(client_with_post_logout(&[])),
        );
        let pushed = "client_id=dcr-x&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb&response_type=code\
                      &scope=openid&code_challenge=PUSHED&code_challenge_method=S256";
        let ru = crate::par::create(&*fs, "dcr-x", pushed).await.unwrap();
        let q = serde_urlencoded::to_string([
            ("client_id", "dcr-x"),
            ("request_uri", ru.0.as_str()),
            ("scope", "openid admin"),
            ("code_challenge", "FRONT"),
        ])
        .unwrap();
        let r = authorize(
            State(p.clone()),
            HeaderMap::new(),
            CookieJar::default(),
            RawQuery(Some(q)),
        )
        .await;
        let location = r.headers().get(header::LOCATION).unwrap().to_str().unwrap();
        let uid = location
            .split("/login/")
            .nth(1)
            .and_then(|s| s.split('?').next())
            .unwrap_or_else(|| panic!("{location}"));
        let i = p.store.get_interaction(uid).await.unwrap();
        assert_eq!(i.raw_query, pushed);
        assert_eq!(i.request_uri.as_deref(), Some(ru.0.as_str()));
    }

    /// /par で使った client_assertion は、token endpoint で使い直せない（jti の記録は口をまたいで 1 つ）。
    /// formal/composition_code_par_pkjwt.spthy が置く前提（P-AJTI）。
    #[cfg(feature = "gcp")]
    #[tokio::test]
    async fn a_client_assertion_used_at_par_is_refused_at_the_token_endpoint() {
        use crate::client_auth::tests::{ISS, assertion, good_claims, pkjwt_client};
        use p256::elliptic_curve::Generate;
        let (host, _state) = crate::firestore::fake_firestore::spawn().await;
        let fs = Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
        let key = p256::ecdsa::SigningKey::generate();
        let p = Arc::new(
            Provider::new(ISS)
                .with_firestore(fs.clone())
                .with_client(pkjwt_client("rp", &key, "k1")),
        );
        let a = assertion(&key, "k1", "ES256", good_claims("rp", "once"));
        let auth = [
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", a.as_str()),
        ];
        let mut par_body = vec![("client_id", "rp"), ("response_type", "code")];
        par_body.extend(auth);
        let r = par(
            State(p.clone()),
            HeaderMap::new(),
            serde_urlencoded::to_string(&par_body).unwrap(),
        )
        .await;
        assert_eq!(r.status(), StatusCode::CREATED);
        let mut token_form: HashMap<String, String> = [
            ("grant_type", "authorization_code"),
            ("code", "unused"),
            ("client_id", "rp"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        token_form.extend(auth.map(|(k, v)| (k.to_string(), v.to_string())));
        let r = token(State(p.clone()), HeaderMap::new(), Form(token_form)).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    /// /par は client の資格情報を、預かる要求に残さない（authorize の raw_query にも写らない）。
    #[cfg(feature = "gcp")]
    #[tokio::test]
    async fn par_does_not_store_the_client_assertion() {
        use crate::client_auth::tests::{ISS, assertion, good_claims, pkjwt_client};
        use p256::elliptic_curve::Generate;
        let (host, _state) = crate::firestore::fake_firestore::spawn().await;
        let fs = Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
        let key = p256::ecdsa::SigningKey::generate();
        let p = Arc::new(
            Provider::new(ISS)
                .with_firestore(fs.clone())
                .with_client(pkjwt_client("rp", &key, "k1")),
        );
        let a = assertion(&key, "k1", "ES256", good_claims("rp", "stored"));
        let body = serde_urlencoded::to_string([
            ("client_id", "rp"),
            ("response_type", "code"),
            ("scope", "openid profile"),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", a.as_str()),
        ])
        .unwrap();
        let r = par(State(p.clone()), HeaderMap::new(), body).await;
        assert_eq!(r.status(), StatusCode::CREATED);
        let v: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let ru = v["request_uri"].as_str().unwrap();
        let (_, stored) = crate::par::peek(&*fs, ru).await.unwrap().unwrap();
        let stored: HashMap<String, String> = serde_urlencoded::from_str(&stored).unwrap();
        assert!(!stored.contains_key("client_assertion"), "{stored:?}");
        assert!(!stored.contains_key("client_assertion_type"), "{stored:?}");
        assert_eq!(
            stored.get("scope").map(String::as_str),
            Some("openid profile")
        );
        assert_eq!(stored.get("client_id").map(String::as_str), Some("rp"));
    }

    /// フロントチャネルが client_id を省いても、預けた値が別の client を名指していれば断る。
    /// formal/composition_code_par_pkjwt.spthy が置く前提（P-PARBIND）。
    #[cfg(feature = "gcp")]
    #[tokio::test]
    async fn a_request_uri_naming_another_client_is_refused_without_a_front_client_id() {
        let (host, _state) = crate::firestore::fake_firestore::spawn().await;
        let fs = Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
        let p = Arc::new(
            Provider::new("https://op.example")
                .with_firestore(fs.clone())
                .with_client(client_with_post_logout(&[])),
        );
        let pushed = "client_id=dcr-x&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb&response_type=code\
                      &scope=openid&code_challenge=PUSHED&code_challenge_method=S256";
        let ru = crate::par::create(&*fs, "dcr-attacker", pushed)
            .await
            .unwrap();
        let q = serde_urlencoded::to_string([("request_uri", ru.0.as_str())]).unwrap();
        let r = authorize(
            State(p.clone()),
            HeaderMap::new(),
            CookieJar::default(),
            RawQuery(Some(q)),
        )
        .await;
        assert!(r.headers().get(header::LOCATION).is_none());
        let body = String::from_utf8(
            axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("invalid_request_uri"), "{body}");
    }

    /// require_par の client は、request_uri を経ない要求で先へ進めない（PAR を外した要求に code を出さない）。
    /// formal/composition_code_par_pkjwt.spthy が置く前提（P-REQUIREPAR）。
    #[tokio::test]
    async fn a_client_that_requires_par_is_refused_without_a_pushed_request() {
        let c = crate::model::Client {
            require_par: true,
            ..client_with_post_logout(&[])
        };
        let p = Arc::new(Provider::new("https://op.example").with_client(c));
        let q = serde_urlencoded::to_string([
            ("client_id", "dcr-x"),
            ("redirect_uri", "https://rp.example.com/cb"),
            ("response_type", "code"),
            ("scope", "openid"),
            (
                "code_challenge",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            ),
            ("code_challenge_method", "S256"),
        ])
        .unwrap();
        let r = authorize(
            State(p),
            HeaderMap::new(),
            CookieJar::default(),
            RawQuery(Some(q)),
        )
        .await;
        let location = r.headers().get(header::LOCATION).unwrap().to_str().unwrap();
        assert!(
            location.starts_with("https://rp.example.com/cb?")
                && location.contains("error=invalid_request")
                && !location.contains("code="),
            "{location}"
        );
    }

    /// A2: ログインで UV を求めていないので、満たせる acr を名乗らない。
    #[tokio::test]
    async fn discovery_does_not_advertise_acr_values() {
        let p = Arc::new(Provider::new("https://op.example"));
        let Json(d) = discovery(State(p)).await;
        assert!(d.get("acr_values_supported").is_none(), "{d}");
    }

    /// 失効できなかったのに 200 を返すと、RP はトークンが死んだと思い込む。503 で試し直させる。
    #[cfg(feature = "gcp")]
    #[tokio::test]
    async fn revoke_answers_503_when_the_token_could_not_be_removed() {
        let (host, state) = crate::firestore::fake_firestore::spawn().await;
        let fs = Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
        let store = Arc::new(crate::firestore_store::FirestoreStore::new(fs));
        let public = crate::model::Client {
            client_id: "rp".into(),
            token_endpoint_auth_method: "none".into(),
            client_secret: None,
            ..client_with_post_logout(&[])
        };
        let p = Arc::new(
            Provider::new("https://op.example")
                .with_store(store)
                .with_client(public),
        );
        p.store.save_access_token(at(None)).await.unwrap();
        let form = || {
            Form(HashMap::from([
                ("client_id".to_string(), "rp".to_string()),
                ("token".to_string(), "AT".to_string()),
            ]))
        };

        state.fail_once("DELETE", "accessTokens", Some("AT"));
        let r = revoke(State(p.clone()), HeaderMap::new(), form()).await;
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            p.store.get_access_token("AT").await.unwrap().is_some(),
            "消せていない"
        );

        let r = revoke(State(p.clone()), HeaderMap::new(), form()).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert!(p.store.get_access_token("AT").await.unwrap().is_none());
    }

    /// RFC 7009 §2.1: ほかの client の token を渡されても消さない（200 は返す）。持ち主は消せる。
    #[tokio::test]
    async fn revoke_does_not_remove_another_clients_tokens() {
        let public = |id: &str| crate::model::Client {
            client_id: id.into(),
            token_endpoint_auth_method: "none".into(),
            client_secret: None,
            ..client_with_post_logout(&[])
        };
        let p = Arc::new(
            Provider::new("https://op.example")
                .with_client(public("rp-a"))
                .with_client(public("rp-b")),
        );
        p.store
            .save_access_token(AccessToken {
                client_id: "rp-b".into(),
                ..at(None)
            })
            .await
            .unwrap();
        p.store
            .save_refresh_token(crate::model::RefreshToken {
                token: "RT".into(),
                client_id: "rp-b".into(),
                account_id: "user@example.com".into(),
                scope: "openid offline_access".into(),
                resource: None,
                jkt: None,
                acr: None,
                auth_time: None,
                family_id: "F".into(),
                used: false,
                replaced_by: None,
            })
            .await
            .unwrap();
        let form = |client: &str, token: &str| {
            Form(HashMap::from([
                ("client_id".to_string(), client.to_string()),
                ("token".to_string(), token.to_string()),
            ]))
        };

        for token in ["AT", "RT"] {
            let r = revoke(State(p.clone()), HeaderMap::new(), form("rp-a", token)).await;
            assert_eq!(r.status(), StatusCode::OK);
        }
        assert!(
            p.store.get_access_token("AT").await.unwrap().is_some(),
            "ほかの client が AT を消した"
        );
        assert!(
            p.store.get_refresh_token("RT").await.unwrap().is_some(),
            "ほかの client が RT を消した"
        );

        for token in ["AT", "RT"] {
            let r = revoke(State(p.clone()), HeaderMap::new(), form("rp-b", token)).await;
            assert_eq!(r.status(), StatusCode::OK);
        }
        assert!(p.store.get_access_token("AT").await.unwrap().is_none());
        assert!(p.store.get_refresh_token("RT").await.unwrap().is_none());
    }

    /// 期限を過ぎた access token は、fake の Firestore に文書が残っていても introspect で active=false。
    #[cfg(feature = "gcp")]
    #[tokio::test]
    async fn an_expired_access_token_is_inactive_on_firestore() {
        let (host, _state) = crate::firestore::fake_firestore::spawn().await;
        let fs = Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
        let store = Arc::new(crate::firestore_store::FirestoreStore::new(fs.clone()));
        let rp = crate::model::Client {
            client_id: "rp".into(),
            ..client_with_post_logout(&[])
        };
        let rp = crate::model::Client {
            client_secret: Some(crate::dcr::hash_token("s3cret")),
            ..rp
        };
        let p = Arc::new(
            Provider::new("https://op.example")
                .with_store(store)
                .with_client(rp),
        );
        p.store.save_access_token(at(None)).await.unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {}", B64.encode("rp:s3cret"))
                .parse()
                .unwrap(),
        );
        let active = |p: Arc<Provider>, h: HeaderMap| async move {
            let r = introspect(
                State(p),
                h,
                Form(HashMap::from([("token".to_string(), "AT".to_string())])),
            )
            .await;
            let v: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(r.into_body(), usize::MAX)
                    .await
                    .unwrap(),
            )
            .unwrap();
            v["active"].clone()
        };

        assert_eq!(active(p.clone(), h.clone()).await, true);
        let past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 60;
        fs.merge_doc("accessTokens", "AT", serde_json::json!({ "expiresAt": crate::firestore::ts(&crate::firestore::rfc3339(past)) }))
            .await
            .unwrap();
        assert!(
            fs.get_doc("accessTokens", "AT").await.unwrap().is_some(),
            "文書は残っている前提"
        );
        assert!(p.store.get_access_token("AT").await.unwrap().is_none());
        assert_eq!(active(p.clone(), h).await, false);
    }

    #[cfg(feature = "gcp")]
    #[tokio::test]
    async fn profile_put_refuses_the_values_the_registration_page_refuses() {
        let (host, _state) = crate::firestore::fake_firestore::spawn().await;
        let fs = Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
        let p = Arc::new(Provider::new("https://op.example").with_firestore(fs.clone()));
        p.store.save_access_token(at(None)).await.unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer AT".parse().unwrap());
        let put = |body: serde_json::Value| {
            profile_put(State(p.clone()), headers.clone(), body.to_string())
        };

        assert_eq!(
            put(serde_json::json!({ "name": "山田 太郎" }))
                .await
                .status(),
            StatusCode::OK
        );
        for bad in ["\u{202E}evil", "a\nb", &"x".repeat(81)] {
            let resp = put(serde_json::json!({ "name": bad })).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad:?}");
        }
        let saved = crate::registration::get_profile(&*fs, "user@example.com")
            .await
            .unwrap();
        assert_eq!(saved.get("name").map(String::as_str), Some("山田 太郎"));
    }

    fn at(jkt: Option<&str>) -> AccessToken {
        AccessToken {
            token: "AT".into(),
            client_id: "rp".into(),
            account_id: "user@example.com".into(),
            scope: "openid profile".into(),
            jkt: jkt.map(str::to_string),
            aud: None,
            acr: None,
            auth_time: None,
            authorization_details: None,
            mandate_consumed: false,
        }
    }

    fn client(method: &str) -> crate::model::Client {
        crate::model::Client {
            client_id: "rs".into(),
            redirect_uris: vec![],
            token_endpoint_auth_method: method.into(),
            client_secret: None,
            grant_types: vec![],
            post_logout_redirect_uris: vec![],
            initiate_login_uri: None,
            dpop_bound: false,
            jwks: vec![],
            jwks_uri: None,
            require_par: false,
            require_pkce: false,
            id_token_signed_response_alg: None,
        }
    }

    #[test]
    fn introspect_requires_confidential_client() {
        // public(none) は拒否、confidential は許可。
        assert!(require_confidential(&client("none")).is_err());
        assert!(require_confidential(&client("client_secret_basic")).is_ok());
        assert!(require_confidential(&client("private_key_jwt")).is_ok());
    }

    /// ほかの RP に出た token は、confidential でも INTROSPECTION_CLIENT_IDS に無い client には
    /// 見せず、mandate も消費させない。token を受けた client 自身と、挙げた RS は引ける。
    #[tokio::test]
    async fn only_the_token_holder_and_listed_resource_servers_may_inspect_a_token() {
        let confidential = |id: &str| crate::model::Client {
            client_id: id.into(),
            client_secret: Some(crate::dcr::hash_token("s3cret")),
            ..client("client_secret_basic")
        };
        let p = Arc::new(
            Provider::new("https://op.example")
                .with_client(confidential("rp"))
                .with_client(confidential("other-rp"))
                .with_client(confidential("rs"))
                .with_introspection_clients(vec!["rs".into()]),
        );
        let mut token = at(None);
        token.authorization_details = Some(r#"[{"type":"payment"}]"#.into());
        p.store.save_access_token(token).await.unwrap();
        let basic = |id: &str| {
            let mut h = HeaderMap::new();
            h.insert(
                header::AUTHORIZATION,
                format!("Basic {}", B64.encode(format!("{id}:s3cret")))
                    .parse()
                    .unwrap(),
            );
            h
        };
        let form = || Form(HashMap::from([("token".to_string(), "AT".to_string())]));
        let json = |r: Response| async move {
            serde_json::from_slice::<serde_json::Value>(
                &axum::body::to_bytes(r.into_body(), usize::MAX)
                    .await
                    .unwrap(),
            )
            .unwrap()
        };

        let other = json(introspect(State(p.clone()), basic("other-rp"), form()).await).await;
        assert_eq!(other, serde_json::json!({ "active": false }));
        let other = json(mandate_consume(State(p.clone()), basic("other-rp"), form()).await).await;
        assert_eq!(other["consumed"], false);
        assert!(
            !p.store
                .get_access_token("AT")
                .await
                .unwrap()
                .unwrap()
                .mandate_consumed
        );

        let own = json(introspect(State(p.clone()), basic("rp"), form()).await).await;
        assert_eq!(own["active"], true);
        let rs = json(introspect(State(p.clone()), basic("rs"), form()).await).await;
        assert_eq!(rs["active"], true);
        assert_eq!(rs["sub"], "user@example.com");
        let rs = json(mandate_consume(State(p.clone()), basic("rs"), form()).await).await;
        assert_eq!(rs["consumed"], true);
    }

    /// mandate を消費できるのは、token を受けた client 自身か、挙げた RS で、どちらも資格情報で認証できること。
    /// 持ち主は 1 度だけ消費でき、資格情報を出さない呼び手（public の持ち主を含む）は消費できない。
    #[tokio::test]
    async fn the_token_holder_consumes_its_mandate_once_and_a_caller_without_credentials_cannot() {
        let p = Arc::new(
            Provider::new("https://op.example")
                .with_client(crate::model::Client {
                    client_id: "rp".into(),
                    client_secret: Some(crate::dcr::hash_token("s3cret")),
                    ..client("client_secret_basic")
                })
                .with_client(crate::model::Client {
                    client_id: "pub-rp".into(),
                    ..client("none")
                }),
        );
        let mut public_token = at(None);
        public_token.token = "AT-PUB".into();
        public_token.client_id = "pub-rp".into();
        p.store.save_access_token(public_token).await.unwrap();
        p.store.save_access_token(at(None)).await.unwrap();
        let consume = |headers: HeaderMap, form: &[(&str, &str)]| {
            let form = Form(
                form.iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect::<HashMap<_, _>>(),
            );
            mandate_consume(State(p.clone()), headers, form)
        };
        let consumed = |token: &'static str| {
            let p = p.clone();
            async move {
                p.store
                    .get_access_token(token)
                    .await
                    .unwrap()
                    .unwrap()
                    .mandate_consumed
            }
        };

        let public = consume(
            HeaderMap::new(),
            &[("token", "AT-PUB"), ("client_id", "pub-rp")],
        )
        .await;
        assert_eq!(public.status(), StatusCode::UNAUTHORIZED);
        assert!(!consumed("AT-PUB").await, "public の持ち主が消費できた");
        let anonymous = consume(HeaderMap::new(), &[("token", "AT")]).await;
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
        assert!(!consumed("AT").await, "認証の無い呼び手が消費できた");

        let mut holder = HeaderMap::new();
        holder.insert(
            header::AUTHORIZATION,
            format!("Basic {}", B64.encode("rp:s3cret"))
                .parse()
                .unwrap(),
        );
        let body = |r: Response| async move {
            serde_json::from_slice::<serde_json::Value>(
                &axum::body::to_bytes(r.into_body(), usize::MAX)
                    .await
                    .unwrap(),
            )
            .unwrap()
        };
        assert_eq!(
            body(consume(holder.clone(), &[("token", "AT")]).await).await["consumed"],
            true
        );
        assert!(consumed("AT").await);
        assert_eq!(
            body(consume(holder, &[("token", "AT")]).await).await["consumed"],
            false,
            "2 度目も消費できた"
        );
    }

    /// 資格情報で認証できる confidential client でも、token を受けた client でも挙げた RS でもなければ、mandate を消費できない。
    #[tokio::test]
    async fn another_confidential_client_cannot_consume_a_mandate_it_was_not_given() {
        let p = Arc::new(
            Provider::new("https://op.example")
                .with_client(crate::model::Client {
                    client_id: "rp".into(),
                    client_secret: Some(crate::dcr::hash_token("s3cret")),
                    ..client("client_secret_basic")
                })
                .with_client(crate::model::Client {
                    client_id: "other-rp".into(),
                    client_secret: Some(crate::dcr::hash_token("0ther")),
                    ..client("client_secret_basic")
                }),
        );
        p.store.save_access_token(at(None)).await.unwrap();
        let mut other = HeaderMap::new();
        other.insert(
            header::AUTHORIZATION,
            format!("Basic {}", B64.encode("other-rp:0ther"))
                .parse()
                .unwrap(),
        );
        let form = Form(HashMap::from([("token".to_string(), "AT".to_string())]));
        let r = mandate_consume(State(p.clone()), other, form).await;
        assert_eq!(r.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["consumed"], false, "ほかの client が消費できた");
        let at = p.store.get_access_token("AT").await.unwrap().unwrap();
        assert!(
            !at.mandate_consumed,
            "ほかの client の呼び出しで消費済みになった"
        );
    }

    async fn token_error(
        p: &Arc<Provider>,
        headers: HeaderMap,
        form: &[(&str, &str)],
    ) -> (StatusCode, serde_json::Value) {
        let form = Form(
            form.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        );
        let r = token(State(p.clone()), headers, form).await;
        let status = r.status();
        let body = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    fn basic_header(id: &str, secret: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {}", B64.encode(format!("{id}:{secret}")))
                .parse()
                .unwrap(),
        );
        h
    }

    /// token の口は、認証できた client でも、その client に許していない grant_type を断る。
    /// 許した grant_type は門を越え、grant の側の検査（ここでは未知の code）で落ちる。
    #[tokio::test]
    async fn the_token_endpoint_refuses_a_grant_type_the_client_was_not_given() {
        let p = Arc::new(
            Provider::new("https://op.example").with_client(crate::model::Client {
                client_id: "rp".into(),
                client_secret: Some(crate::dcr::hash_token("s3cret")),
                grant_types: vec!["authorization_code".into()],
                ..client("client_secret_basic")
            }),
        );
        let (status, body) = token_error(
            &p,
            basic_header("rp", "s3cret"),
            &[("grant_type", "refresh_token"), ("refresh_token", "RT")],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "unauthorized_client", "{body}");

        let (_, body) = token_error(
            &p,
            basic_header("rp", "s3cret"),
            &[
                ("grant_type", "authorization_code"),
                ("code", "UNKNOWN"),
                ("redirect_uri", "https://rp.example/cb"),
            ],
        )
        .await;
        assert_ne!(
            body["error"], "unauthorized_client",
            "許した grant_type まで断った: {body}"
        );
    }

    /// private_key_jwt で登録した client（DCR と同じく secret を持たない）は、client_secret_basic では通らない。
    #[tokio::test]
    async fn a_private_key_jwt_client_is_refused_with_client_secret_basic() {
        let p = Arc::new(
            Provider::new("https://op.example").with_client(crate::model::Client {
                client_id: "pk-rp".into(),
                grant_types: vec!["authorization_code".into()],
                ..client("private_key_jwt")
            }),
        );
        for secret in ["", "s3cret"] {
            let (status, body) = token_error(
                &p,
                basic_header("pk-rp", secret),
                &[
                    ("grant_type", "authorization_code"),
                    ("code", "C"),
                    ("redirect_uri", "https://rp.example/cb"),
                ],
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{secret:?}: {body}");
            assert_eq!(body["error"], "invalid_client");
        }
    }

    /// private_key_jwt で登録した client が secret を持っていても、secret だけでは通さない。
    #[tokio::test]
    async fn a_private_key_jwt_client_with_a_stored_secret_is_still_refused_with_client_secret_basic()
     {
        let p = Arc::new(
            Provider::new("https://op.example").with_client(crate::model::Client {
                client_id: "pk-rp".into(),
                client_secret: Some(crate::dcr::hash_token("s3cret")),
                grant_types: vec!["authorization_code".into()],
                ..client("private_key_jwt")
            }),
        );
        let (status, body) = token_error(
            &p,
            basic_header("pk-rp", "s3cret"),
            &[
                ("grant_type", "authorization_code"),
                ("code", "C"),
                ("redirect_uri", "https://rp.example/cb"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"], "invalid_client");
    }

    /// client 認証を取るほかの口（introspect・revoke・mandate の消費）も、登録と違う方式を断る。
    #[tokio::test]
    async fn introspect_revoke_and_mandate_consume_refuse_a_method_other_than_the_registered_one() {
        let p = Arc::new(
            Provider::new("https://op.example").with_client(crate::model::Client {
                client_id: "rs".into(),
                client_secret: Some(crate::dcr::hash_token("s3cret")),
                ..client("private_key_jwt")
            }),
        );
        p.store
            .save_access_token(AccessToken {
                client_id: "rs".into(),
                ..at(None)
            })
            .await
            .unwrap();
        let form = || Form(HashMap::from([("token".to_string(), "AT".to_string())]));
        let h = || basic_header("rs", "s3cret");

        assert_eq!(
            introspect(State(p.clone()), h(), form()).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            mandate_consume(State(p.clone()), h(), form())
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            revoke(State(p.clone()), h(), form()).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(
            p.store.get_access_token("AT").await.unwrap().is_some(),
            "断ったはずの revoke が token を消した"
        );
    }

    /// client_secret_basic で登録した client は、署名の正しい private_key_jwt の assertion で来ても断る。
    #[tokio::test]
    async fn a_client_secret_basic_client_is_refused_with_a_private_key_jwt_assertion() {
        use p256::ecdsa::signature::Signer;
        use p256::elliptic_curve::Generate;
        let key = p256::ecdsa::SigningKey::generate();
        let pt = key.verifying_key().to_sec1_point(false);
        let b64 = |b: &[u8]| crate::es256::b64url_encode(b);
        let p = Arc::new(
            Provider::new("https://op.example").with_client(crate::model::Client {
                client_id: "rp".into(),
                client_secret: Some(crate::dcr::hash_token("s3cret")),
                grant_types: vec!["authorization_code".into()],
                jwks: vec![crate::model::JwkPub {
                    kid: "k1".into(),
                    x: b64(pt.x().unwrap()),
                    y: b64(pt.y().unwrap()),
                }],
                ..client("client_secret_basic")
            }),
        );
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        let header =
            b64(&serde_json::to_vec(&serde_json::json!({ "alg": "ES256", "kid": "k1" })).unwrap());
        let claims = serde_json::json!({ "iss": "rp", "sub": "rp", "aud": "https://op.example", "exp": exp, "jti": "j1" });
        let signing_input = format!("{header}.{}", b64(&serde_json::to_vec(&claims).unwrap()));
        let sig: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
        let assertion = format!("{signing_input}.{}", b64(&sig.to_bytes()));

        let (status, body) = token_error(
            &p,
            HeaderMap::new(),
            &[
                ("grant_type", "authorization_code"),
                ("code", "C"),
                ("redirect_uri", "https://rp.example/cb"),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", &assertion),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"], "invalid_client");
    }

    #[test]
    fn introspection_dpop_token_includes_cnf_jkt() {
        let b = introspection_active_body(&at(Some("JKT123")));
        assert_eq!(b["active"], true);
        assert_eq!(b["token_type"], "DPoP");
        assert_eq!(b["sub"], "user@example.com");
        assert_eq!(b["scope"], "openid profile");
        assert_eq!(b["client_id"], "rp");
        assert_eq!(b["cnf"]["jkt"], "JKT123");
    }

    #[test]
    fn introspection_bearer_token_has_no_cnf() {
        let b = introspection_active_body(&at(None));
        assert_eq!(b["active"], true);
        assert_eq!(b["token_type"], "Bearer");
        assert!(b.get("cnf").is_none());
    }

    #[test]
    fn introspection_includes_aud_when_resource_bound() {
        let mut a = at(None);
        a.aud = Some("https://api.example.com".into());
        let b = introspection_active_body(&a);
        assert_eq!(b["aud"], "https://api.example.com");
    }

    #[test]
    fn introspection_exposes_acr_and_auth_time_for_step_up() {
        let mut a = at(None);
        a.acr = Some("urn:acr:bronze".into());
        a.auth_time = Some(1_700_000_000);
        let b = introspection_active_body(&a);
        assert_eq!(b["acr"], "urn:acr:bronze");
        assert_eq!(b["auth_time"], 1_700_000_000u64);
    }

    #[test]
    fn valid_resource_requires_absolute_uri_without_fragment() {
        assert!(valid_resource("https://api.example.com"));
        assert!(valid_resource("https://api.example.com/v1"));
        assert!(!valid_resource("api.example.com")); // scheme なし
        assert!(!valid_resource("https://api.example.com/#x")); // fragment 不可
        assert!(!valid_resource("://x")); // scheme 空
    }
}
