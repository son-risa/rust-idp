//! 人に見せる全ページと文言を、ブラウザの言語ごとに描いて確かめる。
//! 英語（en・対応外の fr・ヘッダ無し）には日本語の文字が 1 つも無く `lang="en"`、
//! 日本語（ja）には `lang="ja"` と今までの日本語の見出しが出ること。

use super::*;
use crate::firestore::fake_firestore;
use crate::firestore::Firestore;
use crate::web::i18n::has_japanese;
use std::future::Future;

const ENGLISH: [Option<&str>; 3] = [Some("en"), Some("fr"), None];

fn accept(lang: Option<&str>) -> HeaderMap {
    let mut h = HeaderMap::new();
    if let Some(l) = lang {
        h.insert(header::ACCEPT_LANGUAGE, l.parse().unwrap());
    }
    h
}

async fn body_of(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn japanese_in(s: &str) -> Vec<&str> {
    s.lines().filter(|l| has_japanese(l)).collect()
}

/// HTML のページ。`ja_heading` は日本語で描いたときに出るはずの今までの見出し。
async fn check_page<F, Fut>(name: &str, ja_heading: &str, render: F)
where
    F: Fn(HeaderMap) -> Fut,
    Fut: Future<Output = String>,
{
    for lang in ENGLISH {
        let html = render(accept(lang)).await;
        assert!(
            html.contains("<html lang=\"en\">"),
            "{name} [{lang:?}]: lang=\"en\" が無い"
        );
        assert!(
            japanese_in(&html).is_empty(),
            "{name} [{lang:?}] に日本語: {:?}",
            japanese_in(&html)
        );
        assert!(
            !html.contains("[["),
            "{name} [{lang:?}]: 訳されずに残った印"
        );
    }
    let html = render(accept(Some("ja"))).await;
    assert!(
        html.contains("<html lang=\"ja\">"),
        "{name} [ja]: lang=\"ja\" が無い"
    );
    assert!(
        html.contains(ja_heading),
        "{name} [ja]: 「{ja_heading}」が無い"
    );
    assert!(!html.contains("[["), "{name} [ja]: 訳されずに残った印");
    let english = english_words_shown(&html);
    assert!(
        english.is_empty(),
        "{name} [ja] に訳されていない英語: {english:?}"
    );
}

/// 日本語の画面にそのまま出ても構わない英字の語。固有名と仕様の用語（値として出る none・openid・true・false と、
/// 日本語化の前から使っている redirect host を含む）、
/// client のプロファイル名（Public・Confidential Secret・Confidential Key）、
/// それと管理画面のボタンに添えている操作名（「凍結（disable）」など、日本語化の前からの表記）。
const JA_ALLOWED_WORDS: &[&str] = &[
    "passkey",
    "Passkey",
    "IAT",
    "client",
    "CIBA",
    "Web",
    "iCloud",
    "Keychain",
    "scope",
    "openid",
    "none",
    "Public",
    "Confidential",
    "Secret",
    "Key",
    "true",
    "false",
    "jwks",
    "kids",
    "redirect",
    "host",
    "delete",
    "enable",
    "disable",
];

/// 画面に見える文字（タグの外の文字と placeholder・title・aria-label）のうち、英字だけでできた語。
/// メールアドレスや ID のように記号や数字を含む語はデータなので数えない。script と style の中は見ない。
fn english_words_shown(html: &str) -> Vec<String> {
    let mut shown = String::new();
    let mut rest = html;
    while let Some(lt) = rest.find('<') {
        shown.push_str(&rest[..lt]);
        shown.push(' ');
        let tag_end = rest[lt..].find('>').map_or(rest.len(), |i| lt + i + 1);
        let tag = &rest[lt..tag_end];
        for attr in ["placeholder=\"", "title=\"", "aria-label=\""] {
            if let Some(i) = tag.find(attr) {
                let v = &tag[i + attr.len()..];
                shown.push_str(&v[..v.find('"').unwrap_or(v.len())]);
                shown.push(' ');
            }
        }
        rest = &rest[tag_end..];
        for raw in ["script", "style"] {
            if tag.starts_with(&format!("<{raw}")) {
                let close = format!("</{raw}>");
                rest = rest.find(&close).map_or("", |i| &rest[i + close.len()..]);
            }
        }
    }
    shown.push_str(rest);
    shown
        .split(|c: char| c.is_whitespace() || !c.is_ascii())
        .map(|w| w.trim_matches(|c: char| ",.:;!?()（）\"'".contains(c)))
        .filter(|w| w.len() >= 2 && w.chars().all(|c| c.is_ascii_alphabetic()))
        .filter(|w| !JA_ALLOWED_WORDS.contains(w))
        .map(str::to_string)
        .collect()
}

/// ブラウザにそのまま出る素の文言。
async fn check_text<F, Fut>(name: &str, ja_text: &str, render: F)
where
    F: Fn(HeaderMap) -> Fut,
    Fut: Future<Output = String>,
{
    for lang in ENGLISH {
        let text = render(accept(lang)).await;
        assert!(
            !text.is_empty() && !has_japanese(&text),
            "{name} [{lang:?}] に日本語: {text}"
        );
        assert!(
            !text.contains("[["),
            "{name} [{lang:?}]: 訳されずに残った印"
        );
    }
    let text = render(accept(Some("ja"))).await;
    assert!(
        text.contains(ja_text),
        "{name} [ja]: 「{ja_text}」が無い: {text}"
    );
}

fn plain() -> Arc<Provider> {
    Arc::new(Provider::new("https://idp.example/oidc".to_string()))
}

async fn with_firestore() -> (Arc<Provider>, Arc<Firestore>) {
    let (host, _state) = fake_firestore::spawn().await;
    let fs = Arc::new(Firestore::new_for_test("proj", host));
    let p = Provider::new("https://idp.example".to_string())
        .with_firestore(fs.clone())
        .with_store(Arc::new(crate::firestore_store::FirestoreStore::new(
            fs.clone(),
        )));
    (Arc::new(p), fs)
}

async fn login_as(p: &Provider, account_id: &str) -> CookieJar {
    let sid = Uuid::new_v4().to_string();
    p.store
        .save_session(Session {
            sid: sid.clone(),
            account_id: account_id.to_string(),
            auth_time: 0,
        })
        .await;
    CookieJar::default().add(Cookie::new(SID_COOKIE, sid))
}

async fn register(fs: &Firestore, email: &str, account_id: &str) {
    let outcome = crate::webauthn::RegOutcome {
        credential_id: format!("cred-{account_id}"),
        pub_x: "x".into(),
        pub_y: "y".into(),
        sign_count: 0,
    };
    crate::registration::save_credential(fs, email, account_id, &outcome)
        .await
        .unwrap();
}

fn client(id: &str) -> crate::model::Client {
    crate::model::Client {
        client_id: id.into(),
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        post_logout_redirect_uris: vec![],
        token_endpoint_auth_method: "none".into(),
        client_secret: None,
        grant_types: vec!["authorization_code".into()],
        dpop_bound: true,
        jwks: vec![],
        jwks_uri: None,
        require_par: false,
        require_pkce: true,
        id_token_signed_response_alg: None,
    }
}

/// 管理者 me、一般利用者 u（凍結）、管理者 boss（凍結）、一般利用者 active を持つ Firestore。
async fn admin_world() -> (Arc<Provider>, Arc<Firestore>) {
    let (p, fs) = with_firestore().await;
    register(&fs, "me@example.com", "acc-me").await;
    register(&fs, "u@example.com", "acc-u").await;
    register(&fs, "boss@example.com", "acc-boss").await;
    register(&fs, "active@example.com", "acc-active").await;
    crate::admin_store::grant_admin(&fs, "acc-me", "cli")
        .await
        .unwrap();
    crate::admin_store::grant_admin(&fs, "acc-boss", "cli")
        .await
        .unwrap();
    crate::account_admin::disable_account(&fs, "acc-me", "u@example.com")
        .await
        .unwrap();
    crate::account_admin::disable_account(&fs, "acc-me", "boss@example.com")
        .await
        .unwrap();
    (p, fs)
}

#[tokio::test]
async fn sign_in_and_demo_pages_follow_the_browser_language() {
    check_page("login", "Passkey でサインイン", |h| async move {
        login::login_form(State(plain()), h, Path("uid-1".into()))
            .await
            .0
    })
    .await;
    check_page("demo_start", "Passkey でサインイン", |h| async move {
        pages::demo_start(State(plain()), h).await.0
    })
    .await;
    check_page("demo_callback", "サインイン処理中…", |h| async move {
        pages::demo_callback(State(plain()), h).await.0
    })
    .await;
    check_page("logged out", "ログアウトしました", |h| async move {
        let q: oidc::EndSessionQuery = serde_urlencoded::from_str("").unwrap();
        body_of(oidc::end_session(State(plain()), h, CookieJar::default(), Query(q)).await).await
    })
    .await;
}

#[tokio::test]
async fn the_profile_page_keeps_its_japanese_labels_in_japanese() {
    let html = pages::demo_callback(State(plain()), accept(Some("ja")))
        .await
        .0;
    for ja in [
        "'<h1>プロフィール</h1>",
        "{male:'男性'",
        "field('氏名',p.name)",
        "承認（passkey）",
        "'セッションが切れました。再度サインインしてください。'",
    ] {
        assert!(html.contains(ja), "{ja}");
    }
    let en = pages::demo_callback(State(plain()), accept(Some("en-US")))
        .await
        .0;
    for text in [
        "'<h1>Profile</h1>",
        "{male:'Male'",
        "field('Name',p.name)",
        "Approve (passkey)",
    ] {
        assert!(en.contains(text), "{text}");
    }
}

#[tokio::test]
async fn registration_pages_follow_the_browser_language() {
    check_page("signup form", "ユーザー登録", |h| async move {
        register::register_form(State(plain()), h).await.0
    })
    .await;
    check_page("signup sent", "確認メールを送信しました", |h| async move {
        let (p, _fs) = with_firestore().await;
        let form = Form(serde_urlencoded::from_str("email=new%40example.com").unwrap());
        body_of(register::register_submit(State(p), h, form).await).await
    })
    .await;
    check_page(
        "passkey registration (mail link)",
        "passkey を作成",
        |h| async move {
            let q = serde_urlencoded::from_str("t=abc").unwrap();
            register::magic_redirect(State(plain()), h, Query(q))
                .await
                .0
        },
    )
    .await;
    check_page(
        "passkey registration (web form)",
        "passkey を作成",
        |h| async move {
            let q = serde_urlencoded::from_str("token=abc").unwrap();
            register::verify_form(State(plain()), h, Query(q)).await.0
        },
    )
    .await;
    check_page("invite expired", "この招待は使えません", |h| async move {
        let (p, _fs) = with_firestore().await;
        let q = serde_urlencoded::from_str("t=nope").unwrap();
        body_of(register::invite_page(State(p), h, Query(q)).await).await
    })
    .await;
    let ja = register::magic_redirect(
        State(plain()),
        accept(Some("ja")),
        Query(serde_urlencoded::from_str("t=a").unwrap()),
    )
    .await
    .0;
    assert!(
        ja.contains("NAME_REQUIRED?'氏名（必須）':'氏名（任意）'"),
        "氏名の必須・任意の表示は今までと同じ文字列"
    );
}

#[tokio::test]
async fn the_ciba_approval_page_follows_the_browser_language() {
    check_page(
        "ciba (signed out)",
        "承認するにはログインが必要です。",
        |h| async move {
            body_of(ciba::ciba_pending(State(plain()), h, CookieJar::default()).await).await
        },
    )
    .await;
    check_page(
        "ciba (nothing pending)",
        "保留中の要求はありません。",
        |h| async move {
            let p = plain();
            let jar = login_as(&p, "acc-1").await;
            body_of(ciba::ciba_pending(State(p), h, jar).await).await
        },
    )
    .await;
    check_page("ciba (one pending)", "承認（passkey）", |h| async move {
        let p = plain();
        p.ciba
            .create("client-1", "acc-1", "openid", "order-100", None)
            .await
            .unwrap();
        let jar = login_as(&p, "acc-1").await;
        body_of(ciba::ciba_pending(State(p), h, jar).await).await
    })
    .await;
}

#[tokio::test]
async fn admin_pages_follow_the_browser_language() {
    let (p, fs) = admin_world().await;
    let jar = login_as(&p, "acc-me").await;
    let (p, jar, fsr) = (&p, &jar, fs.as_ref());

    check_page("admin home", "管理コンソール", |h| async move {
        body_of(admin::admin_home(State(p.clone()), h, jar.clone()).await).await
    })
    .await;
    check_page("users", "登録日", |h| async move {
        body_of(admin::users_list(State(p.clone()), h, jar.clone()).await).await
    })
    .await;
    for (account, ja) in [
        (
            "acc-me",
            "自分自身は凍結できません（セッションが即座に失効するため）。",
        ),
        ("acc-active", "このアカウントを凍結しますか？"),
        ("acc-u", "このアカウントを完全に削除しますか？"),
        ("acc-boss", "管理者は削除できません（先に管理者を剥奪）。"),
    ] {
        check_page(&format!("user {account}"), ja, |h| async move {
            body_of(
                admin::user_detail(State(p.clone()), h, jar.clone(), Path(account.to_string()))
                    .await,
            )
            .await
        })
        .await;
    }
    check_page("audit", "監査ログ（直近2件）", |h| async move {
        body_of(admin::audit_list(State(p.clone()), h, jar.clone()).await).await
    })
    .await;

    let mut client = client("rp-1");
    crate::dcr_store::save_client(&fs, &client).await.unwrap();
    client.client_id = "rp-2".into();
    client.post_logout_redirect_uris = vec!["https://rp.example.com/".into()];
    client.client_secret = Some("hash".into());
    crate::dcr_store::save_client(&fs, &client).await.unwrap();
    check_page("clients", "認証方式", |h| async move {
        body_of(admin::clients_list(State(p.clone()), h, jar.clone()).await).await
    })
    .await;
    for (id, ja) in [
        (
            "rp-1",
            "（なし。この client はサインアウト後の戻り先を持ちません）",
        ),
        ("rp-2", "設定済み"),
    ] {
        check_page(&format!("client {id}"), ja, |h| async move {
            body_of(
                admin::client_detail(State(p.clone()), h, jar.clone(), Path(id.to_string())).await,
            )
            .await
        })
        .await;
    }

    let constraints = crate::dcr::IatConstraints {
        allowed_redirect_hosts: vec!["rp.example.com".into()],
        allowed_grant_types: vec!["authorization_code".into()],
        profile: crate::dcr::ClientProfile::Public,
    };
    crate::dcr_store::put_iat(&fs, "h-live", &constraints, now() + 3600, false)
        .await
        .unwrap();
    crate::dcr_store::put_iat(&fs, "h-old", &constraints, 1, false)
        .await
        .unwrap();
    check_page("iats", "未消費のIAT", |h| async move {
        body_of(admin::iats_pending_list(State(p.clone()), h, jar.clone()).await).await
    })
    .await;
    check_page("mint form", "IATを新規発行", |h| async move {
        body_of(admin::iat_mint_form(State(p.clone()), h, jar.clone()).await).await
    })
    .await;
    check_page("flash gone", "表示済みです", |h| async move {
        body_of(admin::iat_show_once(State(p.clone()), h, jar.clone(), Path("none".into())).await)
            .await
    })
    .await;
    for (expires_at, ja) in [(now() + 300, "IATを発行しました"), (1, "期限切れ")] {
        check_page("flash", ja, |h| async move {
            let flash = Uuid::new_v4().to_string();
            let doc = serde_json::json!({
                "raw_token": crate::firestore::s("raw"),
                "expires_at": crate::firestore::int(expires_at),
            });
            fsr.set_doc("adminIatFlash", &flash, doc).await.unwrap();
            body_of(admin::iat_show_once(State(p.clone()), h, jar.clone(), Path(flash)).await).await
        })
        .await;
    }
}

#[tokio::test]
async fn giving_up_admin_rights_shows_a_page_in_the_browser_language() {
    check_page(
        "gave up admin",
        "管理者権限を放棄しました",
        |h| async move {
            let (p, fs) = admin_world().await;
            let jar = login_as(&p, "acc-me").await;
            crate::account_admin::enable_account(&fs, "cli", "boss@example.com")
                .await
                .unwrap();
            body_of(admin::user_revoke_admin(State(p), h, jar, Path("acc-me".into())).await).await
        },
    )
    .await;
}

#[tokio::test]
async fn admin_messages_follow_the_browser_language() {
    let (p, fs) = admin_world().await;
    let jar = login_as(&p, "acc-me").await;
    let (p, jar) = (&p, &jar);

    check_text(
        "disable self",
        "自分自身は凍結できません",
        |h| async move {
            body_of(
                admin::user_disable(State(p.clone()), h, jar.clone(), Path("acc-me".into())).await,
            )
            .await
        },
    )
    .await;
    check_text(
        "delete admin",
        "管理者は削除できません。先に管理者を剥奪してください",
        |h| async move {
            body_of(
                admin::user_delete(State(p.clone()), h, jar.clone(), Path("acc-boss".into())).await,
            )
            .await
        },
    )
    .await;
    check_text(
        "delete active",
        "凍結していないアカウントは削除できません。先に凍結してください",
        |h| async move {
            body_of(
                admin::user_delete(State(p.clone()), h, jar.clone(), Path("acc-active".into()))
                    .await,
            )
            .await
        },
    )
    .await;
    let mint = |form: &'static str| {
        move |h: HeaderMap| async move {
            let form = Form(serde_urlencoded::from_str(form).unwrap());
            body_of(admin::iat_mint_submit(State(p.clone()), h, jar.clone(), form).await).await
        }
    };
    check_text(
        "mint without hosts",
        "redirect host を最低1つ指定してください",
        mint("profile=public&redirect_hosts=+&ttl_hours=1"),
    )
    .await;
    check_text(
        "mint with a long ttl",
        "ttl_hours は1〜8760（365日）の範囲で指定してください",
        mint("profile=public&redirect_hosts=rp.example.com&ttl_hours=9000"),
    )
    .await;

    crate::dcr_store::save_client(&fs, &client("rp-1"))
        .await
        .unwrap();
    for lang in [None, Some("ja")] {
        let form = Form(
            serde_urlencoded::from_str(
                "post_logout_redirect_uris=https%3A%2F%2Fevil.example.net%2F",
            )
            .unwrap(),
        );
        let resp = admin::client_set_post_logout(
            State(p.clone()),
            accept(lang),
            jar.clone(),
            Path("rp-1".into()),
            form,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let text = body_of(resp).await;
        assert!(
            !has_japanese(&text) && text.contains("evil.example.net"),
            "OAuth の検証の文言は英語だけ: {text}"
        );
    }
}

#[tokio::test]
async fn the_last_admin_message_follows_the_browser_language() {
    check_text(
        "revoke last admin",
        "最後の管理者は剥奪できません",
        |h| async move {
            let (p, fs) = with_firestore().await;
            crate::admin_store::grant_admin(&fs, "acc-only", "cli")
                .await
                .unwrap();
            let jar = login_as(&p, "acc-only").await;
            body_of(admin::user_revoke_admin(State(p), h, jar, Path("acc-only".into())).await).await
        },
    )
    .await;
}

#[test]
fn mails_follow_the_browser_language_and_are_bilingual_without_one() {
    type Mail = fn(Option<Lang>) -> (String, String);
    let mails: [(&str, Mail, &str); 2] = [
        (
            "verification",
            |l| crate::mailer::verification_mail("https://idp.example/r?t=abc", l),
            "メールアドレス確認",
        ),
        (
            "already registered",
            |l| crate::mailer::already_registered_mail("a@example.com", l),
            "既に登録済みです",
        ),
    ];
    for (name, mail, ja_heading) in mails {
        let (subject, html) = mail(Some(Lang::En));
        assert!(
            !has_japanese(&subject) && !has_japanese(&html),
            "{name}: 英語のメールに日本語: {subject} {html}"
        );
        assert!(subject.starts_with("[rust-op] "), "{name}: {subject}");
        assert!(!html.contains("[["), "{name}");

        let (subject, html) = mail(Some(Lang::Ja));
        assert!(subject.starts_with("【rust-op】"), "{name}: {subject}");
        assert!(html.contains(ja_heading), "{name}");

        let (subject, html) = mail(None);
        let (ja_subject, ja_html) = mail(Some(Lang::Ja));
        let (en_subject, en_html) = mail(Some(Lang::En));
        assert_eq!(subject, format!("{ja_subject} / {en_subject}"), "{name}");
        let (ja_idx, en_idx) = (
            html.find(&ja_html).expect("日本語の段"),
            html.find(&en_html).expect("英語の段"),
        );
        assert!(ja_idx < en_idx, "{name}: 日本語の段が先");
    }
    let (_, html) = crate::mailer::already_registered_mail("a@example.com", Some(Lang::Ja));
    assert!(
        html.contains(
            "このメールアドレス (<strong>a@example.com</strong>) は既に登録されています。"
        ),
        "今までの日本語と同じ並び"
    );
}

#[tokio::test]
async fn the_admin_navigation_and_badges_follow_the_browser_language() {
    let (p, _fs) = admin_world().await;
    let jar = login_as(&p, "acc-me").await;
    let html = body_of(admin::users_list(State(p), accept(Some("ja")), jar).await).await;
    for ja in [
        "<title>ユーザー</title>",
        ">ユーザー</a>",
        ">監査ログ</a>",
        ">ログアウト</a>",
        "<h1>ユーザー (4)</h1>",
        "<th>メールアドレス</th>",
        ">凍結中</span>",
        ">有効</span>",
        ">管理者</span>",
    ] {
        assert!(html.contains(ja), "「{ja}」が無い");
    }
}

#[tokio::test]
async fn passkey_pages_translate_the_api_failures_they_show() {
    let login = |h| async move {
        login::login_form(State(plain()), h, Path("uid-1".into()))
            .await
            .0
    };
    let en = login(accept(Some("en"))).await;
    assert!(en.contains("'account disabled':'This account is disabled.'"));
    assert!(en.contains("msgEl.textContent=await errorText(v)"));
    let ja = login(accept(Some("ja"))).await;
    assert!(ja.contains("'account disabled':'このアカウントは凍結されています。'"));

    check_text(
        "signup invalid email",
        "正しいメールアドレスを入力してください。",
        |h| async move {
            let (p, _fs) = with_firestore().await;
            let form = Form(serde_urlencoded::from_str("email=not-an-email").unwrap());
            body_of(register::register_submit(State(p), h, form).await).await
        },
    )
    .await;
}

#[tokio::test]
async fn sign_in_and_admin_refusals_follow_the_browser_language() {
    check_text(
        "admin without sign-in",
        "サインインしてください。",
        |h| async move {
            body_of(admin::users_list(State(plain()), h, CookieJar::default()).await).await
        },
    )
    .await;
    check_text(
        "admin without Firestore",
        "管理コンソールは使えません。",
        |h| async move {
            let p = plain();
            let jar = login_as(&p, "acc-1").await;
            body_of(admin::users_list(State(p), h, jar).await).await
        },
    )
    .await;
    check_text(
        "resume of an unknown sign-in",
        "最初からやり直してください",
        |h| async move {
            let q = HashMap::from([("uid".to_string(), "missing".to_string())]);
            body_of(oidc::authorize_resume(State(plain()), h, Query(q)).await).await
        },
    )
    .await;
    check_text(
        "cancel of an unknown sign-in",
        "最初からやり直してください",
        |h| async move {
            body_of(oidc::authorize_cancel(State(plain()), h, Path("missing".into())).await).await
        },
    )
    .await;
}
