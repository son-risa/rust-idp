// ピュア Rust 方針の明文化: unsafe を全面禁止する（lib.rs と同じ）。
#![forbid(unsafe_code)]

use rust_idp::{Client, JwkPub, MobileApp, Provider};

#[tokio::main]
async fn main() {
    // ログ: Cloud Run では構造化 JSON（Cloud Logging がフィールド解析→log-based metric/alert）。
    // ローカルは人間可読のまま。管理者サブコマンドの分岐より前に初期化する:
    // 以前はサーバ起動パスの直前で初期化していたため、サブコマンド(mint/disable-account等)
    // 内の tracing::error!/warn! がサブスクライバ未設置のまま呼ばれ、実行時に完全に
    // 握りつぶされていた(server起動パスの request handler には影響しない——そちらは
    // 元々この初期化より後にしか到達しないため)。
    let env_filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if std::env::var("K_SERVICE").is_ok() {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    // 管理者用サブコマンド（out-of-band）。サーバ起動前に分岐する。
    let argv: Vec<String> = std::env::args().collect();
    #[cfg(feature = "gcp")]
    if rust_idp::gcp::run_admin_command(&argv).await {
        return;
    }
    #[cfg(not(feature = "gcp"))]
    if let Some(cmd) = argv
        .get(1)
        .filter(|c| rust_idp::AdminCommand::from_name(c).is_some())
    {
        eprintln!(
            "{cmd}: Firestore を使うので、gcp の feature を付けて build した binary でだけ使えます"
        );
        std::process::exit(2);
    }

    // ORIGIN = スキーム+ホスト（例 https://oidc.sonrisa.co.jp）。
    // BASE_PATH = Hosting rewrite のパス接頭辞（例 /roidc）。issuer = ORIGIN + BASE_PATH。
    let origin = std::env::var("ORIGIN").unwrap_or_else(|_| "http://localhost:8080".into());
    let base_path = std::env::var("BASE_PATH").unwrap_or_default();
    let issuer = format!("{origin}{base_path}");

    // demo-rp / mobile-rp / ciba-rp は Step5 の移行(migrate-static-clients)で
    // Firestore(clients/)へ移り、resolve_client の静的Map→Firestoreフォールバック経由で
    // 解決される（static_app_clients は移行コマンド専用の定義源として gcp.rs に在る）。
    // このため Firestore が未配線のローカル実行(FIRESTORE_EMULATOR_HOST 未設定)では
    // これらのクライアントは解決できない点に注意（demo-rp 等の動作確認には
    // FIRESTORE_EMULATOR_HOST を設定し migrate-static-clients を流し込んでおくこと）。
    let mut provider = Provider::new(issuer.clone())
        .with_base_path(base_path.clone())
        .with_invite_clients(client_ids_from_env("INVITE_CLIENT_IDS"))
        .with_introspection_clients(client_ids_from_env("INTROSPECTION_CLIENT_IDS"));

    if let Some(app) = mobile_app_from_env() {
        provider = provider.with_mobile_app(app);
    }

    // FAPI2 conformance 用の静的クライアント（fapi-1 = client / fapi-2 = client2）。
    // FAPI 認定スイートは動的登録 variant を持たず静的クライアント専用なので、認定時のみ
    // env で公開鍵（FAPI{1,2}_X/Y/KID）を与えて登録する。env 未設定の本番では登録されない
    // （= パラメータ切替: 鍵 env を入れれば ON、外せば OFF）。private_key_jwt + PAR + PKCE + DPoP。
    for (id, prefix) in [("fapi-1", "FAPI1"), ("fapi-2", "FAPI2")] {
        if let Some(client) = fapi_client_from_env(id, prefix) {
            tracing::info!("registered FAPI conformance client {id} from env");
            provider = provider.with_client(client);
        }
    }

    #[cfg(feature = "gcp")]
    let provider = rust_idp::gcp::configure_from_env(provider).await;
    // gcp 無しの binary を Cloud Run に載せると、起動ごとの鍵とメモリ上の保存先で本番を名乗ってしまう。
    // gcp 付きの binary が正規の鍵を読めないときと同じく、起動しない。
    #[cfg(not(feature = "gcp"))]
    if std::env::var("K_SERVICE").is_ok() {
        tracing::error!("FATAL: built without the gcp feature; refusing to start on Cloud Run");
        std::process::exit(1);
    }
    #[cfg(not(feature = "gcp"))]
    if std::env::var("FIRESTORE_EMULATOR_HOST").is_ok() {
        tracing::warn!("FIRESTORE_EMULATOR_HOST is ignored: built without the gcp feature");
    }
    // gcp 無しでは、利用者・passkey・登録の token などもメモリに置く（process を止めると消える）。
    #[cfg(not(feature = "gcp"))]
    let provider = {
        let docs = std::sync::Arc::new(rust_idp::MemoryDocumentStore::default());
        provider
            .with_document_store(docs.clone())
            .with_store(std::sync::Arc::new(rust_idp::MemoryStore::with_documents(
                docs,
            )))
    };
    let app = rust_idp::router(provider);

    if std::env::var("K_SERVICE").is_ok() {
        // Cloud Run は $PORT を 0.0.0.0 で待ち受ける。
        let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
            .await
            .unwrap();
        tracing::info!("rust-idp listening on 0.0.0.0:{port} (issuer={issuer})");
        axum::serve(listener, app).await.unwrap();
    } else {
        // ローカルは IPv4/IPv6 ループバック両方で待つ。Conformance Tool(Chromium)が
        // localhost を ::1 に解決しても届くようにする（127.0.0.1 だけだと Failed to fetch）。
        let port = std::env::var("ADDR")
            .ok()
            .and_then(|a| a.rsplit(':').next().map(|s| s.to_string()))
            .or_else(|| std::env::var("PORT").ok())
            .unwrap_or_else(|| "8080".into());
        let v4 = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let app2 = app.clone();
        tracing::info!(
            "rust-idp local listening on 127.0.0.1:{port} and [::1]:{port} (issuer={issuer})"
        );
        match tokio::net::TcpListener::bind(format!("[::1]:{port}")).await {
            Ok(v6) => {
                let _ = tokio::join!(axum::serve(v4, app), axum::serve(v6, app2),);
            }
            Err(e) => {
                tracing::warn!("IPv6 loopback bind failed ({e}); IPv4 only");
                axum::serve(v4, app).await.unwrap();
            }
        }
    }
}

/// カンマ区切りの client_id の一覧。未設定なら空。
fn client_ids_from_env(name: &str) -> Vec<String> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .collect()
}

/// 登録の画面から開くアプリと AASA。4 つが揃っていれば Some。
fn mobile_app_from_env() -> Option<MobileApp> {
    Some(MobileApp {
        name: std::env::var("APP_NAME").ok()?,
        scheme: std::env::var("APP_SCHEME").ok()?,
        android_package: std::env::var("APP_ANDROID_PACKAGE").ok()?,
        apple_app_id: std::env::var("APPLE_APP_ID").ok()?,
    })
}

/// FAPI conformance クライアントを env から組む。`{prefix}_X` `{prefix}_Y` `{prefix}_KID`
/// が全て揃っていれば Some。揃っていなければ None（= 本番で未登録）。
/// redirect は認定スイートの alias コールバック固定（`CONFORMANCE_FAPI_CALLBACK` で上書き可）。
fn fapi_client_from_env(client_id: &str, prefix: &str) -> Option<Client> {
    let x = std::env::var(format!("{prefix}_X")).ok()?;
    let y = std::env::var(format!("{prefix}_Y")).ok()?;
    let kid = std::env::var(format!("{prefix}_KID")).ok()?;
    let callback = std::env::var("CONFORMANCE_FAPI_CALLBACK").unwrap_or_else(|_| {
        "https://www.certification.openid.net/test/a/rustop-fapi2/callback".into()
    });
    Some(Client {
        client_id: client_id.into(),
        redirect_uris: vec![callback],
        post_logout_redirect_uris: vec![],
        initiate_login_uri: None,
        token_endpoint_auth_method: "private_key_jwt".into(),
        client_secret: None,
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        dpop_bound: true,
        jwks: vec![JwkPub { kid, x, y }],
        jwks_uri: None,
        require_par: true,
        require_pkce: true,
        id_token_signed_response_alg: None,
    })
}
