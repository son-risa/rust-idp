# rust-idp

A passkey-first OpenID Provider in Rust. It runs as a single Cloud Run service, lets you choose how strict each client must be, and publishes every security claim together with the assumptions it rests on.

**Website: https://son-risa.github.io/rust-idp/** (English / 日本語)

Status: v0.1.0 · running in one production deployment · MIT · not certified. The API may change. Not yet on crates.io.

パスキーでログインする OpenID Provider（Rust 製）。紹介・特徴・検証の範囲は、上のサイトにまとめている（日本語版あり）。

## Try it

```sh
cargo run --example in_memory   # starts a provider on localhost and walks discovery → authorization code → token
```

Build a `rust_idp::Provider` and turn it into an axum `Router` with `rust_idp::router`. Storage, signing keys and mail are traits you can replace (`Store`, `JwsSigner`, `Mailer`, `ClientAuthMethod`, `GrantHandler`, and others).

Passkey sign-in, PAR, dynamic client registration and the admin pages need the `gcp` feature (Firestore, Cloud KMS, Secret Manager, FCM, Resend). It is off by default; the production binary is built with it (`Dockerfile`).

## Documents

- Website: [Get started](https://son-risa.github.io/rust-idp/get-started/) · [Verification](https://son-risa.github.io/rust-idp/verification/)
- [docs/verification-map.md](docs/verification-map.md): which models, tests and premises apply to each client profile
- [docs/routes.md](docs/routes.md): every HTTP route
- [docs/development.md](docs/development.md): running locally, the FIDO2 conformance tool, heavy fuzzing, static clients, deploy notes (Japanese)
- [formal/README.md](formal/README.md): Tamarin models and Kani harnesses
- [docs/security-ladder.md](docs/security-ladder.md), [docs/zero-trust-assessment.md](docs/zero-trust-assessment.md), [docs/crypto-assumptions.md](docs/crypto-assumptions.md)

The site's source is in [`site/`](site/) (built with Zensical; see `site/build.sh`).

## Checks

```sh
cargo test --features gcp   # all tests, same configuration as production
formal/check.sh             # Tamarin models against formal/expected.tsv
formal/check-kani.sh        # Kani harnesses against formal/kani-harnesses.txt
cargo deny check            # advisories and licences
```

## 運用の覚え書き

### 設定（環境変数）

| 変数 | 用途 |
|---|---|
| `ORIGIN` | スキーム+ホスト（例 `https://<issuer-host>`） |
| `BASE_PATH` | パス接頭辞（例 `/oidc`）。issuer = ORIGIN + BASE_PATH |
| `GCLOUD_PROJECT` / `GOOGLE_CLOUD_PROJECT` | Firestore / KMS のプロジェクト。gcp 付きで Firestore を使うとき（`K_SERVICE` か `FIRESTORE_EMULATOR_HOST` があるとき）と管理者用サブコマンドでは必須で、どちらも無ければ起動も CLI も止まる |
| `PORT` / `ADDR` | 待受ポート（Cloud Run は PORT、ローカルは ADDR） |
| `KMS_ES256_KEY` / `KMS_RS256_KEY` | Cloud KMS 署名鍵（無ければ Secret Manager にフォールバック） |
| `FIDO_RP_ID` / `FIDO_ORIGIN` / `FIDO_RP_NAME` | FIDO/WebAuthn の RP 設定 |
| `FIDO_CONFORMANCE_ENABLED` | `/fido` conformance 面の有効化 |
| `CIBA_RP_SECRET` | CIBA クライアントの secret |
| `RESEND_API_KEY` | メール送信（Secret Manager） |
| `MAIL_FROM` | Resend で送るメールの差出人（例 `rust-idp <noreply@example.com>`） |
| `APP_NAME` / `APP_SCHEME` / `APP_ANDROID_PACKAGE` / `APPLE_APP_ID` | メールのリンクから passkey の登録を渡すネイティブのアプリ（表示名・custom scheme・Android の package・`<Team ID>.<Bundle ID>`）。4 つが揃ったときだけ、登録の画面のアプリへの誘導と AASA（`/.well-known/apple-app-site-association`）を出す |
| `FAPI1_X/Y/KID` / `FAPI2_X/Y/KID` | FAPI2 conformance 静的クライアント `fapi-1`/`fapi-2` の公開鍵（**設定時のみ登録 = ON/OFF 切替**。staging にだけ入れ、本番には入れない） |
| `CONFORMANCE_FAPI_CALLBACK` | FAPI conformance の redirect 上書き |
| `LOG_PSEUDONYM_KEY` | ログ内 sub の擬似化キー |

`K_SERVICE` は Cloud Run が自動設定（本番機能の有効化トリガ）。

### パスキーを使えなくなった人の扱い

- **本人（管理者以外）**: ログイン画面か `/account` の「パスキーを使えないとき」（`/recover`）から、メールのリンクでその端末にパスキーを 1 本足す。既存のパスキーは残り、全部のセッションとトークンが失効し、本人に知らせのメールが届く。リンクは 15 分・1 回きり。失くした端末のパスキーは、足した直後に `/account` で消してもらう。
- **管理者・凍結中の人**: メールでは足せない。別の管理者が管理画面の「パスキーだけ削除」を押し、本人が `/signup` で登録し直す（sub は変わらない）。
- **切り戻したとき**: 複数パスキーより前の版（#95 より前）へ戻すと、パスキーが 0 本のアカウントは登録し直す前に管理画面の「パスキーだけ削除」が要る。

### 旧名

旧名 rust-op。2026-09-26 に `david3080/rust-op` から `son-risa/rust-idp` へ移した。crate 名とバイナリ名は 2026-11-23 に `rust-idp` へ変えた。Cloud Run のサービス名は 2026-11 に `rust-idp`・`rust-idp-staging` へ変えた。デプロイ用のサービスアカウント（`rust-op-deployer`）と実行用のサービスアカウント（`rust-op-runtime`）は旧名のまま。

## License

MIT ([`LICENSE`](LICENSE)). rust-idp is an independent Rust implementation and does not copy source code from other projects. Acknowledgements (node-oidc-provider, SimpleWebAuthn, webauthn-rs and others) are in [`CREDITS.md`](CREDITS.md); runtime dependency licences are in [`THIRD-PARTY-LICENSES.md`](THIRD-PARTY-LICENSES.md).
