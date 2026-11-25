# 運用の覚え書き

rust-idp を配備して動かすときの覚え書き。README を短い入口にしたときに、README から移した。

## 設定（環境変数）

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
| `MAIL_FROM` | Resend で送るメールの差出人（例 `rust-idp <noreply@example.com>`）。無ければ Resend を使わず、メールはログに出る |
| `APP_NAME` / `APP_SCHEME` / `APP_ANDROID_PACKAGE` / `APPLE_APP_ID` | メールのリンクから passkey の登録を渡すネイティブのアプリ（表示名・custom scheme・Android の package・`<Team ID>.<Bundle ID>`）。4 つが揃ったときだけ、登録の画面のアプリへの誘導と AASA（`/.well-known/apple-app-site-association`）を出す |
| `FAPI1_X/Y/KID` / `FAPI2_X/Y/KID` | FAPI2 conformance 静的クライアント `fapi-1`/`fapi-2` の公開鍵（**設定時のみ登録 = ON/OFF 切替**。staging にだけ入れ、本番には入れない） |
| `CONFORMANCE_FAPI_CALLBACK` | FAPI conformance の redirect 上書き |
| `LOG_PSEUDONYM_KEY` | ログ内 sub の擬似化キー |
| `INVITE_CLIENT_IDS` | `/invites`・`/accounts/disable` を呼べる client_id（カンマ区切り） |
| `INTROSPECTION_CLIENT_IDS` | ほかの client に出た access token も `/introspect`・`/oauth/mandate/consume` で引ける RS の client_id（カンマ区切り）。ここに無い client は自分に出た token しか引けない |

`K_SERVICE` は Cloud Run が自動設定（本番機能の有効化トリガ）。

## パスキーを使えなくなった人の扱い

- **本人（管理者以外）**: ログイン画面か `/account` の「パスキーを使えないとき」（`/recover`）から、メールのリンクでその端末にパスキーを 1 本足す。既存のパスキーは残り、全部のセッションとトークンが失効し、本人に知らせのメールが届く。リンクは 15 分・1 回きり。失くした端末のパスキーは、足した直後に `/account` で消してもらう。
- **管理者・凍結中の人**: メールでは足せない。別の管理者が管理画面の「パスキーだけ削除」を押し、本人が `/signup` で登録し直す（sub は変わらない）。
- **切り戻したとき**: 複数パスキーより前の版（#95 より前）へ戻すと、パスキーが 0 本のアカウントは登録し直す前に管理画面の「パスキーだけ削除」が要る。

## 旧名

旧名 rust-op。2026-09-26 に `david3080/rust-op` から `son-risa/rust-idp` へ移した。crate 名とバイナリ名は 2026-11-23 に `rust-idp` へ変えた。Cloud Run のサービス名は 2026-11 に `rust-idp`・`rust-idp-staging` へ変えた。デプロイ用のサービスアカウント（`rust-op-deployer`）と実行用のサービスアカウント（`rust-op-runtime`）は旧名のまま。
