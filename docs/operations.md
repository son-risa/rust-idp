# 運用の覚え書き

rust-idp を配備して動かすときの覚え書き。README を短い入口にしたときに、README から移した。

## 設定（環境変数）

| 変数 | 用途 |
|---|---|
| `ORIGIN` | スキーム+ホスト（例 `https://<issuer-host>`） |
| `BASE_PATH` | パス接頭辞（例 `/oidc`）。issuer = ORIGIN + BASE_PATH |
| `GCLOUD_PROJECT` / `GOOGLE_CLOUD_PROJECT` | Firestore / KMS のプロジェクト。gcp 付きで Firestore を使うとき（`K_SERVICE` か `FIRESTORE_EMULATOR_HOST` があるとき）と管理者用サブコマンドでは必須で、どちらも無ければ起動も CLI も止まる |
| `FIRESTORE_DATABASE_ID` | Firestore の database 名。無いか空なら `(default)`。staging は `staging`。PITR で戻すときはここを写しの名に向け替える |
| `PORT` / `ADDR` | 待受ポート（Cloud Run は PORT、ローカルは ADDR） |
| `KMS_ES256_KEY` / `KMS_RS256_KEY` | Cloud KMS 署名鍵（無ければ Secret Manager にフォールバック）。鍵の道（`.../cryptoKeys/<名>`）なら版 1、版までの道（`.../cryptoKeyVersions/<N>`）ならその版で署名する |
| `KMS_ES256_VERIFY_ONLY` / `KMS_RS256_VERIFY_ONLY` | 署名に使わず、`/jwks` と `id_token_hint` の確かめにだけ載せる版（カンマ区切りの版までの道）。鍵の入れ替えの前後に使う。読めなかった版は記録（`kms_verify_only_key_skipped`）して飛ばす。無ければ載せない |
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

## 負荷の試し

staging に負荷を当てるときは、Actions の「Load test (staging)」を手で回す（`.github/workflows/load-test.yml`）。当てる先は staging に固定で、本番には当てない。合否のしきい値は `scripts/load/login-start.js` にだけ置く。

- 当てるのはログインの手前まで（discovery・jwks・PAR・authorize の 303・DPoP 付きの token の誤り応答）。パスキーのログインは機械で回せないので、ログインの後の token の発行・userinfo は当てない。
- cold start の回は、`idle_minutes` の間なにも送らずに待ってから最初の 1 要求を測る。待つ間に staging へ別の要求があると台が止まらず、測れない。
- 回数の上限のある口（登録・CIBA・DCR）には当てない。429 が返ったら、誤りとは分けて数える。
- 1 回で数千要求になり、staging の Firestore の書き込みを使う（PAR・interaction・DPoP の jti）。続けて何度も回さない。

## env を変えたあとの流量

配備の script（`scripts/lib_cloud_run.sh`）は流量を revision 名で決めて渡す。そのため `gcloud run services update --update-env-vars` などで env だけを変えると、新しい revision はできるが流量は 0% のままで、状態は `Retired` になる。`status.latestReadyRevisionName` も前の名のまま変わらない。新しい revision の名は `status.latestCreatedRevisionName` で読み、流量を移す。

```sh
gcloud run services update <サービス> --region asia-northeast1 --update-env-vars ...
R=$(gcloud run services describe <サービス> --region asia-northeast1 --format='value(status.latestCreatedRevisionName)')
gcloud run services update-traffic <サービス> --region asia-northeast1 --to-revisions "$R=100"
```

配備の script は env を渡さないので、こうして変えた env は次の配備でも残る。

## 署名鍵の入れ替え

Cloud KMS の署名鍵（ES256・RS256）を新しい版に替える。前の版で署名した ID Token を確かめられるよう、前の版は 15 日のあいだ `/jwks` に残す。ES256 と RS256 は同じ形で、同時に進めてよい。各段の env の変更は、前の節のとおり流量まで移して 1 段と数える。

### 始める前に

- **staging と本番の両方の image が #162 以降であること。** #162 より前の image は `KMS_*_KEY` の版の道を読めない（鍵の道の後ろに `/cryptoKeyVersions/1` を足して KMS を引き、失敗する）。KMS の初期化に失敗すると、ERROR の記録（`KMS ES256 init failed (...); falling back to Secret Manager`）を出して Secret Manager の鍵で署名し続け、kid が変わる（Secret Manager にも鍵が無ければ起動しない）。promote は本番と staging の image を入れ替えるので、本番に入れた直後の staging には本番の前の image が載っている。各 revision の image を `gcloud run revisions describe` で見て、その image を作った commit を確かめる。revision の `commit-sha` の label は `--image` の配備では前の revision から引き継がれるので、当てにしない。
- 先に staging で通してから本番で行う。staging と本番は別の鍵輪（`oidc-staging`・`oidc`）を使う。鍵が同じだと、staging で版を作るだけで本番の鍵にも版が増える。

### 手順

以下 `<鍵>` は `projects/<project>/locations/<region>/keyRings/<鍵輪>/cryptoKeys/<es256|rs256>`、版 1 を今の版、版 2 を新しい版とする。

1. KMS で新しい版を作り、`ENABLED` になるのを待つ（作った直後は `PENDING_GENERATION`）。この段は配備しない。env が鍵の道を指している間は版 1 で署名し続ける。
   ```sh
   gcloud kms keys versions create --key es256 --keyring <鍵輪> --location <region>
   ```
2. `KMS_ES256_VERIFY_ONLY=<鍵>/cryptoKeyVersions/2` を足して、流量を移す。署名は版 1 のまま、`/jwks` に版 2 が前もって載る。
   - 確かめ: 起動の記録に `KMS_ES256_VERIFY_ONLY: publishing kid "<kid>" for verification only` が出て、その kid が `/jwks` の後ろに載る。この kid を控える。
   - RP の jwks の取り置きが切れるまで待つ。`/jwks` は `Cache-Control` を返さないので、取り置きの長さは RP ごとに違う。つないでいる RP の取り置きの最長を確かめて、その時間を待つ。
3. `KMS_ES256_KEY=<鍵>/cryptoKeyVersions/2`、`KMS_ES256_VERIFY_ONLY=<鍵>/cryptoKeyVersions/1` にして、流量を移す。版 2 で署名し、版 1 は確かめにだけ残す。
   - 確かめ: `/jwks` の先頭（署名鍵が先に並ぶ）の kid が、2 で控えた kid と同じ。起動の記録に `KMS ES256 init failed` と `kms_verify_only_key_skipped` が出ていない。`ES256 signing via Cloud KMS` は版を出さないので、これだけでは版 2 で署名しているとは言えない。
   - 流量を移した時刻を控える。4 の起点になる。
4. 3 の時刻から 15 日たったら、`KMS_ES256_VERIFY_ONLY` を外して（`--remove-env-vars`）流量を移し、`/jwks` に版 2 の kid だけが残ることを確かめてから、KMS で版 1 を無効にする（`gcloud kms keys versions disable 1 ...`）。順を逆にすると、まだ載せている版 1 を読めずに `kms_verify_only_key_skipped` が出る。
   - 15 日は refresh token の寿命の 14 日に 1 日の余裕を足したもの。RP は refresh token の 14 日のあいだ、前の鍵で署名した ID Token を持ちうる。ログアウトの `id_token_hint` は期限切れでも受けるので、RP が持っている間は前の鍵が要る。

### 入れ替えの途中で前の image に戻すとき

`KMS_*_KEY` が版の道を指している間に #162 より前の image へ戻す（`scripts/rollback.sh`、または promote で staging に前の image が載る）と、「始める前に」に書いたとおり Secret Manager の鍵に落ちる。前の image に戻す前に、`KMS_*_KEY` を鍵の道（版 1）に戻し、`KMS_*_VERIFY_ONLY` を外す。版 2 で署名した ID Token は、この時点から確かめられなくなる。

## Firestore を PITR で戻す

Firestore の `(default)`（本番）と `staging` は PITR（7 日）と削除保護を入れてある。PITR は今の database を上書きして戻すのではなく、指定した時刻の中身を**別の名前の database に写す**。戻すときは、写しを作ってから Cloud Run の `FIRESTORE_DATABASE_ID` をその名に向け替える（`src/firestore.rs` の `Firestore::new` がこの env を読む）。

1. 戻したい時刻を決める（7 日より前には戻せない）。分の区切りで指定する。
2. 別の名前の database に写す。
   ```sh
   gcloud firestore databases clone \
     --source-database=projects/<project>/databases/<元の名> \
     --snapshot-time=<UTC の時刻、例 2026-11-26T10:20:00Z> \
     --destination-database=<写しの名>
   ```
   staging で練習したときは、写しに 9 分半かかった。かかる時間は中身の量で変わる。
3. Cloud Run の `FIRESTORE_DATABASE_ID` を写しの名に変え、流量を移す（「env を変えたあとの流量」のとおり）。

**3 の向け替えはまだ練習していない。** 写しに対する実行用のサービスアカウントの権限、写しの索引と TTL の設定、写した時刻から向け替えまでに元の database に書かれたもの（失われる）の扱いは、練習で確かめてから書き足す。

## client に制限付きの scope を許す

`ciba:approve`（CIBA の承認の口に入る token の scope）は、client の登録の `scope` に書かれた client しか求められない。DCR では付かない。既にある登録へは次で書く（他の項目は変えない。`--scope ""` で外す）。

```sh
rust-idp set-client-scope --client mobile-rp --scope ciba:approve
rust-idp set-client-scope --client demo-rp --scope ciba:approve
```

- 承認の口を scope で絞る版を配る前に、staging と本番の Firestore で、承認のアプリの client と `demo-rp` に書いておく。書かずに配ると、承認のアプリの token は承認の口で 403 になる。デモの画面は登録を見て `ciba:approve` を求めないので、サインインと管理画面は止まらない。
- scope を持たない前の版が、管理画面で client を保存し直すと、`scope` が消える（前の版は知らない項目を読み捨てて書き戻す）。配っている途中と前の版へ戻したときは、管理画面で client を保存しない。戻した後は書き直す。
- 配った後、承認のアプリの利用者はログインし直す（前の refresh token では scope を広げられない）。
- 配る前の版で開いたままのデモの画面は、前の scope を求める。配った後は開き直す。

## 旧名

旧名 rust-op。2026-09-26 に `david3080/rust-op` から `son-risa/rust-idp` へ移した。crate 名とバイナリ名は 2026-11-23 に `rust-idp` へ変えた。Cloud Run のサービス名は 2026-11 に `rust-idp`・`rust-idp-staging` へ変えた。デプロイ用のサービスアカウント（`rust-op-deployer`）と実行用のサービスアカウント（`rust-op-runtime`）は旧名のまま。
