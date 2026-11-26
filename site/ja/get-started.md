# 使い始める

rust-idp の動かし方は 2 つある。自分の axum のアプリに組み込むか、同梱の binary を Cloud Run に置くか。

## ライブラリとして組む

crate は 1 つ。`rust_idp::Provider` を組み、`rust_idp::router` で axum の `Router` にする。保存先・署名鍵・メールは trait で、既定はメモリ上の保存先と、起動ごとに作る署名鍵。

crate はまだ crates.io に出していない。リポジトリを直に指す。

```toml
[dependencies]
rust-idp = { git = "https://github.com/son-risa/rust-idp" }
```

例を動かす。localhost に OP を立て、同じ process の中から discovery、`/authorize`、認可コード、`/token` まで通す。

```sh
cargo run --example in_memory
```

この例は、ログイン済みのセッションを保存先へ直に入れる。この例は `DocumentStore` を渡さないので、パスキーのログインは使えない。

### `gcp` の feature が要るもの

Firestore・Cloud KMS・Secret Manager・FCM・Resend へ出る実装は `gcp` の feature の中にある。この feature は既定では入らない。

付けない binary は、利用者とパスキーを `MemoryDocumentStore` に置く。パスキーの登録とログインは動く。process を止めると消える。

ライブラリとして `Provider::new` だけで組むと、`DocumentStore` が無い。`with_document_store` で渡す。渡さないと、次は 503 で断る。

- パスキーの登録とログイン
- PAR と動的な client 登録
- 管理画面

## Cloud Run に置く

`Dockerfile` が `--features gcp` で本番の binary を作る。Cloud Build がソースから build するので、手元の Docker は要らない。

```sh
gcloud run deploy <service> --source . --region <region>
```

要るもの:

- Firestore のデータベース
- ES256 と RS256 の署名鍵。Cloud KMS に置き、`KMS_ES256_KEY`・`KMS_RS256_KEY` で指す。無ければ Secret Manager の鍵を使う
- 登録と復旧のメールのための `RESEND_API_KEY`
- `cloudkms.signerVerifier` と `datastore.user` を持つ、実行用のサービスアカウント
- `ORIGIN` と `BASE_PATH`。issuer は `ORIGIN + BASE_PATH`

Cloud Run の上では、2 つの署名鍵を読めなければ起動しない。`gcp` 無しで build した binary は、Cloud Run では起動しない。

独自のドメインは Cloud Run のサービスに直に割り当てる。LB は要らない。

### 費用 {#costs}

小さな組織なら、この置き方の費用はほぼかからない。ただし、まったくの無料ではない。

**課金の有効化が要る。** Google Cloud のプロジェクトに請求先アカウントを結ぶ。課金が有効でないと、Cloud Run は動かず、Firestore の TTL（期限の過ぎた文書を消す仕組み）も使えない。

**無料枠に収まるもの。** Firestore には、プロジェクトごとに 1 日あたりの無料枠がある。その中なら次はお金がかからない:

| Firestore（東京、`asia-northeast1`） | 1 日の無料の分 | 無料枠を超えた分の単価 |
|---|---|---|
| 文書の読み | 50,000 件 | 100 万件あたり 0.38 USD |
| 文書の書き | 20,000 件 | 100 万件あたり 1.15 USD |
| 文書の削除 | 20,000 件 | 100 万件あたり 0.13 USD |
| 保存するデータ | 1 GiB | 1 GiB・1 か月あたり 0.115 USD |

Cloud Run は、請求先アカウントごとに、毎月はじめの 200 万件の request が無料。CPU とメモリの無料の分は [Cloud Run の料金の頁](https://cloud.google.com/run/pricing) を見てほしい。rust-idp は最小 0 台で動かすので、誰もログインしない間は何も動かない。

**無料の分が無いもの。** 次は 1 件目・1 GiB 目から課金される。このため、ほかは無料枠に収まっていても、ごく少額の請求が来る:

| Firestore（東京、`asia-northeast1`） | 単価 |
|---|---|
| TTL の削除（期限が過ぎて、TTL の方針で消される文書） | 100 万件あたり 0.13 USD |
| ポイントインタイム リカバリ（PITR）の保存 | 1 GiB・1 か月あたり 0.115 USD |

rust-idp は、セッションや認可コードのような短命の記録に期限を付け、Firestore の TTL に消させる。Google の [TTL の頁](https://cloud.google.com/firestore/docs/ttl) には "TTL delete operations count towards your document delete costs."（TTL の削除は文書の削除の費用に数える）とあり、"Data is typically deleted within 24 hours after its expiration date."（データはふつう期限から 24 時間以内に消える）ともある。

30 人での目安: 1 人が 1 日 10 回ログインし、書いた文書がすべて後で TTL で消えると多めに置くと、TTL の削除は月におよそ 10 万件、費用はおよそ 0.013 USD（1 USD = 150 円で約 2 円）。実際の例では、ある環境で TTL を有効にした初日に、本番と staging の合計で 716 件が消えた。それまでに溜まっていた、期限切れの記録の分である。

PITR は 7 日分の履歴を持つ。rust-idp の規模では保存するデータがごく小さいので、PITR の保存の費用もごく小さい。

**単価は変わりうる。** 上の単価は、2026-11-26 に Google の料金表で確かめた値（Cloud Billing Catalog API、Firestore の Standard edition、東京）。今の単価は [Firestore の料金の頁](https://cloud.google.com/firestore/pricing) と [Cloud Run の料金の頁](https://cloud.google.com/run/pricing) で確かめてほしい。料金表を自分で引くなら:

```sh
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  'https://cloudbilling.googleapis.com/v1/services/EE2C-7FAC-5E08/skus?pageSize=5000&currencyCode=USD'
```

**費用が出たら知らせてほしいなら**、Cloud Billing の [予算と予算アラート](https://cloud.google.com/billing/docs/how-to/budgets) を置くとよい。決めた額に達すると知らせが来る。ただし、予算だけでは課金は止まらない。

## 手元で動かす

```sh
cargo run                                    # http://localhost:8080
FIRESTORE_EMULATOR_HOST=127.0.0.1:8180 cargo run --features gcp   # Firestore だけエミュレータへ
```

手元では Firestore・Resend・KMS は使わない。保存先はメモリ、メールは記録に出すだけ、署名鍵は起動ごとに新しく作る。
