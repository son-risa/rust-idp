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

## 手元で動かす

```sh
cargo run                                    # http://localhost:8080
FIRESTORE_EMULATOR_HOST=127.0.0.1:8180 cargo run --features gcp   # Firestore だけエミュレータへ
```

手元では Firestore・Resend・KMS は使わない。保存先はメモリ、メールは記録に出すだけ、署名鍵は起動ごとに新しく作る。
