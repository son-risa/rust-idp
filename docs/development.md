# 開発の覚え書き

README を短い入口にしたときに、README から移した開発と配備の覚え書き。

## 手元で動かす

```sh
ADDR=127.0.0.1:8099 cargo run                                     # gcp 無し。メモリの保存先、起動ごとの一時の署名鍵、メールはログへ
FIRESTORE_EMULATOR_HOST=127.0.0.1:8180 cargo run --features gcp   # Firestore だけエミュレータへ
```

KMS・Secret Manager・Resend は、`K_SERVICE`（Cloud Run が設定する）があるときだけ有効になる。

### FIDO2 の適合試験の道具を手元で当てる

```sh
ADDR=127.0.0.1:8099 FIDO_RP_ID=localhost FIDO_ORIGIN=http://localhost:8099 \
  FIDO_CONFORMANCE_ENABLED=1 cargo run
# 道具の Server URL に http://localhost:8099/fido を入れる
```

## 試験

```sh
cargo test                                  # gcp 無し（fake Firestore を使う試験は除く）
cargo test --features gcp                   # 本番と同じ構成。全部の試験
PROPTEST_CASES=30000 cargo test fuzz_tests  # 重いファジング
```

## 静的な client

| client_id | 認証 | 用途 |
|---|---|---|
| `demo-rp` | public + PKCE + DPoP | 内蔵の試しの RP |
| `mobile-rp` | public + PKCE + DPoP | モバイルアプリ（custom scheme の redirect） |
| `ciba-rp` | client_secret_basic | CIBA の Consumption Device |
| `fapi-1` / `fapi-2` | private_key_jwt + PAR + PKCE + DPoP | FAPI 2.0 の適合試験。env（`FAPI1_*`・`FAPI2_*`）を入れたときだけ登録する。staging だけ |
| `dcr-*` | private_key_jwt など | DCR で登録した client（Firestore に保存） |

## 配備（Cloud Run）

- 手順は `scripts/` と `.github/workflows/` にある。
- 再デプロイしても、Cloud Run の env と secret の割り当ては保たれる。
- issuer の独自ドメインは Cloud Run のドメインの割り当てで直に結ぶ。保護するリソースサーバは別のサービスに分ける。
- 署名鍵と Firestore は、実行用のサービスアカウント（`cloudkms.signerVerifier` と `datastore.user`）で使う。
