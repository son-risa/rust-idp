# 設計ノート

CLAUDE.md の「拡張安全性の判断基準」に基づき、新しい公開型/trait/関数シグネチャを導入した箇所の判断を記録する。

## TokenError (src/error.rs)

`enum` を選択。RFC 6749 5.2 で定義された token endpoint のエラーコード(`invalid_request` / `invalid_client` / `invalid_grant` / `unsupported_grant_type` など)は仕様上ほぼ閉じた集合なので、exhaustive match で扱える enum にした。trait化するような「将来実装が増える」種類のものではない。

## CodeStore は trait 化しなかった (src/store.rs)

将来 Firestore 永続化に置き換える予定はあるが、CLAUDE.md の「FAPI 2.0 / CIBA / WebAuthn / Firestore永続化は、素朴な土台が動いてから段階的に足す」という方針に従い、今 felt need がない抽象化(`trait CodeRepository` 等)は先回りしなかった。`CodeStore` は具体的な struct のまま。Firestore対応が実際の作業になった時点で、その時のインターフェース必要性を見てtrait化するか判断する。

## SigningKeys は trait 化しなかった (src/keys.rs)

署名アルゴリズムは RS256 固定。ES256/PS256 等を追加する具体的な要求がまだないため、`trait SigningKey` のような抽象化はせず、RSA専用の具体型にした。

## id_token 署名は KMS委譲を前提にした手組みのJWS生成にする (src/keys.rs)

`sign_id_token` は `jsonwebtoken::encode()` のようなライブラリのローカル署名APIには頼らない。本番では秘密鍵をプロセス内に持たずCloud KMSに保持し、KMSの`asymmetricSign`に署名を委譲する設計にする（rust-opの本番構成を踏襲）。`jsonwebtoken`の`EncodingKey`はローカル鍵材料が必須で外部署名者への委譲をサポートしないため、`base64url(header) + "." + base64url(claims)`を自前で組み立て、その署名対象バイト列を渡すと署名済みバイト列が返る、という境界の関数にする。今の段階ではその関数の中身はローカル鍵で署名してよい（KMS配線自体は素朴な土台が動いてからでよい）が、境界の形は最初からこれに合わせておくことで、KMS移行時に呼び出し側を変えずに内部だけ差し替えられるようにする。

呼び出し元（`handlers/token.rs`）は `state.keys.sign_id_token(&claims)` の1箇所だけであり、この境界は既に保たれている。

## /.well-known/jwks.json はJWK JSONを自前で組み立てる (src/keys.rs)

`jsonwebtoken::jwk`モジュールは公開JWKの読み込み専用で生成機能を持たないため、`jwks_document()`は公開鍵の構成要素（RSAならn/e）から素朴にJSONを組み立てている。ライブラリ側にJWK生成ヘルパーは無いという制約を踏まえた実装であり、今後鍵種別が増えても同様に手組みする。

## authorize ハンドラのエラー処理は enum にしなかった (src/handlers/authorize.rs)

OAuth2 の authorize エンドポイントのエラーには「redirect_uri へのリダイレクトで返すもの(response_type/scope不正)」と「直接400を返すもの(client_id不明・redirect_uri未登録)」の2系統があり、後者をリダイレクトしてしまうとオープンリダイレクタになる。この区別は enum で表現するほど複雑でも再利用されるものでもないため、素朴に関数 `bad_request` / `redirect_with_error` を分けて呼ぶだけに留めた。

## IdTokenClaims は構造体越しに渡す (src/keys.rs)

`SigningKeys::sign_id_token` の引数は `iss/sub/aud/exp/iat/nonce` の直列挙にせず `IdTokenClaims` 構造体越しに渡している。今後 claims が増えても呼び出し側のシグネチャを壊さない。
