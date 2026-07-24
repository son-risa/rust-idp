# rust-idp 開発方針

## 目的

node-oidc-provider を機能/責務分割のチェックリストとして参照しつつ、ゼロからピュアRustでOIDC Providerを実装する。最終的にはWebAuthnパスキー認証・FAPI 2.0 Security Profile・CIBAに対応し、Cloud Run + Firestoreで稼働させる（README参照）。ただし実装者（david3080）自身がコードと設計判断を理解することが最優先で、動くものを最短で作ることではない。

## 進め方

- 最小の縦切り（discovery doc + クライアント1つ固定 + authorization_codeのみ + インメモリ）から始める
- trait/enum設計は「今felt needがある」ものだけを導入する。将来のための抽象化を先回りしない
- 機能がまとまった単位でOpenID Foundation conformance suite（certification.openid.net）の該当テスト計画のみ実行し、チェックポイントとする（フルスイートを早期に回さない）
- FAPI 2.0 / CIBA / WebAuthn / Firestore永続化は、そこに至る素朴な土台（authorization_code + インメモリ）が動いてから段階的に足す。具体的な順序は下記「段階的ロードマップ」を参照

## 段階的ロードマップ（現時点の計画、進めながら見直す）

1. **最小の縦切り**(完了) — discovery + authorization_code + インメモリ + ダミー認証
2. **異常系の堅牢化** — 不正なclient_id/redirect_uri/response_type、認可コードの再利用・期限切れ、state伝播等を洗い出して修正
3. **WebAuthn認証** — ダミー認証を実際のpasskey登録・認証に置き換え。チェックポイントは2つ、別物であることに注意:
   - Basic OP conformance（certification.openid.net、OIDCコア部分のみを見る。WebAuthn/FIDO2は対象外）
   - FIDO2 Server conformance（FIDO Allianceのネイティブアプリ、登録済み・利用可能）。テスト対象サーバーは本番のWebAuthn RPエンドポイントと別に、テスト専用の4エンドポイント（`/attestation/options`, `/attestation/result`, `/assertion/options`, `/assertion/result`、フィールドエンコードが本番と一部異なる）を一時的に実装する必要がある。テスト完了後は本番ビルドから外してよい
4. **PKCE・iss付与** — PKCE・redirect_uri厳密一致・認可レスポンスへのiss付与（既存フローへの軽量な追加なので早めに入れる）
5. **Firestore永続化** — アカウント/credentialを永続化
6. **KMS署名移行** — id_token署名をプロセス内ローカル鍵からCloud KMSの`asymmetricSign`へ委譲（DESIGN_NOTES.md参照: `sign_bytes`のasync化・SHA-256ダイジェスト送信が必要）。ローカル署名とKMS署名を実行時に選べるようにする必要が生じるので、ここでSigningKey相当のtrait化を検討する
7. **private_key_jwt認証** — client_secret_postから置き換え
8. **PAR対応** — Pushed Authorization Requests
9. **DPoP対応** — センダー制約付きトークン
10. **CIBA対応** — ここまで揃った状態で作ると最初からFAPI2-CIBAプロファイル準拠で実装できる
11. **FAPI2 conformance実行**（最終チェックポイント）— 正式なFAPI2 Security Profile conformance suite実行

FAPI 2.0対応は単独の機能ではなく、4・7・8・9・10にまたがって段階的に重ねる強化要件の集合であることに注意する（6のKMS署名移行はFAPI2仕様上の要求ではなく、rust-op踏襲のセキュリティ設計判断）。「FAPI2対応する」という単発の作業は発生しない。

この順序は現時点の計画であり、実装を進める中で見直しが必要になった場合は理由をDESIGN_NOTES.mdに残す。

## テスト方針

- ステップ2（異常系の堅牢化）以降、curl等で手動確認した内容はその場で自動テスト（`#[tokio::test]`等）として残す。全網羅は狙わず、実際に手で叩いて確認した異常系をそのままテスト化する程度でよい
- 理由: rust-op開発時、Firestore連携層にテストが無かったために発見が遅れた自己バグ混入の実例がある。テスト未実装のまま機能を積み上げるのは同種のリスクを繰り返す

## デプロイ/運用トラック（機能ステップと並行して進める）

- 全機能が揃うまでデプロイを待たない。機能ステップと並行して、早い段階からCloud Run + GitHub ActionsでのCI/CD（test→build→deploy）を通す
- 現時点（ステップ1-2相当）でも最小構成でCloud Runにデプロイしておく。署名鍵はプロセス内生成のままでよい。カスタムドメインはWebAuthnで必要になるステップ3まで不要（デフォルトの`*.run.app`で十分）
- GCPプロジェクトはrust-opと同じ`fido2-8b943`、Cloud RunサービスアカウントはRust-opの`rust-op-runtime@`を再利用、KMS鍵も共有（既に合意済みの方針）
- 機能ステップに合わせてインフラも段階的に拡張する: ステップ3でカスタムドメイン(`idp.sonrisa.co.jp`)、ステップ5で`FIRESTORE_DATABASE_ID`等の環境変数、ステップ6（KMS署名移行）でKMSアクセス権限

## 拡張安全性の判断基準（新しい公開型/trait/関数シグネチャを導入する時だけ適用）

- 将来ケースが増える見込みが強いもの → trait（実装追加だけで既存コードに触れない設計にする）
- 仕様上ほぼ閉じているもの → enum（exhaustive matchで安全性を取る）
- 迷ったらtrait側に倒す（後からenumをtraitに開くより、traitをenumに閉じる方が一般に手戻りが小さい）
- 型/trait名は「今実装する1ケース」ではなく「それが表す概念」で命名する
- 関数シグネチャは、今必要なフィールドだけを持つ構造体越しに渡す（引数の直列挙にしない）
- 上記の判断をした箇所は DESIGN_NOTES.md に一言（何を選んだか・なぜか）残す

## コミット規約

- 1つのまとまった変更 = 1コミット
- メッセージは「何を」+「なぜその設計にしたか」
- 縦切り完成やconformanceチェックポイント通過ごとに `git tag` を打つ
