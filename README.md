# rust-idp

Rust で実装する WebAuthn 対応 OIDC IdP (Identity Provider) です。
FAPI 2.0 Security Profile および CIBA (Client Initiated Backchannel Authentication) に準拠し、Cloud Run / Firebase Functions / Firestore を用いたサーバーレス構成で稼働します。

## 特徴

- WebAuthn によるパスキー認証
- OIDC FAPI 2.0 準拠
- CIBA (バックチャネル認証) 対応
- Cloud Run および Firebase Functions によるサーバーレス実行
- Firestore をデータストアとして使用

## ステータス

開発初期段階です。段階的に実装を進めています。
