# rust-idp

Rust で実装する WebAuthn 対応 OIDC IdP (Identity Provider) です。
FAPI 2.0 Security Profile および CIBA (Client Initiated Backchannel Authentication) に準拠し、Cloud Run / Firestore を用いたサーバーレス構成で稼働します。

## 特徴

- WebAuthn によるパスキー認証
- OIDC FAPI 2.0 準拠
- CIBA (バックチャネル認証) 対応
- Cloud Run によるサーバーレス実行
- Firestore をデータストアとして使用

## ステータス

開発初期段階です。最小の縦切り（discovery + authorization_code + インメモリ）が動作確認済みです。
段階的な実装計画・開発方針は [CLAUDE.md](./CLAUDE.md) を参照してください。
