# rust-idp 開発方針

## 目的

node-oidc-provider を機能/責務分割のチェックリストとして参照しつつ、ゼロからピュアRustでOIDC Providerを実装する。最終的にはWebAuthnパスキー認証・FAPI 2.0 Security Profile・CIBAに対応し、Cloud Run + Firestoreで稼働させる（README参照）。ただし実装者（david3080）自身がコードと設計判断を理解することが最優先で、動くものを最短で作ることではない。

## 進め方

- 最小の縦切り（discovery doc + クライアント1つ固定 + authorization_codeのみ + インメモリ）から始める
- trait/enum設計は「今felt needがある」ものだけを導入する。将来のための抽象化を先回りしない
- 機能がまとまった単位でOpenID Foundation conformance suite（certification.openid.net）の該当テスト計画のみ実行し、チェックポイントとする（フルスイートを早期に回さない）
- FAPI 2.0 / CIBA / WebAuthn / Firestore永続化は、そこに至る素朴な土台（authorization_code + インメモリ）が動いてから段階的に足す

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
