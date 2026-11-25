# 設計の文書

設計の詳しい文書はリポジトリにある。このサイトの主張の根拠は、これらの文書にある。

| 文書 | 内容 |
|---|---|
| [検証の地図](https://github.com/son-risa/rust-idp/blob/main/docs/verification-map.md) | client の profile ごとに、当てはまる Tamarin のモデル、適合試験、前提を並べる |
| [認証セキュリティの梯子](https://github.com/son-risa/rust-idp/blob/main/docs/security-ladder.md) | 脅威のモデルを段ごとに。各機構がどの攻撃者に答えるか |
| [Zero Trust の自己評価と前提の台帳](https://github.com/son-risa/rust-idp/blob/main/docs/zero-trust-assessment.md) | 自己評価と、安全性が頼っている前提の一覧 |
| [暗号の前提](https://github.com/son-risa/rust-idp/blob/main/docs/crypto-assumptions.md) | 暗号のライブラリに置いている前提 |
| [経路の一覧](https://github.com/son-risa/rust-idp/blob/main/docs/routes.md) | HTTP の経路の全部。router と試験で照らしている |
| [形式検証](https://github.com/son-risa/rust-idp/blob/main/formal/README.md) | Tamarin のモデルと Kani のハーネス。結果と限界 |
| [前提の台帳](https://github.com/son-risa/rust-idp/blob/main/formal/premises.json) | 前提ごとに、担保するコード・試験、または試験にできない理由 |

API の文書は、crate を出した後に docs.rs に置く。
