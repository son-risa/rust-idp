# 検証

rust-idp は、安全性の主張を「約束 Z は、攻撃者 X に対し、前提 Y の下で成り立つ」の形で書き、それを確かめられる層で確かめる。この頁は、各層が何を見て、何を見ないかを書く。

## 層

| 確かめ方 | 対象 | 見ないもの |
|---|---|---|
| Tamarin | プロトコルのモデル 13 本。守りを 1 つ外した 19 本は、破れることを確かめる | コードとモデルの一致 |
| Kani | コードの 9 関数 | 残りのコード |
| 試験 | 外から見える振る舞いと、試験にできる前提 | 試験にできない前提 |
| 適合試験の道具 | FIDO Alliance のサーバの試験は `/fido` の面に、OpenID Foundation の FAPI 2.0 の試験は FAPI 2.0 の形の client に当てる | ほかの client の形。本番のログインは `/fido` とは別の経路 |

コードかモデルを触る PR ごとに、Tamarin の結果を期待表と照らし、違えば赤にする。Kani のハーネスも一覧と同じように照らす。どちらも `main` への merge に必須の検査。

## 前提

前提の台帳は 44 件。25 件は、守る試験の名前を持つ。19 件は試験にできず、その理由を書く（例：「token endpoint への通信路はサーバ認証の TLS」）。

## client の profile ごと

検証の結果が何を意味するかは、client の profile で変わる。lemma の名前と前提の ID まで載せた表は[検証の地図](https://github.com/son-risa/rust-idp/blob/main/docs/verification-map.md)にある。

| client の profile | 認証 / PAR / token | Tamarin のモデル | 適合試験 | 本番 |
|---|---|---|---|---|
| `Public` | none / なし / DPoP | 認可コード + PKCE、DPoP、ID token、合成 #8 | 無い | 試し用の RP だけ |
| `ConfidentialSecret` | client_secret_basic / なし / Bearer | 合成 #11。示せない性質（盗まれた Bearer の token は使える）も載せる | 無い | 主な RP |
| `ConfidentialKey`（FAPI 2.0 の形） | private_key_jwt / 必須 / DPoP | #1、#2、#5、合成 #6。PAR はどのモデルにも無い | FAPI 2.0 の試験計画。記録は未公開 | 0 件 |
| CIBA | client_secret_basic / — / Bearer | #3（束縛、単回） | 無い | RP 1 件 |

## 認定は取っていない

OpenID Foundation と FIDO Alliance の認定は取っていない。適合試験の道具は、開発の検査として使う。証跡（試験計画の ID、実施日、suite の版、対象の commit）は準備中で、リポジトリに置く。

## 根拠

- [formal/expected.tsv](https://github.com/son-risa/rust-idp/blob/main/formal/expected.tsv)：モデルと lemma ごとの期待する結果
- [formal/kani-harnesses.txt](https://github.com/son-risa/rust-idp/blob/main/formal/kani-harnesses.txt)：Kani のハーネス 9 本
- [formal/premises.json](https://github.com/son-risa/rust-idp/blob/main/formal/premises.json)：前提の台帳
- [.github/workflows/formal.yml](https://github.com/son-risa/rust-idp/blob/main/.github/workflows/formal.yml)：CI の job
