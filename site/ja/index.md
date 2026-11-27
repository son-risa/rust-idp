---
template: home.html
hide:
  - footer
title: パスキーでログインする OpenID Provider
description: rust-idp は Rust 製の OSS の OpenID Provider。Cloud Run の 1 サービスで動き、守りの強さを client ごとに選べる。安全性の主張は、前提と一緒に公開している。
---

<header class="rh-hero">
  <p class="rh-eyebrow">rust-idp <span aria-hidden="true">·</span> Rust 製の OSS の OpenID Provider <a class="rh-lang" href="../" hreflang="en" lang="en">English</a></p>
  <h1>パスキーでログインする OpenID Provider</h1>
  <p class="rh-lead">Cloud Run の 1 サービスで動き、守りの強さを client ごとに選べる。安全性の主張は、前提と一緒に公開している。</p>
  <p class="rh-actions">
    <a class="rh-button rh-button--primary" href="get-started/">使い始める</a>
    <a class="rh-button" href="verification/">何を確かめているか</a>
    <a class="rh-button" href="https://github.com/son-risa/rust-idp">GitHub</a>
  </p>
  <ul class="rh-status" aria-label="状態">
    <li><code>v0.1.0</code></li>
    <li>本番 1 件で稼働中</li>
    <li>MIT License</li>
    <li>認定は未取得</li>
  </ul>
</header>

<section class="rh-section" aria-labelledby="usecases">
  <h2 id="usecases">ユースケース</h2>
  <div class="rh-grid rh-grid--3">
    <article class="rh-card">
      <h3>業務アプリにパスキーでログイン</h3>
      <p>マルチテナントの業務アプリの利用者が、合言葉なしでログインする。招待と登録のリンクは、アプリから送る。</p>
      <p class="rh-scope">いま。本番で動いている。</p>
    </article>
    <article class="rh-card">
      <h3>1 つの操作を、別の端末で承認</h3>
      <p>危ない操作の前に、利用者が自分の端末のパスキーで、その操作だけを承認する（CIBA と RAR）。</p>
      <p class="rh-scope">いま。適合試験は受けていない。</p>
    </article>
    <article class="rh-card">
      <h3>人や組織の代わりに動く AI エージェント</h3>
      <p>どのソフトウェアか、誰の代わりか、何をしてよいかを示すエージェントに、狭く短いトークンを渡す。</p>
      <p class="rh-scope">計画中。まだ実装していない。</p>
    </article>
  </div>
  <p class="rh-actions"><a class="rh-button" href="use-cases/">ユースケースと仕様の一覧</a></p>
</section>

<section class="rh-section" aria-labelledby="principles">
  <h2 id="principles">設計方針</h2>
  <div class="rh-grid rh-grid--3">
    <article class="rh-card">
      <h3>サーバレスで安価に動かす</h3>
      <p>Cloud Run の 1 サービスに、状態は Firestore、署名鍵は Cloud KMS。独自のドメインは Cloud Run に直に割り当てるので、LB も、自分で持つ仮想機械も、パスワードの DB も運用しない。</p>
      <p class="rh-gaveup"><span>諦めたこと</span>mTLS。送り主の束縛は DPoP で行い、TLS の終端は Google に任せる。</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/docs/zero-trust-assessment.md">docs/zero-trust-assessment.md</a></p>
    </article>
    <article class="rh-card">
      <h3>AI と書き、機械で確かめる</h3>
      <p>commit の多くは AI のコーディング支援と共著。それを信じてとは言わない。主張は「約束 Z は、攻撃者 X に対し、前提 Y の下で成り立つ」の形で書く。コードかモデルを触る PR ごとに Tamarin のモデルを回し、守りを 1 つ外した版は破れなければならない。</p>
      <p class="rh-gaveup"><span>諦めたこと</span>コードそのものの証明。モデルは手書きで、モデルとコードの一致は確かめていない。</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/docs/security-ladder.md">docs/security-ladder.md</a></p>
    </article>
    <article class="rh-card">
      <h3>規格の拡張に追従する</h3>
      <p>プロトコルの概念は 1 つずつ trait にして <code>Provider</code> に登録する。grant、client 認証、認可の検査、応答の返し方、署名、保存先。新しい規格は、多くの場合、作り直しでなく実装を 1 つ足すことになる。</p>
      <p class="rh-gaveup"><span>諦めたこと</span>幅。response_type は <code>code</code> だけ、<code>claims</code> パラメータは無し、<code>request_uri</code> は PAR 経由だけ。</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/src/provider.rs">src/provider.rs</a></p>
    </article>
  </div>
</section>

<section class="rh-section" aria-labelledby="features">
  <h2 id="features">特徴</h2>
  <div class="rh-grid rh-grid--3">
    <article class="rh-card rh-feature">
      <h3>サーバレス</h3>
      <p>要るのはマネージドのサービスだけ。Cloud Run・Firestore・Cloud KMS・Secret Manager と、メールの送り手。</p>
      <p class="rh-scope">範囲：GCP の実装だけ。mTLS は使わない。</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/src/gcp.rs">src/gcp.rs</a> <a href="https://github.com/son-risa/rust-idp/blob/main/Dockerfile">Dockerfile</a></p>
    </article>
    <article class="rh-card rh-feature">
      <h3>パスキー</h3>
      <p>パスワードを保存しない。ログインはパスキー（WebAuthn）。</p>
      <p class="rh-scope">範囲：登録と復旧はメール。通常のログインは UV を求めない。</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/src/web/login.rs">src/web/login.rs</a> <a href="https://github.com/son-risa/rust-idp/blob/main/src/web/recover.rs">src/web/recover.rs</a></p>
    </article>
    <article class="rh-card rh-feature">
      <h3>FAPI 2.0 の profile</h3>
      <p>private_key_jwt・PAR・PKCE・DPoP を client ごとに必須にできる。profile は管理者が決め、client の側からは弱められない。</p>
      <p class="rh-scope">範囲：サーバ全体は準拠ではない。弱い profile の client も受ける。</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/src/dcr.rs">src/dcr.rs</a></p>
    </article>
    <article class="rh-card rh-feature">
      <h3>CIBA</h3>
      <p>poll モード。承認はパスキーで、UV 必須。</p>
      <p class="rh-scope">範囲：ping・push は無い。適合試験は受けていない。</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/src/web/oidc.rs">src/web/oidc.rs</a> <a href="https://github.com/son-risa/rust-idp/blob/main/src/web/ciba.rs">src/web/ciba.rs</a></p>
    </article>
    <article class="rh-card rh-feature">
      <h3>適合試験</h3>
      <p>FIDO Alliance と OpenID Foundation の試験の道具を、開発の検査に使う。</p>
      <p class="rh-scope">範囲：認定は未取得。証跡は準備中。</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/docs/verification-map.md">docs/verification-map.md</a></p>
    </article>
    <article class="rh-card rh-feature">
      <h3>形式検証</h3>
      <p>Tamarin のモデル 14 本と、守りを外した 20 本。Kani のハーネス 9 本。</p>
      <p class="rh-scope">範囲：モデルは手書き。コード全体の証明ではない。</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/formal/expected.tsv">formal/expected.tsv</a> <a href="https://github.com/son-risa/rust-idp/blob/main/formal/kani-harnesses.txt">formal/kani-harnesses.txt</a></p>
    </article>
  </div>
</section>

<section class="rh-section" aria-labelledby="architecture">
  <h2 id="architecture">構成</h2>
  <figure class="rh-figure">
    <svg class="rh-diagram rh-diagram--wide" viewBox="0 0 720 400" role="img" aria-labelledby="arch-wide-title">
      <title id="arch-wide-title">ブラウザ、RP、承認の端末が、Cloud Run の 1 サービスを呼ぶ。中では axum の router が Provider に渡す。差し替えられる部品は client 認証、grant、保存先、署名、メールで、保存先は Firestore、署名は Cloud KMS、メールはメールの送り手を使う。</title>
      <g class="d-node">
        <rect x="10" y="40" width="170" height="64" rx="6"/>
        <text x="95" y="67" class="d-title">ブラウザ</text>
        <text x="95" y="87" class="d-sub">パスキーの認証器</text>
        <rect x="10" y="168" width="170" height="64" rx="6"/>
        <text x="95" y="195" class="d-title">RP</text>
        <text x="95" y="215" class="d-sub">Web やモバイルのアプリ</text>
        <rect x="10" y="296" width="170" height="64" rx="6"/>
        <text x="95" y="323" class="d-title">承認の端末</text>
        <text x="95" y="343" class="d-sub">CIBA。パスキーと UV</text>
      </g>
      <g class="d-edge">
        <path d="M180 72 H250"/><path d="M180 200 H250"/><path d="M180 328 H250"/>
      </g>
      <g class="d-label">
        <text x="215" y="64">認可</text>
        <text x="215" y="192">PAR · token</text>
        <text x="215" y="320">承認</text>
      </g>
      <rect class="d-frame" x="250" y="10" width="250" height="380" rx="8"/>
      <text x="375" y="36" class="d-title d-accent">Cloud Run · 1 サービス</text>
      <g class="d-node">
        <rect x="270" y="52" width="210" height="40" rx="5"/>
        <text x="375" y="77" class="d-sub">axum の router</text>
        <rect x="270" y="108" width="210" height="268" rx="5"/>
        <text x="375" y="130" class="d-title">Provider</text>
      </g>
      <g class="d-swap">
        <rect x="286" y="144" width="178" height="36" rx="4"/>
        <rect x="286" y="190" width="178" height="36" rx="4"/>
        <rect x="286" y="236" width="178" height="36" rx="4"/>
        <rect x="286" y="282" width="178" height="36" rx="4"/>
        <rect x="286" y="328" width="178" height="36" rx="4"/>
      </g>
      <g class="d-text">
        <text x="375" y="167">保存先（Store）</text>
        <text x="375" y="213">署名（Signer）</text>
        <text x="375" y="259">メール（Mailer）</text>
        <text x="375" y="305">client 認証</text>
        <text x="375" y="351">grant</text>
      </g>
      <g class="d-edge">
        <path d="M464 162 H560"/><path d="M464 208 H560"/><path d="M464 254 H560"/>
      </g>
      <g class="d-node">
        <rect x="560" y="140" width="150" height="44" rx="6"/>
        <text x="635" y="159" class="d-title">Firestore</text>
        <text x="635" y="175" class="d-sub">状態・単回の消費</text>
        <rect x="560" y="186" width="150" height="44" rx="6"/>
        <text x="635" y="205" class="d-title">Cloud KMS</text>
        <text x="635" y="221" class="d-sub">署名鍵</text>
        <rect x="560" y="232" width="150" height="44" rx="6"/>
        <text x="635" y="251" class="d-title">メール</text>
        <text x="635" y="267" class="d-sub">登録・復旧</text>
      </g>
      <g class="d-legend">
        <rect class="d-swap-key" x="560" y="330" width="28" height="16" rx="3"/>
        <text x="596" y="343">差し替えられる（trait）</text>
      </g>
    </svg>
    <svg class="rh-diagram rh-diagram--tall" viewBox="0 0 340 540" role="img" aria-labelledby="arch-tall-title">
      <title id="arch-tall-title">ブラウザ、RP、承認の端末が、Cloud Run の 1 サービスを呼ぶ。中では axum の router が Provider に渡す。差し替えられる部品は、保存先（Firestore）、署名（Cloud KMS）、メール、client 認証、grant。</title>
      <g class="d-node">
        <rect x="4" y="8" width="104" height="56" rx="6"/>
        <text x="56" y="32" class="d-title">ブラウザ</text>
        <text x="56" y="50" class="d-sub">パスキー</text>
        <rect x="118" y="8" width="104" height="56" rx="6"/>
        <text x="170" y="32" class="d-title">RP</text>
        <text x="170" y="50" class="d-sub">アプリ</text>
        <rect x="232" y="8" width="104" height="56" rx="6"/>
        <text x="284" y="32" class="d-title">承認の端末</text>
        <text x="284" y="50" class="d-sub">CIBA</text>
      </g>
      <g class="d-edge">
        <path d="M56 64 V96"/><path d="M170 64 V96"/><path d="M284 64 V96"/>
      </g>
      <rect class="d-frame" x="4" y="96" width="332" height="384" rx="8"/>
      <text x="170" y="122" class="d-title d-accent">Cloud Run · 1 サービス</text>
      <g class="d-node">
        <rect x="20" y="136" width="300" height="36" rx="5"/>
        <text x="170" y="159" class="d-sub">axum の router</text>
        <rect x="20" y="184" width="300" height="282" rx="5"/>
        <text x="170" y="206" class="d-title">Provider</text>
      </g>
      <g class="d-swap">
        <rect x="36" y="218" width="268" height="40" rx="4"/>
        <rect x="36" y="266" width="268" height="40" rx="4"/>
        <rect x="36" y="314" width="268" height="40" rx="4"/>
        <rect x="36" y="362" width="268" height="40" rx="4"/>
        <rect x="36" y="410" width="268" height="40" rx="4"/>
      </g>
      <g class="d-text">
        <text x="170" y="243">保存先 → Firestore</text>
        <text x="170" y="291">署名 → Cloud KMS</text>
        <text x="170" y="339">メール → メールの送り手</text>
        <text x="170" y="387">client 認証</text>
        <text x="170" y="435">grant</text>
      </g>
      <g class="d-legend">
        <rect class="d-swap-key" x="70" y="504" width="28" height="16" rx="3"/>
        <text x="106" y="517">差し替えられる（trait）</text>
      </g>
    </svg>
    <figcaption>描いていないもの（無いため）：LB、自分で持つ仮想機械、パスワードの DB。</figcaption>
  </figure>
</section>

<section class="rh-section" aria-labelledby="verified">
  <h2 id="verified">何を確かめていて、何を確かめていないか</h2>
  <div class="rh-scroll">
    <table>
      <thead><tr><th>確かめ方</th><th>対象</th><th>見ないもの</th></tr></thead>
      <tbody>
        <tr><td>Tamarin</td><td>プロトコルのモデル 14 本。守りを 1 つ外した 20 本は破れることを確かめる</td><td>コードとモデルの一致</td></tr>
        <tr><td>Kani</td><td>ハーネス 9 本（バイト列の解析、PKCE の格下げ、redirect の完全一致など）</td><td>残りのコード</td></tr>
        <tr><td>試験と適合試験の道具</td><td>外から見える振る舞い</td><td>適合試験の道具を当てていない client の形</td></tr>
        <tr><td>前提の台帳</td><td>前提 56 件。33 件は守る試験の名前を持ち、23 件は試験にできない理由を書く</td><td>試験にできない前提が、運用で成り立っているか</td></tr>
      </tbody>
    </table>
  </div>
  <p>どのモデルが当てはまるかは、client の profile で変わる。</p>
  <div class="rh-scroll">
    <table>
      <thead><tr><th>client の profile</th><th>認証 / PAR / token</th><th>Tamarin のモデル</th><th>適合試験</th><th>本番</th></tr></thead>
      <tbody>
        <tr><td><code>Public</code></td><td>none / なし / DPoP</td><td>認可コード + PKCE、DPoP、ID token、合成 #8</td><td>無い</td><td>試し用の RP だけ</td></tr>
        <tr class="rh-row-mark"><td><code>ConfidentialSecret</code></td><td>client_secret_basic / なし / Bearer</td><td>合成 #11。示せない性質（盗まれた Bearer の token は使える）も載せる</td><td>無い</td><td>主な RP</td></tr>
        <tr><td><code>ConfidentialKey</code>（FAPI 2.0 の形）</td><td>private_key_jwt / 必須 / DPoP</td><td>#1、#2、#5、合成 #6。PAR はどのモデルにも無い</td><td>FAPI 2.0 の試験計画。記録は未公開</td><td>0 件</td></tr>
        <tr><td>CIBA</td><td>client_secret_basic / — / Bearer</td><td>#3（束縛、単回）</td><td>無い</td><td>RP 1 件</td></tr>
      </tbody>
    </table>
  </div>
  <p class="rh-src">全体の表：<a href="https://github.com/son-risa/rust-idp/blob/main/docs/verification-map.md">docs/verification-map.md</a> · 前提：<a href="https://github.com/son-risa/rust-idp/blob/main/formal/premises.json">formal/premises.json</a></p>
</section>

<section class="rh-section" aria-labelledby="start">
  <h2 id="start">使い始める</h2>
  <div class="rh-grid rh-grid--2">
    <article class="rh-card">
      <h3>ライブラリとして組む</h3>
      <p><code>rust_idp::Provider</code> を組み、<code>rust_idp::router</code> で axum の <code>Router</code> にする。既定はメモリ上の保存先と、起動ごとに作る鍵。</p>
      <pre><code>cargo run --example in_memory</code></pre>
      <p class="rh-scope">パスキーのログイン、PAR、動的な client 登録は <code>gcp</code> の feature が要る。利用者の保存先が Firestore にしか無いため。</p>
    </article>
    <article class="rh-card">
      <h3>Cloud Run に置く</h3>
      <p>Dockerfile が <code>gcp</code> の feature 付きで本番の binary を作る。build は Cloud Build が行うので、手元の Docker は要らない。</p>
      <pre><code>gcloud run deploy &lt;service&gt; --source . --region &lt;region&gt;</code></pre>
      <p class="rh-scope">Firestore、ES256 と RS256 の署名鍵（Cloud KMS か、代わりに Secret Manager）、実行用のサービスアカウントが要る。署名鍵を読めなければ起動しない。</p>
    </article>
  </div>
  <p><a href="get-started/">手順を詳しく見る</a></p>
</section>

<section class="rh-section" aria-labelledby="extend">
  <h2 id="extend">拡張の方式</h2>
  <p>差し替えられる部品は、どれも公開の trait。自分の実装を <code>Provider</code> に登録する。</p>
  <div class="rh-scroll">
    <table>
      <thead><tr><th>trait</th><th>決めること</th><th>同梱の実装</th></tr></thead>
      <tbody>
        <tr><td><code>Store</code></td><td>セッション・コード・token の保存</td><td>メモリ、Firestore</td></tr>
        <tr><td><code>JwsSigner</code></td><td>ID token と JWS の署名</td><td>ES256、RS256、Cloud KMS</td></tr>
        <tr><td><code>Mailer</code></td><td>登録と復旧のメール</td><td>記録に出すだけ、Resend</td></tr>
        <tr><td><code>ClientAuthMethod</code></td><td>token endpoint での client 認証</td><td>none、client_secret_basic、private_key_jwt</td></tr>
        <tr><td><code>GrantHandler</code></td><td>grant_type ごとの token の発行</td><td>authorization_code、refresh_token、CIBA</td></tr>
        <tr><td><code>AuthorizationCheck</code></td><td><code>/authorize</code> の検査（順序つき）</td><td>response_type、scope、PKCE</td></tr>
        <tr><td><code>ResponseMode</code></td><td>認可の応答の返し方</td><td>query</td></tr>
        <tr><td><code>DpopVerifier</code></td><td>DPoP の proof の検査</td><td>ES256（jti はメモリか Firestore に持つ）</td></tr>
        <tr><td><code>CibaStore</code></td><td>CIBA の要求の保存</td><td>メモリ、Firestore</td></tr>
      </tbody>
    </table>
  </div>
  <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/src/lib.rs">src/lib.rs</a></p>
</section>

<section class="rh-section" aria-labelledby="nongoals">
  <h2 id="nongoals">やらないこと</h2>
  <ul class="rh-list">
    <li>パスワードでのログイン。</li>
    <li>mTLS の client 認証と、証明書に束縛した token（RFC 8705）。</li>
    <li>CIBA の ping・push のモードと、<code>user_code</code>。</li>
    <li><code>code</code> 以外の response_type と、要求の <code>claims</code> パラメータ。</li>
    <li>PAR 以外からの <code>request_uri</code>。</li>
    <li>GCP 以外の保存先・署名・メールの実装。上の trait で自分で書ける。</li>
  </ul>
  <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/src/web/oidc.rs">src/web/oidc.rs</a>（discovery の文書）</p>
</section>

<section class="rh-section" aria-labelledby="status">
  <h2 id="status">状態と今後</h2>
  <ul class="rh-list">
    <li>版は 0.1.0。API は変わりうる。crates.io にはまだ出していない。</li>
    <li>本番 1 件で稼働中。その主な RP は、まだ <code>client_secret_basic</code> を使う。</li>
    <li>次：適合試験の証跡（試験計画、実施日、suite の版、対象の commit）を公開する。主な RP を <code>private_key_jwt</code> へ移す。登録された client 認証の方式だけを受けるようにする。</li>
  </ul>
</section>
