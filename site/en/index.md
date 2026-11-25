---
template: home.html
hide:
  - footer
title: A passkey-first OpenID Provider in Rust
description: rust-idp is an open-source OpenID Provider in Rust. It runs as a single Cloud Run service, lets you choose how strict each client must be, and publishes every security claim with the assumptions behind it.
---

<header class="rh-hero">
  <p class="rh-eyebrow">rust-idp <span aria-hidden="true">·</span> open-source OpenID Provider <a class="rh-lang" href="ja/" hreflang="ja" lang="ja">日本語</a></p>
  <h1>A passkey-first OpenID Provider in Rust</h1>
  <p class="rh-lead">Runs as a single Cloud Run service. You choose how strict each client must be. Every security claim is published together with the assumptions it rests on.</p>
  <p class="rh-actions">
    <a class="rh-button rh-button--primary" href="get-started/">Get started</a>
    <a class="rh-button" href="verification/">What we verify</a>
    <a class="rh-button" href="https://github.com/son-risa/rust-idp">GitHub</a>
  </p>
  <ul class="rh-status" aria-label="Project status">
    <li><code>v0.1.0</code></li>
    <li>Running in one production deployment</li>
    <li>MIT License</li>
    <li>Not certified</li>
  </ul>
</header>

<section class="rh-section" aria-labelledby="principles">
  <h2 id="principles">Design principles</h2>
  <div class="rh-grid rh-grid--3">
    <article class="rh-card">
      <h3>Serverless and inexpensive</h3>
      <p>One Cloud Run service, Firestore for state and Cloud KMS for signing keys. The custom domain is mapped straight to Cloud Run, so there is no load balancer, no virtual machine of your own and no password database to operate.</p>
      <p class="rh-gaveup"><span>Gave up</span> mTLS. Sender-constraining is done with DPoP, and TLS terminates at Google.</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/docs/zero-trust-assessment.md">docs/zero-trust-assessment.md</a></p>
    </article>
    <article class="rh-card">
      <h3>Written with AI, checked by machines</h3>
      <p>Most commits are co-written with an AI coding agent. We do not ask you to trust that. Each claim is stated as "promise Z holds against attacker X under premises Y". Protocol models run in Tamarin on every pull request that touches the code or the models, and versions with one defence removed must break.</p>
      <p class="rh-gaveup"><span>Gave up</span> proving the code itself. The models are written by hand, and the gap between model and code is not verified.</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/docs/security-ladder.md">docs/security-ladder.md</a></p>
    </article>
    <article class="rh-card">
      <h3>Keeping up with the standards</h3>
      <p>Each protocol concept is a trait registered on the <code>Provider</code>: grants, client authentication, authorization checks, response modes, signers and stores. A new specification usually means a new implementation, not a rewrite.</p>
      <p class="rh-gaveup"><span>Gave up</span> breadth. Only the <code>code</code> response type, no <code>claims</code> parameter, and <code>request_uri</code> only through PAR.</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/src/provider.rs">src/provider.rs</a></p>
    </article>
  </div>
</section>

<section class="rh-section" aria-labelledby="features">
  <h2 id="features">Features</h2>
  <div class="rh-grid rh-grid--3">
    <article class="rh-card rh-feature">
      <h3>Serverless</h3>
      <p>Needs only managed services: Cloud Run, Firestore, Cloud KMS and Secret Manager, plus an email sender.</p>
      <p class="rh-scope">Scope: only the GCP backends are implemented. No mTLS.</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/src/gcp.rs">src/gcp.rs</a> <a href="https://github.com/son-risa/rust-idp/blob/main/Dockerfile">Dockerfile</a></p>
    </article>
    <article class="rh-card rh-feature">
      <h3>Passkeys</h3>
      <p>No passwords are stored. Users sign in with a passkey (WebAuthn).</p>
      <p class="rh-scope">Scope: sign-up and recovery go through email. Everyday sign-in does not require user verification.</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/src/web/login.rs">src/web/login.rs</a> <a href="https://github.com/son-risa/rust-idp/blob/main/src/web/recover.rs">src/web/recover.rs</a></p>
    </article>
    <article class="rh-card rh-feature">
      <h3>FAPI 2.0 client profile</h3>
      <p>private_key_jwt, PAR, PKCE and DPoP can be made mandatory per client. The admin picks the profile; a client cannot weaken it.</p>
      <p class="rh-scope">Scope: the server as a whole is not FAPI 2.0 conformant. Weaker profiles are also accepted.</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/src/dcr.rs">src/dcr.rs</a></p>
    </article>
    <article class="rh-card rh-feature">
      <h3>CIBA</h3>
      <p>Poll mode. Approval is a passkey with user verification required.</p>
      <p class="rh-scope">Scope: no ping or push mode. Not conformance-tested.</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/src/web/oidc.rs">src/web/oidc.rs</a> <a href="https://github.com/son-risa/rust-idp/blob/main/src/web/ciba.rs">src/web/ciba.rs</a></p>
    </article>
    <article class="rh-card rh-feature">
      <h3>Conformance tools</h3>
      <p>The FIDO Alliance and OpenID Foundation test tools are used as development checks.</p>
      <p class="rh-scope">Scope: not certified. Test evidence is being prepared.</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/docs/verification-map.md">docs/verification-map.md</a></p>
    </article>
    <article class="rh-card rh-feature">
      <h3>Formal verification</h3>
      <p>13 Tamarin models, plus 19 variants with a defence removed. 9 Kani harnesses.</p>
      <p class="rh-scope">Scope: the models are hand-written. This is not a proof of the whole code base.</p>
      <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/formal/expected.tsv">formal/expected.tsv</a> <a href="https://github.com/son-risa/rust-idp/blob/main/formal/kani-harnesses.txt">formal/kani-harnesses.txt</a></p>
    </article>
  </div>
</section>

<section class="rh-section" aria-labelledby="architecture">
  <h2 id="architecture">Architecture</h2>
  <figure class="rh-figure">
    <svg class="rh-diagram rh-diagram--wide" viewBox="0 0 720 400" role="img" aria-labelledby="arch-wide-title">
      <title id="arch-wide-title">Browsers, relying parties and approval devices call one Cloud Run service. Inside it, the axum router hands requests to the Provider, whose replaceable parts are client authentication, grants, store, signer and mailer. The store uses Firestore, the signer Cloud KMS, and the mailer an email service.</title>
      <g class="d-node">
        <rect x="10" y="40" width="170" height="64" rx="6"/>
        <text x="95" y="67" class="d-title">Browser</text>
        <text x="95" y="87" class="d-sub">passkey authenticator</text>
        <rect x="10" y="168" width="170" height="64" rx="6"/>
        <text x="95" y="195" class="d-title">Relying party</text>
        <text x="95" y="215" class="d-sub">your web or mobile app</text>
        <rect x="10" y="296" width="170" height="64" rx="6"/>
        <text x="95" y="323" class="d-title">Approval device</text>
        <text x="95" y="343" class="d-sub">CIBA, passkey with UV</text>
      </g>
      <g class="d-edge">
        <path d="M180 72 H250"/><path d="M180 200 H250"/><path d="M180 328 H250"/>
      </g>
      <g class="d-label">
        <text x="215" y="64">authorize</text>
        <text x="215" y="192">PAR · token</text>
        <text x="215" y="320">approve</text>
      </g>
      <rect class="d-frame" x="250" y="10" width="250" height="380" rx="8"/>
      <text x="375" y="36" class="d-title d-accent">Cloud Run · one service</text>
      <g class="d-node">
        <rect x="270" y="52" width="210" height="40" rx="5"/>
        <text x="375" y="77" class="d-sub">axum router</text>
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
        <text x="375" y="167">Store</text>
        <text x="375" y="213">Signer</text>
        <text x="375" y="259">Mailer</text>
        <text x="375" y="305">Client authentication</text>
        <text x="375" y="351">Grants</text>
      </g>
      <g class="d-edge">
        <path d="M464 162 H560"/><path d="M464 208 H560"/><path d="M464 254 H560"/>
      </g>
      <g class="d-node">
        <rect x="560" y="140" width="150" height="44" rx="6"/>
        <text x="635" y="159" class="d-title">Firestore</text>
        <text x="635" y="175" class="d-sub">state, single use</text>
        <rect x="560" y="186" width="150" height="44" rx="6"/>
        <text x="635" y="205" class="d-title">Cloud KMS</text>
        <text x="635" y="221" class="d-sub">signing keys</text>
        <rect x="560" y="232" width="150" height="44" rx="6"/>
        <text x="635" y="251" class="d-title">Email</text>
        <text x="635" y="267" class="d-sub">sign-up, recovery</text>
      </g>
      <g class="d-legend">
        <rect class="d-swap-key" x="560" y="330" width="28" height="16" rx="3"/>
        <text x="596" y="343">replaceable (trait)</text>
      </g>
    </svg>
    <svg class="rh-diagram rh-diagram--tall" viewBox="0 0 340 540" role="img" aria-labelledby="arch-tall-title">
      <title id="arch-tall-title">Browsers, relying parties and approval devices call one Cloud Run service. Inside it, the axum router hands requests to the Provider, whose replaceable parts are store (Firestore), signer (Cloud KMS), mailer (email), client authentication and grants.</title>
      <g class="d-node">
        <rect x="4" y="8" width="104" height="56" rx="6"/>
        <text x="56" y="32" class="d-title">Browser</text>
        <text x="56" y="50" class="d-sub">passkey</text>
        <rect x="118" y="8" width="104" height="56" rx="6"/>
        <text x="170" y="32" class="d-title">RP</text>
        <text x="170" y="50" class="d-sub">your app</text>
        <rect x="232" y="8" width="104" height="56" rx="6"/>
        <text x="284" y="32" class="d-title">Approver</text>
        <text x="284" y="50" class="d-sub">CIBA</text>
      </g>
      <g class="d-edge">
        <path d="M56 64 V96"/><path d="M170 64 V96"/><path d="M284 64 V96"/>
      </g>
      <rect class="d-frame" x="4" y="96" width="332" height="384" rx="8"/>
      <text x="170" y="122" class="d-title d-accent">Cloud Run · one service</text>
      <g class="d-node">
        <rect x="20" y="136" width="300" height="36" rx="5"/>
        <text x="170" y="159" class="d-sub">axum router</text>
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
        <text x="170" y="243">Store → Firestore</text>
        <text x="170" y="291">Signer → Cloud KMS</text>
        <text x="170" y="339">Mailer → email</text>
        <text x="170" y="387">Client authentication</text>
        <text x="170" y="435">Grants</text>
      </g>
      <g class="d-legend">
        <rect class="d-swap-key" x="80" y="504" width="28" height="16" rx="3"/>
        <text x="116" y="517">replaceable (trait)</text>
      </g>
    </svg>
    <figcaption>Not in the picture, because they do not exist: a load balancer, a virtual machine of your own, a password database.</figcaption>
  </figure>
</section>

<section class="rh-section" aria-labelledby="verified">
  <h2 id="verified">What is verified, and what is not</h2>
  <div class="rh-scroll">
    <table>
      <thead><tr><th>Method</th><th>Covers</th><th>Does not cover</th></tr></thead>
      <tbody>
        <tr><td>Tamarin</td><td>13 protocol models; 19 variants with one defence removed must be falsified</td><td>Whether the code matches the models</td></tr>
        <tr><td>Kani</td><td>9 harnesses (byte parsing, PKCE downgrade, exact redirect match, and others)</td><td>The rest of the code</td></tr>
        <tr><td>Tests and conformance tools</td><td>Externally visible behaviour</td><td>Client shapes the conformance tools were not run against</td></tr>
        <tr><td>Premise ledger</td><td>44 premises; 25 name a guarding test, 19 cannot be tested and say why</td><td>Whether the untestable premises hold in operation</td></tr>
      </tbody>
    </table>
  </div>
  <p>Which models apply depends on the client profile:</p>
  <div class="rh-scroll">
    <table>
      <thead><tr><th>Client profile</th><th>Auth / PAR / token</th><th>Tamarin models</th><th>Conformance-tested</th><th>In production</th></tr></thead>
      <tbody>
        <tr><td><code>Public</code></td><td>none / no / DPoP</td><td>code + PKCE, DPoP, ID token, composition #8</td><td>No</td><td>Test RPs only</td></tr>
        <tr class="rh-row-mark"><td><code>ConfidentialSecret</code></td><td>client_secret_basic / no / Bearer</td><td>composition #11. Also states what cannot hold: a stolen Bearer token is usable</td><td>No</td><td>Main RP</td></tr>
        <tr><td><code>ConfidentialKey</code> (FAPI 2.0 shape)</td><td>private_key_jwt / yes / DPoP</td><td>#1, #2, #5, composition #6. PAR is in no model</td><td>FAPI 2.0 test plan; records not yet published</td><td>None</td></tr>
        <tr><td>CIBA</td><td>client_secret_basic / — / Bearer</td><td>#3 (binding, single use)</td><td>No</td><td>One RP</td></tr>
      </tbody>
    </table>
  </div>
  <p class="rh-src">Full table: <a href="https://github.com/son-risa/rust-idp/blob/main/docs/verification-map.md">docs/verification-map.md</a> · premises: <a href="https://github.com/son-risa/rust-idp/blob/main/formal/premises.json">formal/premises.json</a></p>
</section>

<section class="rh-section" aria-labelledby="start">
  <h2 id="start">Get started</h2>
  <div class="rh-grid rh-grid--2">
    <article class="rh-card">
      <h3>Embed it as a library</h3>
      <p>Build a <code>rust_idp::Provider</code> and turn it into an axum <code>Router</code> with <code>rust_idp::router</code>. The default uses in-memory storage and a key generated at start-up.</p>
      <pre><code>cargo run --example in_memory</code></pre>
      <p class="rh-scope">Passkey sign-in, PAR and dynamic registration need the <code>gcp</code> feature, because users live in Firestore.</p>
    </article>
    <article class="rh-card">
      <h3>Deploy it to Cloud Run</h3>
      <p>The Dockerfile builds the production binary with the <code>gcp</code> feature. Cloud Build builds it; no local Docker is needed.</p>
      <pre><code>gcloud run deploy &lt;service&gt; --source . --region &lt;region&gt;</code></pre>
      <p class="rh-scope">Needs Firestore, ES256 and RS256 signing keys (Cloud KMS, or Secret Manager as a fallback) and a runtime service account. Without a signing key, the binary refuses to start.</p>
    </article>
  </div>
  <p><a href="get-started/">Step-by-step guide</a></p>
</section>

<section class="rh-section" aria-labelledby="extend">
  <h2 id="extend">Extending it</h2>
  <p>Every replaceable part is a public trait. Register your own implementation on the <code>Provider</code>.</p>
  <div class="rh-scroll">
    <table>
      <thead><tr><th>Trait</th><th>What it decides</th><th>Bundled</th></tr></thead>
      <tbody>
        <tr><td><code>Store</code></td><td>Sessions, codes and tokens</td><td>memory, Firestore</td></tr>
        <tr><td><code>JwsSigner</code></td><td>ID token and JWS signing</td><td>ES256, RS256, Cloud KMS</td></tr>
        <tr><td><code>Mailer</code></td><td>Sign-up and recovery mail</td><td>log only, Resend</td></tr>
        <tr><td><code>ClientAuthMethod</code></td><td>Client authentication at the token endpoint</td><td>none, client_secret_basic, private_key_jwt</td></tr>
        <tr><td><code>GrantHandler</code></td><td>Token issuance per grant type</td><td>authorization_code, refresh_token, CIBA</td></tr>
        <tr><td><code>AuthorizationCheck</code></td><td>Ordered checks on <code>/authorize</code></td><td>response_type, scope, PKCE</td></tr>
        <tr><td><code>ResponseMode</code></td><td>How the authorization response is returned</td><td>query</td></tr>
        <tr><td><code>DpopVerifier</code></td><td>DPoP proof checks</td><td>ES256 (jti kept in memory or Firestore)</td></tr>
        <tr><td><code>CibaStore</code></td><td>Pending CIBA requests</td><td>memory, Firestore</td></tr>
      </tbody>
    </table>
  </div>
  <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/src/lib.rs">src/lib.rs</a></p>
</section>

<section class="rh-section" aria-labelledby="nongoals">
  <h2 id="nongoals">What it does not do</h2>
  <ul class="rh-list">
    <li>Password sign-in.</li>
    <li>mTLS client authentication and certificate-bound tokens (RFC 8705).</li>
    <li>CIBA ping and push modes, and <code>user_code</code>.</li>
    <li>Response types other than <code>code</code>, and the <code>claims</code> request parameter.</li>
    <li><code>request_uri</code> from anywhere but PAR.</li>
    <li>Storage, signing or mail backends outside GCP. You can write your own through the traits above.</li>
  </ul>
  <p class="rh-src"><a href="https://github.com/son-risa/rust-idp/blob/main/src/web/oidc.rs">src/web/oidc.rs</a> (discovery document)</p>
</section>

<section class="rh-section" aria-labelledby="status">
  <h2 id="status">Status and next steps</h2>
  <ul class="rh-list">
    <li>Version 0.1.0. The API may change. Not yet published on crates.io.</li>
    <li>Runs one production deployment. Its main relying party still uses <code>client_secret_basic</code>.</li>
    <li>Next: publish conformance evidence (test plan, date, suite version, commit), move the main relying party to <code>private_key_jwt</code>, and accept only the registered client authentication method.</li>
  </ul>
</section>
