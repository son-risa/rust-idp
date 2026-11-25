# docs.amate.ai の Worker

`docs.amate.ai/idp/` を、GitHub Pages の紹介サイト（`son-risa.github.io/rust-idp`）へ回す Cloudflare Worker。ほかの道は 404 の置き場の頁を返す。

- `worker.mjs`: Worker の本体。`/idp` は `/idp/` へ 301。Pages が返す `/rust-idp/...` への転送は `/idp/...` に書き換える。GET と HEAD 以外は 405。
- `worker.test.mjs`: `node site/worker/worker.test.mjs` で回す。上流へは出ない。
- `deploy.sh`: 試験を回してから、Worker `docs-amate-ai` を上げる。`CLOUDFLARE_API_TOKEN` と `CLOUDFLARE_ACCOUNT_ID` が要る。

Cloudflare の側で一度だけ設定したもの（この repo からは変えない）:

- route `docs.amate.ai/*` → Worker `docs-amate-ai`
- DNS: `docs.amate.ai` の AAAA `100::`（proxied）。Worker だけで答えるための名前で、`*.amate.ai` の wildcard より優先される。

GitHub Pages の側は、repo の変数 `SITE_URL=https://docs.amate.ai/idp/` で canonical を合わせている。
