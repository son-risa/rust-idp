// docs.amate.ai: /idp/ を rust-idp の GitHub Pages へ回す。ほかの道は置き場の頁。
const UPSTREAM = "https://son-risa.github.io/rust-idp";
const PREFIX = "/idp";

const PLACEHOLDER = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>docs.amate.ai</title>
<style>body{font:16px/1.6 system-ui,sans-serif;margin:0;padding:15vh 16px;color:#1f2328;background:#fff;text-align:center}
a{color:#0b6e63}@media (prefers-color-scheme:dark){body{color:#e6edf3;background:#0d1117}a{color:#5cc8b8}}</style></head>
<body><p>Nothing is published here yet.</p><p><a href="/idp/">rust-idp documentation</a></p></body></html>`;

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method Not Allowed", { status: 405, headers: { allow: "GET, HEAD" } });
    }
    if (url.pathname === PREFIX) {
      return Response.redirect(`${url.origin}${PREFIX}/${url.search}`, 301);
    }
    if (!url.pathname.startsWith(PREFIX + "/")) {
      return new Response(request.method === "HEAD" ? null : PLACEHOLDER, {
        status: 404,
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=300" },
      });
    }
    const upstream = UPSTREAM + url.pathname.slice(PREFIX.length) + url.search;
    const res = await fetch(upstream, { method: request.method, redirect: "manual" });
    const headers = new Headers(res.headers);
    const loc = headers.get("location");
    if (loc) {
      // Pages の末尾の / を足す転送などを、docs.amate.ai/idp の道へ書き換える。
      const target = new URL(loc, upstream);
      if (target.origin === "https://son-risa.github.io" && (target.pathname === "/rust-idp" || target.pathname.startsWith("/rust-idp/"))) {
        headers.set("location", `${url.origin}${PREFIX}${target.pathname.slice("/rust-idp".length)}${target.search}${target.hash}`);
      }
    }
    headers.set("x-content-type-options", "nosniff");
    headers.set("referrer-policy", "strict-origin-when-cross-origin");
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
  },
};
