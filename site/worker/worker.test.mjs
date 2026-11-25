// node site/worker/worker.test.mjs で回す。fetch を差し替え、上流へは出ない。
import assert from "node:assert/strict";
import worker from "./worker.mjs";

const calls = [];
globalThis.fetch = async (url) => {
  calls.push(url);
  if (url.endsWith("/rust-idp/ja")) {
    return new Response(null, { status: 301, headers: { location: "https://son-risa.github.io/rust-idp/ja/" } });
  }
  return new Response("x", { status: 200, headers: { "content-type": "text/html" } });
};
const get = (path, method = "GET") => worker.fetch(new Request("https://docs.amate.ai" + path, { method }));

let r = await get("/");
assert.equal(r.status, 404);
r = await get("/idpx/");
assert.equal(r.status, 404);
assert.equal(calls.length, 0);

r = await get("/idp?a=1");
assert.equal(r.status, 301);
assert.equal(r.headers.get("location"), "https://docs.amate.ai/idp/?a=1");

r = await get("/idp/?a=1");
assert.equal(r.status, 200);
assert.equal(calls.at(-1), "https://son-risa.github.io/rust-idp/?a=1");
assert.equal(r.headers.get("x-content-type-options"), "nosniff");

r = await get("/idp/ja");
assert.equal(r.status, 301);
assert.equal(r.headers.get("location"), "https://docs.amate.ai/idp/ja/");

r = await get("/idp/", "POST");
assert.equal(r.status, 405);

console.log("ok");
