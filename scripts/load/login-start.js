// staging に負荷を当てる k6 の script。.github/workflows/load-test.yml から回す。
//
// パスキーのログインは機械で回せないので、ログインの手前まで（discovery・jwks・PAR・authorize の 303・
// DPoP 付きの token の誤り応答）を 1 回の繰り返しとして回す。
//
// PHASE=cold: 1 要求だけ送り、止まっていた台が起きるまでの時間を測る。
// PHASE=warm: VUS 人が DURATION の間、繰り返しを回す。
//
// 合否のしきい値はこの file だけに置く。

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';
import encoding from 'k6/encoding';

const BASE = __ENV.BASE_URL;
const PHASE = __ENV.PHASE || 'warm';
const CLIENT_ID = 'demo-rp';
const REDIRECT_URI = 'https://test.sonrisa.co.jp/oidc/callback';
// RFC 7636 の付録 B の値。code は偽物なので verifier が合う必要は無い。
const CODE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

if (!BASE) {
  throw new Error('BASE_URL が要る');
}

const NAMES = ['par', 'authorize', 'token', 'discovery', 'jwks'];

const coldStart = new Trend('cold_start', true);
const rateLimited = new Counter('rate_limited');
const unexpected = new Rate('unexpected');

export const options =
  PHASE === 'cold'
    ? {
        vus: 1,
        iterations: 1,
        thresholds: { cold_start: ['max<3000'] },
      }
    : {
        scenarios: {
          warm: {
            executor: 'constant-vus',
            vus: Number(__ENV.VUS || 30),
            duration: __ENV.DURATION || '3m',
          },
        },
        thresholds: {
          // 認可（PAR・authorize）と token の応答。discovery・jwks は数えない。
          'http_req_duration{flow:yes}': ['p(95)<300', 'p(99)<1000'],
          unexpected: ['rate<0.01'],
          // 口ごとの数字を summary に出すための空の判定。
          ...Object.fromEntries(
            NAMES.flatMap((n) => [
              [`http_req_duration{name:${n}}`, []],
              [`http_reqs{name:${n}}`, []],
            ]),
          ),
        },
        summaryTrendStats: ['min', 'med', 'avg', 'p(90)', 'p(95)', 'p(99)', 'max'],
      };

function record(res, want) {
  if (res.status === 429) {
    // 回数の上限は正しい振る舞いとして、誤りとは分けて数える。
    rateLimited.add(1);
    return false;
  }
  const ok = res.status === want;
  unexpected.add(!ok);
  return ok;
}

let key = null;

async function dpopKey() {
  if (key === null) {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ]);
    const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    key = { priv: pair.privateKey, jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
  }
  return key;
}

function b64(obj) {
  return encoding.b64encode(JSON.stringify(obj), 'rawurl');
}

async function dpopProof(htu) {
  const k = await dpopKey();
  const input =
    b64({ typ: 'dpop+jwt', alg: 'ES256', jwk: k.jwk }) +
    '.' +
    b64({ htm: 'POST', htu, iat: Math.floor(Date.now() / 1000), jti: crypto.randomUUID() });
  // 文字列を bytes にする手が k6 に無いので、base64 を往復させる。
  const bytes = encoding.b64decode(encoding.b64encode(input, 'std'), 'std');
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k.priv, bytes);
  return input + '.' + encoding.b64encode(sig, 'rawurl');
}

function form(obj) {
  return Object.entries(obj)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
}

const FORM = { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } };

export default async function () {
  if (PHASE === 'cold') {
    const res = http.get(`${BASE}/.well-known/openid-configuration`, { tags: { name: 'discovery' } });
    coldStart.add(res.timings.duration);
    check(res, { 'cold: discovery 200': (r) => r.status === 200 });
    return;
  }

  const disc = http.get(`${BASE}/.well-known/openid-configuration`, { tags: { name: 'discovery' } });
  if (!record(disc, 200)) {
    sleep(1);
    return;
  }
  // DPoP の htu は issuer の側の URL（staging は前に別の名前が付いている）。
  const tokenHtu = disc.json('token_endpoint');
  record(http.get(`${BASE}/jwks`, { tags: { name: 'jwks' } }), 200);
  sleep(2);

  const par = http.post(
    `${BASE}/par`,
    form({
      client_id: CLIENT_ID,
      response_type: 'code',
      scope: 'openid',
      redirect_uri: REDIRECT_URI,
      state: crypto.randomUUID(),
      nonce: crypto.randomUUID(),
      code_challenge: CODE_CHALLENGE,
      code_challenge_method: 'S256',
    }),
    Object.assign({ tags: { name: 'par', flow: 'yes' } }, FORM),
  );
  if (!record(par, 201)) {
    sleep(1);
    return;
  }
  const requestUri = par.json('request_uri');

  const authz = http.get(
    `${BASE}/authorize?${form({ client_id: CLIENT_ID, request_uri: requestUri })}`,
    { redirects: 0, tags: { name: 'authorize', flow: 'yes' } },
  );
  record(authz, 303);
  // 人がパスキーを使う間。
  sleep(3);

  const tok = http.post(
    `${BASE}/token`,
    form({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      code: 'load-test-' + crypto.randomUUID(),
      redirect_uri: REDIRECT_URI,
      code_verifier: 'dBjftJeZ4CVP-mJ0n8nYhHqo6Hk5Ri7y8x5D7x0Yx9g',
    }),
    {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', DPoP: await dpopProof(tokenHtu) },
      tags: { name: 'token', flow: 'yes' },
    },
  );
  // 偽の code なので invalid_grant の 400 が正しい。DPoP の検証と code の引きは通る。
  if (tok.status === 400 && tok.json('error') !== 'invalid_grant') {
    unexpected.add(true);
  } else {
    record(tok, 400);
  }
  sleep(2);
}

function ms(v) {
  return v === undefined ? '-' : `${v.toFixed(0)} ms`;
}

export function handleSummary(data) {
  const m = data.metrics;
  const lines = [`## 負荷の試し（${PHASE}）`, ''];
  if (PHASE === 'cold') {
    lines.push(`- cold start（最初の要求）: ${ms(m.cold_start?.values.max)}`);
  } else {
    lines.push('| 口 | 数 | p50 | p95 | p99 | max |', '|---|---|---|---|---|---|');
    for (const name of NAMES) {
      const t = m[`http_req_duration{name:${name}}`];
      const c = m[`http_reqs{name:${name}}`];
      if (!t) continue;
      const v = t.values;
      lines.push(
        `| ${name} | ${c ? c.values.count : '-'} | ${ms(v.med)} | ${ms(v['p(95)'])} | ${ms(v['p(99)'])} | ${ms(v.max)} |`,
      );
    }
    const f = m['http_req_duration{flow:yes}'].values;
    lines.push(
      '',
      `- 認可・token の合計: p50 ${ms(f.med)}、p95 ${ms(f['p(95)'])}、p99 ${ms(f['p(99)'])}`,
      `- 要求の総数: ${m.http_reqs.values.count}`,
      `- 思わぬ応答の率: ${((m.unexpected?.values.rate ?? 0) * 100).toFixed(2)} %`,
      `- 429（回数の上限）: ${m.rate_limited ? m.rate_limited.values.count : 0}`,
    );
  }
  const failed = Object.entries(m)
    .filter(([, v]) => v.thresholds && Object.values(v.thresholds).some((t) => !t.ok))
    .map(([k]) => k);
  lines.push('', failed.length ? `**不合格**: ${failed.join(', ')}` : '**合格**', '');
  const md = lines.join('\n');
  return { stdout: md + '\n', [`summary-${PHASE}.md`]: md, [`summary-${PHASE}.json`]: JSON.stringify(data, null, 2) };
}
