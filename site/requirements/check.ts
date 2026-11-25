// 7 覧のデータを確かめる。食い違いが 1 つでもあれば 1 で終わる。
// node site/requirements/check.ts [--lists data/lists.json] [--steps data/steps.json] [--config data/config.json] [--routes docs/routes.md]
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

type Json = Record<string, any>;

const HERE = dirname(fileURLToPath(import.meta.url));
const { values } = parseArgs({
  options: {
    lists: { type: "string", default: join(HERE, "data/lists.json") },
    steps: { type: "string", default: join(HERE, "data/steps.json") },
    config: { type: "string", default: join(HERE, "data/config.json") },
    routes: { type: "string", default: join(HERE, "../../docs/routes.md") },
  },
});
const read = (f: string): any => JSON.parse(readFileSync(f, "utf8"));
const L: Json = read(values.lists!);
const TJ: Json[] = read(values.steps!);
const CFG: Json = read(values.config!);

const errors: string[] = [];
const fail = (msg: string): void => {
  errors.push(msg);
};
const unique = (name: string, ids: string[]): Set<string> => {
  const seen = new Set<string>();
  for (const id of ids) {
    if (seen.has(id)) fail(`${name}: ${id} が 2 度ある`);
    seen.add(id);
  }
  return seen;
};
const mustHave = (where: string, set: Set<string>, id: string, what: string): void => {
  if (!set.has(id)) fail(`${where}: ${what} ${id} が無い`);
};

const ROWS: Json[] = L.ROWS;
const ops = unique("ROWS", ROWS.map((r) => r.id));
const screens = unique("SCREENS", L.SCREENS.map((s: Json) => s.id));
const settings = unique("ST", L.ST.map((s: Json) => s.id));
const settingNames = unique("ST の名", L.ST.map((s: Json) => s.name));
const systems = unique("XS", L.XS.map((x: Json) => x.id));
const xops = unique("XOR", L.XOR.map((x: Json) => x.id));
const tables = unique("DMR の名", L.DMR.map((t: Json) => t.id));
const dids = unique("DMR の id", L.DMR.map((t: Json) => t.did));
const didOf = new Map<string, string>(L.DMR.map((t: Json) => [t.id, t.did]));
const pids = new Set<string>(ROWS.flatMap((r) => r.children.map((_: Json, i: number) => `${r.id}#${i + 1}`)));

// 1. docs/routes.md の経路が、子の行の route にちょうど 1 回ずつ在る
const routeKey = (place: string, method: string, path: string): string => `${place} ${method} ${path}`;
const listed = readFileSync(values.routes!, "utf8")
  .split("\n")
  .map((line) => line.match(/^\| (base|top|fido) \| ([A-Z]+) \| `([^`]+)` \|/))
  .filter((m): m is RegExpMatchArray => m !== null)
  .map((m) => routeKey(m[1]!, m[2]!, m[3]!));
const listedSet = unique("routes.md", listed);
const used = new Map<string, number>();
for (const r of ROWS) {
  for (const c of r.children) {
    if (!c.route) continue;
    const k = routeKey(c.route.place, c.route.method, c.route.path);
    used.set(k, (used.get(k) ?? 0) + 1);
    if (!listedSet.has(k)) fail(`${r.id}: 経路 ${k} が routes.md に無い`);
  }
}
for (const k of listed) {
  const n = used.get(k) ?? 0;
  if (n !== 1) fail(`routes.md の ${k} が子の行に ${n} 回ある`);
}

// 2. 権限のマス
const CELLS = new Set(["可", "断", "条件つき", "該当しない", "口無し", "未確認", "入口で違う"]);
const count = CFG.actors.reduce((n: number, a: Json) => n + (a.relations ? CFG.relations.length : 1), 0);
for (const r of ROWS) {
  const rc: string[] | undefined = r.cells;
  if (rc && rc.length !== count) fail(`${r.id}: マスが ${rc.length} 個（${count} 個のはず）`);
  for (const v of rc ?? []) if (!CELLS.has(v)) fail(`${r.id}: マスの値 ${v}`);
  if (!rc && r.children.some((c: Json) => c.cells)) fail(`${r.id}: 親にマスが無いのに子にある`);
  for (const [i, c] of r.children.entries()) {
    if (!c.cells) continue;
    if (!Array.isArray(c.show)) fail(`${r.id}#${i + 1}: cells があるのに show が無い（頁が落ちる）`);
    if (c.cells.length !== count) fail(`${r.id}#${i + 1}: マスが ${c.cells.length} 個`);
    c.cells.forEach((v: string, j: number) => {
      if (!CELLS.has(v)) fail(`${r.id}#${i + 1}: マスの値 ${v}`);
      if (rc && rc[j] !== "入口で違う" && rc[j] !== v) fail(`${r.id}#${i + 1}: ${j} 番のマスが親（${rc[j]}）と違う（${v}）`);
    });
  }
}

// 3. 結び
for (const s of L.SCREENS) {
  for (const o of s.ops ?? []) mustHave(`画面 ${s.id}`, ops, o, "操作");
  for (const o of s.opens ?? []) mustHave(`画面 ${s.id}`, screens, o, "画面");
  if (s.parent) mustHave(`画面 ${s.id}`, screens, s.parent, "親の画面");
  if (s.kind === "メニュー" && !s.dest?.at) fail(`画面 ${s.id}: メニューの dest に at が無い（頁に undefined と出る）`);
}
for (const x of L.XO.not_listed ?? []) {
  for (const k of ["entry", "why", "at"]) if (!x[k]) fail(`XO.not_listed ${x.at}: ${k} が無い（頁に undefined と出る）`);
}
for (const [k, list] of Object.entries(L.CHECK as Record<string, Json[]>)) {
  for (const x of list) {
    if (x.op) mustHave(`CHECK.${k}`, ops, x.op, "操作");
    if (x.screen) mustHave(`CHECK.${k}`, screens, x.screen, "画面");
  }
}
if (JSON.stringify([...Object.keys(L.SCL)].sort()) !== JSON.stringify([...settings].sort()))
  fail("SCL の鍵が ST の id と揃わない（頁が落ちる）");
for (const [pid, ids] of Object.entries(L.GATE as Record<string, string[]>)) {
  mustHave("GATE", pids, pid, "子の行");
  for (const id of ids) mustHave(`GATE ${pid}`, settings, id, "設定");
}
for (const [id, list] of Object.entries(L.GPID as Record<string, string[]>)) {
  mustHave("GPID", settings, id, "設定");
  for (const pid of list) mustHave(`GPID ${id}`, pids, pid, "子の行");
}
for (const id of Object.keys(L.GN)) mustHave("GN", settings, id, "設定");
for (const x of L.XS) {
  for (const o of x.parents) mustHave(`XS ${x.id}`, ops, o, "操作");
  for (const n of x.settings) mustHave(`XS ${x.id}`, settingNames, n, "設定の名");
}
for (const x of L.XOR) {
  mustHave(`XOR ${x.id}`, systems, x.system, "外部システム");
  for (const o of x.a_ops) mustHave(`XOR ${x.id}`, ops, o, "操作");
}
// OPEXT・XS.parents・XOR.a_ops は同じ組を持つ
const pairs = (list: Array<[string, string]>): string => JSON.stringify([...new Set(list.map((p) => p.join(" ")))].sort());
const fromOpext = Object.entries(L.OPEXT as Record<string, string[]>).flatMap(([o, xs]) => xs.map((x) => [o, x] as [string, string]));
const fromXs = L.XS.flatMap((x: Json) => x.parents.map((o: string) => [o, x.id]));
const fromXor = L.XOR.flatMap((x: Json) => x.a_ops.map((o: string) => [o, x.system]));
for (const [o, x] of fromOpext) {
  mustHave("OPEXT", ops, o, "操作");
  mustHave(`OPEXT ${o}`, systems, x, "外部システム");
}
if (pairs(fromOpext) !== pairs(fromXs)) fail("OPEXT と XS.parents の組が揃わない");
if (pairs(fromOpext) !== pairs(fromXor)) fail("OPEXT と XOR.a_ops の組が揃わない");
for (const t of L.DMR) {
  for (const rel of t.rels) for (const to of rel.to.split("|")) mustHave(`DMR ${t.id} の rels`, tables, to, "表");
}
for (const [o, list] of Object.entries(L.OPDM as Record<string, Array<[string, string, number]>>)) {
  mustHave("OPDM", ops, o, "操作");
  for (const [did, name, sure] of list) {
    mustHave(`OPDM ${o}`, dids, did, "表の id");
    if (didOf.get(name) !== did) fail(`OPDM ${o}: ${did} と ${name} が合わない`);
    const u = L.DMOP[name];
    if (!u) continue;
    if (u.x) fail(`OPDM ${o}: 横断の表 ${name} を名指す`);
    else if (!(sure ? u.o : u.m).includes(o)) fail(`OPDM ${o}: ${name} の DMOP に ${o} が無い`);
  }
}
if (JSON.stringify(Object.keys(L.DMOP).sort()) !== JSON.stringify([...tables].sort())) fail("DMOP の鍵が DMR の表と揃わない");
for (const [name, u] of Object.entries(L.DMOP as Record<string, Json>)) {
  for (const o of [...u.o, ...u.m]) mustHave(`DMOP ${name}`, ops, o, "操作");
  if (u.x) continue;
  for (const o of u.o) if (!(L.OPDM[o] ?? []).some((e: Json) => e[1] === name && e[2] === 1)) fail(`DMOP ${name}: ${o} が OPDM に無い`);
  for (const o of u.m) if (!(L.OPDM[o] ?? []).some((e: Json) => e[1] === name && e[2] === 0)) fail(`DMOP ${name}: ${o} が OPDM に無い（見込み）`);
}

// 4. 手順の結び（台本の build も確かめるが、頁を作る前に分かるようここでも見る）
const goals = unique("TJ", TJ.map((g) => g.id));
const known: Record<string, Set<string>> = { ops, screens, settings, ext: systems, xops, dm: dids };
unique("TJ の段", TJ.flatMap((g) => g.steps.map((s: Json) => s.id)));
for (const g of TJ) {
  if (g.checked === undefined || g.source === undefined) fail(`${g.id}: checked と source が要る（頁に undefined と出る）`);
  for (const n of g.needs ?? []) mustHave(g.id, goals, n, "前提の目的");
  for (const s of g.steps) for (const [k, set] of Object.entries(known)) for (const id of s[k]) mustHave(s.id, set, id, k);
}

if (errors.length) {
  for (const e of errors) process.stderr.write(`赤: ${e}\n`);
  process.stderr.write(`${errors.length} 件\n`);
  process.exit(1);
}
process.stdout.write(
  `緑: 経路 ${listed.length}・操作 ${ops.size}・画面 ${screens.size}・設定 ${settings.size}・外部 ${systems.size}・外部の物×処理 ${xops.size}・表 ${tables.size}・手順 ${goals.size}\n`,
);
