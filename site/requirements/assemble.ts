// data/*.json の 7 覧を 1 つの data/lists.json にまとめる。手順（steps.json）と設定（config.json）は build に別に渡す。
// node site/requirements/assemble.ts
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const DATA = join(dirname(fileURLToPath(import.meta.url)), "data");

// 覧の file → lists.json に入れる鍵。notes・outside など頁が読まない鍵は入れない
const PARTS: Record<string, string[]> = {
  "rows.json": ["ROWS"],
  "screens.json": ["SCREENS", "CHECK"],
  "settings.json": ["ST", "SCL", "GN", "GPID", "GATE", "OV", "SP", "UR"],
  "external.json": ["XS", "XOR", "OPEXT", "XO"],
  "dmodel.json": ["DMR", "OPDM", "DMOP"],
};

const lists: Record<string, unknown> = {};
for (const [file, keys] of Object.entries(PARTS)) {
  const part = JSON.parse(readFileSync(join(DATA, file), "utf8")) as Record<string, unknown>;
  for (const key of keys) {
    if (!(key in part)) throw new Error(`${file} has no ${key}`);
    lists[key] = part[key];
  }
}
writeFileSync(join(DATA, "lists.json"), `${JSON.stringify(lists, null, 1)}\n`);
process.stdout.write(`${Object.keys(lists).join(" ")}\n`);
