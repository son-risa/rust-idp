#!/usr/bin/env bash
# formal/premises.json の tests が、cargo test に実際に登録された試験の名前（`cargo test -- --list`）と
# 完全一致し、#[ignore] でないことを見る。消えた・名前が変わった・別の mod へ移った・cfg やコメントで
# 外された・ignored になった試験を名指していれば非 0 で終わる。
set -euo pipefail
cd "$(dirname "$0")/.."

listed=$(mktemp)
ignored=$(mktemp)
wanted=$(mktemp)
trap 'rm -f "$listed" "$ignored" "$wanted"' EXIT

cargo test --locked -q -- --list --format terse 2>/dev/null | sed -n 's/: test$//p' | sort -u >"$listed"
cargo test --locked -q -- --list --format terse --ignored 2>/dev/null | sed -n 's/: test$//p' | sort -u >"$ignored"
python3 -c 'import json,sys; [print(t) for r in json.load(open("formal/premises.json")) for t in r.get("tests", [])]' | sort -u >"$wanted"

if [ ! -s "$listed" ]; then
  echo "cargo test -- --list が試験を 1 本も返さなかった" >&2
  exit 1
fi

status=0
missing=$(comm -23 "$wanted" "$listed")
if [ -n "$missing" ]; then
  echo "formal/premises.json が名指す試験が cargo test に無い:" >&2
  printf '%s\n' "$missing" >&2
  status=1
fi
skipped=$(comm -12 "$wanted" "$ignored")
if [ -n "$skipped" ]; then
  echo "formal/premises.json が名指す試験が #[ignore] で回っていない:" >&2
  printf '%s\n' "$skipped" >&2
  status=1
fi
[ "$status" -eq 0 ] && echo "台帳の試験 $(wc -l <"$wanted" | tr -d ' ') 本が cargo test の一覧と一致"
exit "$status"
