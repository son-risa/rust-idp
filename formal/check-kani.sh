#!/usr/bin/env bash
# cargo kani で全ハーネスを回し、走ったハーネスの名前と結果を kani-harnesses.txt と突き合わせる。
# 一覧は「SUCCESSFUL になるべきハーネス」の全部。消えた・増えた・名前が変わった・失敗した、のどれでも非 0 で終わる。
set -euo pipefail
cd "$(dirname "$0")"

out=$(mktemp)
actual=$(mktemp)
trap 'rm -f "$out" "$actual"' EXIT

status=0
(cd .. && cargo kani) >"$out" 2>&1 || status=1
awk '/^Checking harness /{h=$3; sub(/^kani_harness::/, "", h); sub(/\.\.\.$/, "", h)}
     /^VERIFICATION:- SUCCESSFUL/{if (h != "") print h; h=""}' "$out" | sort >"$actual"

if [ "$status" -ne 0 ]; then
  echo "cargo kani が失敗した" >&2
  grep -E '^(Checking harness|VERIFICATION|Complete)' "$out" >&2 || tail -n 30 "$out" >&2
fi
if ! diff -u <(grep -v '^$' kani-harnesses.txt | sort) "$actual"; then
  echo "SUCCESSFUL になったハーネスが kani-harnesses.txt と食い違う（- が期待、+ が実際）" >&2
  status=1
fi
[ "$status" -eq 0 ] && echo "Kani: $(wc -l <"$actual" | tr -d ' ') ハーネスが kani-harnesses.txt と一致"
exit "$status"
