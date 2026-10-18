#!/usr/bin/env bash
# formal/*.spthy を全部 Tamarin にかけ、lemma ごとの結果を expected.tsv と突き合わせる。
# 本体のモデルは verified、NEG 版は README に書いた lemma が falsified であることを期待する。
# 期待と違う・表に無いモデルや lemma がある・表にあるのに走らなかった、のどれでも非 0 で終わる。
set -euo pipefail
cd "$(dirname "$0")"

actual=$(mktemp)
trap 'rm -f "$actual"' EXIT

status=0
for model in *.spthy; do
  if ! out=$(tamarin-prover --prove --auto-sources "$model" 2>&1); then
    echo "$model: tamarin-prover が失敗した" >&2
    printf '%s\n' "$out" | tail -n 30 >&2
    status=1
    continue
  fi
  if ! grep -q 'All wellformedness checks were successful' <<<"$out"; then
    echo "$model: wellformedness の検査が通っていない" >&2
    status=1
  fi
  sed -n '/summary of summaries/,$p' <<<"$out" |
    sed -nE "s/^ *([A-Za-z0-9_]+) \((all-traces|exists-trace)\): ([a-z]+).*/$model\t\1\t\3/p" >>"$actual"
done

if ! diff -u <(tail -n +2 expected.tsv | sort) <(sort "$actual"); then
  echo "Tamarin の結果が expected.tsv と食い違う（- が期待、+ が実際）" >&2
  status=1
fi
[ "$status" -eq 0 ] && echo "Tamarin: $(wc -l <"$actual" | tr -d ' ') lemma が expected.tsv と一致"
exit "$status"
