#!/usr/bin/env bash
# formal/*.spthy を全部 Tamarin にかけ、lemma ごとの結果を expected.tsv と突き合わせる。
# 本体のモデルは verified、NEG 版は README に書いた lemma が falsified であることを期待する。
# 期待と違う・表に無いモデルや lemma がある・表にあるのに走らなかった・警告が出た、のどれでも非 0 で終わる。
# 結果は出力の最後の「summary of summaries:」より後ろだけから読む（モデルの text{* *} などに
# 同じ形の行を書いても、判定に混ざらない）。
set -euo pipefail
cd "$(dirname "$0")"

actual=$(mktemp)
trap 'rm -f "$actual"' EXIT

status=0
models=()
for model in *.spthy; do
  # model の名前は表の 1 列目と出力の行にそのまま入るので、TAB・改行などで行を偽造できない形に限る。
  if [[ ! "$model" =~ ^[A-Za-z0-9_]+\.spthy$ ]]; then
    echo "モデルの file 名が ^[A-Za-z0-9_]+\.spthy\$ に合わない: $(printf '%q' "$model")" >&2
    status=1
    continue
  fi
  # heuristic（oracle）・#include・configuration: は、判定の途中で任意のプログラムを走らせたり、別の file を
  # 読ませたりできる（oracle が expected.tsv を書き換えて緑にできた）。Tamarin にかける前に断る。
  if grep -niE 'heuristic|#include|configuration[[:space:]]*:' "$model" >&2; then
    echo "$model: heuristic・#include・configuration: は使えない" >&2
    status=1
    continue
  fi
  models+=("$model")
done

# lemma を 1 つも持たないモデルは結果の行を出さないので、モデルの名前の集合を表と別に照らす。
if ! diff -u <(tail -n +2 expected.tsv | cut -f1 | sort -u) <(printf '%s\n' "${models[@]}" | sort -u); then
  echo "formal/ のモデルの集合が expected.tsv と食い違う（- が表だけ、+ が formal/ だけ）" >&2
  status=1
fi

for model in "${models[@]}"; do
  if ! out=$(tamarin-prover --quit-on-warning --prove --auto-sources "$model" 2>&1); then
    echo "$model: tamarin-prover が失敗した（警告を含む）" >&2
    printf '%s\n' "$out" | tail -n 30 >&2
    status=1
    continue
  fi
  summary=$(awk '/^summary of summaries:$/{buf=""; on=1; next} on{buf=buf $0 "\n"} END{printf "%s", buf}' <<<"$out")
  if [ -z "$summary" ]; then
    echo "$model: summary of summaries が無い" >&2
    status=1
    continue
  fi
  if ! grep -q 'All wellformedness checks were successful' <<<"$out" || grep -qi 'wellformedness check failed' <<<"$summary"; then
    echo "$model: wellformedness の検査が通っていない" >&2
    status=1
  fi
  while IFS= read -r line; do
    if [[ "$line" =~ ^\ \ ([A-Za-z0-9_]+)\ \((all-traces|exists-trace)\):\ ([a-z]+) ]]; then
      printf '%s\t%s\t%s\n' "$model" "${BASH_REMATCH[1]}" "${BASH_REMATCH[3]}" >>"$actual"
    else
      echo "$model: lemma の行を読めない: $line" >&2
      status=1
    fi
  done < <(grep -E '\((all-traces|exists-trace)\)' <<<"$summary" || true)
done

if ! diff -u <(tail -n +2 expected.tsv | sort) <(sort "$actual"); then
  echo "Tamarin の結果が expected.tsv と食い違う（- が期待、+ が実際）" >&2
  status=1
fi
[ "$status" -eq 0 ] && echo "Tamarin: $(wc -l <"$actual" | tr -d ' ') lemma が expected.tsv と一致"
exit "$status"
