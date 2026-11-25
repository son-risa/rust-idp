#!/usr/bin/env bash
# docs.amate.ai の Worker（docs-amate-ai）を Cloudflare に上げる。
# CLOUDFLARE_API_TOKEN（Workers の編集権限）と CLOUDFLARE_ACCOUNT_ID を環境から読む。
set -euo pipefail
: "${CLOUDFLARE_API_TOKEN:?}" "${CLOUDFLARE_ACCOUNT_ID:?}"
D=$(cd "$(dirname "$0")" && pwd)
node "$D/worker.test.mjs"
M=$(mktemp)
trap 'rm -f "$M"' EXIT
printf '{"main_module":"worker.mjs","compatibility_date":"2026-11-01"}' > "$M"
curl -sf -X PUT -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/workers/scripts/docs-amate-ai" \
  -F "metadata=@$M;type=application/json" \
  -F "worker.mjs=@$D/worker.mjs;type=application/javascript+module" \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print("success:",d.get("success"));sys.exit(0 if d.get("success") else 1)'
