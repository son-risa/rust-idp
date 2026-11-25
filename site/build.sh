#!/usr/bin/env bash
# Builds the English site into site/public/ and the Japanese site into site/public/ja/.
# SITE_URL only sets canonical links and the sitemap; links between pages are relative either way.
set -euo pipefail
cd "$(dirname "$0")"

export SITE_URL="${SITE_URL:-https://docs.amate.ai/idp/}"
export SITE_URL_JA="${SITE_URL%/}/ja/"

rm -rf public
# English first: its build cleans site_dir, which would remove public/ja/.
zensical build --strict -f mkdocs.en.yml
zensical build --strict -f mkdocs.ja.yml
# The requirements page is one self-contained HTML file built outside Zensical; copy it after both builds.
mkdir -p public/requirements
cp requirements/index.html public/requirements/index.html
