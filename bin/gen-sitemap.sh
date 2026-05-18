#!/bin/sh
# gen-sitemap.sh — regenerate public/sitemap.xml from the public/ tree.
#
# Why this exists: sitemap.xml was hand-maintained and drifted every time a
# blog post or talk landed (req_xdm3wx4j). This rebuilds it deterministically
# from what's actually served, so it can never drift again. `make deploy`
# runs it first, so every deploy ships a current sitemap.
#
# Rules:
#   - Every .html file under public/ becomes one <url>.
#   - <loc> is the page's own <link rel="canonical"> when it declares one
#     (single source of truth — the sitemap can never disagree with a page's
#     declared canonical, e.g. /contact has no trailing slash). Pages without
#     a canonical fall back to the clean URL the worker serves
#     (no .html; index.html -> dir/).
#   - Pages carrying a robots "noindex" meta are skipped (e.g. /contact/thanks).
#   - <lastmod> is the file's last git commit date (today if untracked).
#   - Binaries (PDF/zip) are never in the sitemap — only .html is walked.
set -eu

cd "$(dirname "$0")/.."
ROOT=public
BASE=https://solpbc.org
OUT="$ROOT/sitemap.xml"

tmp=$(mktemp)
{
  echo '<?xml version="1.0" encoding="UTF-8"?>'
  echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'

  find "$ROOT" -type f -name '*.html' | LC_ALL=C sort | while IFS= read -r f; do
    # Skip pages that opt out of indexing.
    if grep -qi 'name="robots"[^>]*noindex' "$f"; then
      continue
    fi

    # Prefer the page's declared canonical; fall back to the clean URL.
    loc=$(grep -o '<link rel="canonical" href="[^"]*"' "$f" 2>/dev/null \
            | head -1 | sed -e 's/.*href="//' -e 's/"$//')
    if [ -z "$loc" ]; then
      rel=${f#"$ROOT"/}
      case "$rel" in
        index.html)   path='/' ;;                  # site root
        */index.html) path="/${rel%index.html}" ;; # directory -> /dir/
        *.html)       path="/${rel%.html}" ;;      # clean URL, no .html
      esac
      loc="$BASE$path"
    fi

    lastmod=$(git log -1 --format=%cs -- "$f" 2>/dev/null || true)
    [ -n "$lastmod" ] || lastmod=$(date +%F)

    printf '  <url>\n    <loc>%s</loc>\n    <lastmod>%s</lastmod>\n  </url>\n' \
      "$loc" "$lastmod"
  done

  echo '</urlset>'
} >"$tmp"

mv "$tmp" "$OUT"
echo "gen-sitemap: wrote $OUT ($(grep -c '<url>' "$OUT") urls)"
