#!/bin/sh
# gen-brand-assets.sh — generate every downloadable asset for /brands/.
#
# Why this exists: the brand portal (public/brands/index.html) renders logos
# on-page as live inline SVG, but also offers per-asset downloads (SVG, PNG 512,
# PNG 1024, vector PDF) and per-brand + global zips. Those binaries are
# generated here from the canonical brand SVGs and committed (static site, no
# runtime generation). Re-run any time a source SVG changes; output is
# deterministic so it does not churn git.
#
# Build spec: cmo/workspace/brand-portal-build-spec-260518.md §5.4.
#
# Source of truth for the SVGs is the (private) extro repo's cmo/brand/ tree.
# Override with BRAND_SRC=/abs/path if it is not the sibling default.
#
# Renderer: the spec names `rsvg-convert` (librsvg). librsvg2-tools is not
# installed in this environment (only the library, not the CLI; magick is also
# absent so cmo/brand/sol/export-pngs.sh cannot be reused). We therefore prefer
# rsvg-convert when present and otherwise fall back to cairosvg in a
# self-bootstrapped local venv. Both are Cairo-family renderers; both render
# PNGs natively at the target size (never downsample — founder rule,
# cmo/brand/sol/index.md § rendering rule) and both emit true-vector PDFs
# (zero raster image rows under `pdfimages -list` — acceptance gate §7.6).
# The portal's sol assets (pbc-wordmark, sol-wordmark, sol-ring + white
# variants) have no per-size hand-tuned source, so a uniform native render
# satisfies the rule for every brand identically.
set -eu

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BRAND_SRC="${BRAND_SRC:-$REPO/../extro/cmo/brand}"
OUT="$REPO/public/brands/assets"

if [ ! -d "$BRAND_SRC" ]; then
  echo "gen-brand-assets: brand source not found: $BRAND_SRC" >&2
  echo "  set BRAND_SRC=/abs/path/to/extro/cmo/brand and re-run." >&2
  exit 1
fi

# --- asset manifest ---------------------------------------------------------
# One line per asset: "<brand> <asset-name> <source-svg-path-relative-to-BRAND_SRC>"
# <brand> in sol-pbc | solstone | vit ; names match the portal's download set.
MANIFEST="
sol-pbc   pbc-wordmark        sol/pbc-wordmark.svg
sol-pbc   pbc-wordmark-white  sol/pbc-wordmark-white.svg
sol-pbc   sol-ring            sol/sol-ring.svg
solstone  sol-wordmark        sol/sol-wordmark.svg
solstone  sol-wordmark-white  sol/sol-wordmark-white.svg
solstone  sol-ring            sol/sol-ring.svg
solstone  sol-app-icon-cream        sol/app-icon/sol-app-icon-cream.svg
solstone  sol-app-icon-transparent  sol/app-icon/sol-app-icon-transparent.svg
solstone  sol-lockup-solstone-app             sol/sol-lockup-solstone-app.svg
solstone  sol-lockup-solstone-app-accessible  sol/sol-lockup-solstone-app-accessible.svg
solstone  sol-lockup-solstone-app-white       sol/sol-lockup-solstone-app-white.svg
vit       vit-mark            vit/vit-mark.svg
vit       vit-mark-dark       vit/vit-mark-dark.svg
vit       vit-mark-white      vit/vit-mark-white.svg
vit       vit-wordmark        vit/vit-wordmark.svg
vit       badge-vit-enabled       vit/badge-vit-enabled.svg
vit       badge-vit-enabled-flat  vit/badge-vit-enabled-flat.svg
vit       badge-social-open-source vit/badge-social-open-source.svg
vit       badge-vit-icon-only     vit/badge-vit-icon-only.svg
"

LADDER="16 32 64 128 256 512 1024"
# Fixed mtime for every generated file so the zips are byte-deterministic
# run-to-run (git tracks content, but zip records mtimes — pin them).
EPOCH="2026-01-01T00:00:00"

# --- prerequisites ----------------------------------------------------------
# qpdf normalizes every generated PDF to a byte-deterministic form (pins
# CreationDate + /ID — the only nondeterministic fields any SVG->PDF renderer
# emits). Without it the committed PDFs and zips would churn git on every run.
if ! command -v qpdf >/dev/null 2>&1; then
  echo "gen-brand-assets: qpdf is required (PDF determinism). install qpdf." >&2
  exit 1
fi

# --- renderer selection -----------------------------------------------------
RENDERER=""
if command -v rsvg-convert >/dev/null 2>&1; then
  RENDERER="rsvg"
  echo "gen-brand-assets: renderer = rsvg-convert ($(rsvg-convert --version))"
else
  VENV="$REPO/bin/.brand-venv"
  if [ ! -x "$VENV/bin/python" ]; then
    echo "gen-brand-assets: bootstrapping cairosvg venv at bin/.brand-venv"
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install -q --disable-pip-version-check 'cairosvg>=2.7' >/dev/null
  fi
  PY="$VENV/bin/python"
  RENDERER="cairosvg"
  echo "gen-brand-assets: renderer = cairosvg ($("$PY" -c 'import cairosvg;print(cairosvg.__version__)'))"
fi

# render_png <src.svg> <size> <dest.png>
# Renders natively at <size> with aspect ratio preserved (the larger viewBox
# side maps to <size>) — never distorts non-square assets (vit-wordmark,
# badges), never downsamples.
render_png() {
  src="$1"; size="$2"; dst="$3"
  if [ "$RENDERER" = "rsvg" ]; then
    # rsvg-convert preserves aspect when only one of -w/-h is given; pick the
    # constraint matching the larger viewBox side via --keep-aspect-ratio.
    rsvg-convert --keep-aspect-ratio -w "$size" -h "$size" "$src" -o "$dst"
  else
    "$PY" - "$src" "$size" "$dst" <<'PY'
import sys, re, cairosvg
src, size, dst = sys.argv[1], int(sys.argv[2]), sys.argv[3]
svg = open(src, 'r', encoding='utf-8').read()
m = re.search(r'viewBox\s*=\s*["\']\s*[\d.+-]+\s+[\d.+-]+\s+([\d.+eE.+-]+)\s+([\d.eE+-]+)', svg)
if m:
    vw, vh = float(m.group(1)), float(m.group(2))
else:
    # Badges declare no viewBox — only width/height attrs (e.g. 108x20).
    wm = re.search(r'\bwidth\s*=\s*["\']\s*([\d.]+)', svg)
    hm = re.search(r'\bheight\s*=\s*["\']\s*([\d.]+)', svg)
    vw = float(wm.group(1)) if wm else 1.0
    vh = float(hm.group(1)) if hm else 1.0
if vw >= vh:
    ow, oh = size, max(1, round(size * vh / vw))
else:
    ow, oh = max(1, round(size * vw / vh)), size
cairosvg.svg2png(bytestring=svg.encode('utf-8'), write_to=dst,
                 output_width=ow, output_height=oh)
PY
  fi
}

# render_pdf <src.svg> <dest.pdf> — true-vector PDF at the SVG's native size,
# normalized to a byte-deterministic form.
#
# Every SVG->PDF renderer (cairosvg and rsvg-convert alike) stamps a wall-clock
# /CreationDate and a random /ID. The vector content is deterministic; only
# those two fields vary run-to-run. We pin both so the committed PDFs (and the
# zips that contain them) never churn git:
#   1. render raw PDF
#   2. expand to QDF (uncompressed, no object streams) so /CreationDate is
#      plain text, and pin it to a fixed equal-length value (keeps QDF xref)
#   3. qpdf --static-id rewrites with a fixed second /ID element
#   4. pin the surviving first /ID element (32 hex, trailer-only — safe,
#      equal-length, after the xref) to zeros
# Result verified: byte-identical across runs, distinct assets stay distinct,
# pdfimages -list shows zero raster rows (true vector), qpdf --check clean.
ZID="00000000000000000000000000000000"
PIID="31415926535897932384626433832795"  # qpdf --static-id constant
render_pdf() {
  src="$1"; dst="$2"
  raw="$(mktemp --suffix=.pdf)"; qa="$(mktemp --suffix=.qdf)"
  qb="$(mktemp --suffix=.qdf)"; sc="$(mktemp --suffix=.pdf)"
  if [ "$RENDERER" = "rsvg" ]; then
    rsvg-convert -f pdf "$src" -o "$raw"
  else
    "$PY" -c "import sys,cairosvg; cairosvg.svg2pdf(url=sys.argv[1], write_to=sys.argv[2])" "$src" "$raw"
  fi
  qpdf --qdf --object-streams=disable "$raw" "$qa"
  sed "s#/CreationDate (D:[0-9]\{14\}[+-][0-9]\{2\}'[0-9]\{2\})#/CreationDate (D:20260101000000+00'00)#" "$qa" > "$qb"
  qpdf --static-id --object-streams=disable "$qb" "$sc"
  sed "s#/ID \[<[0-9a-f]\{32\}><$PIID>\]#/ID [<$ZID><$PIID>]#" "$sc" > "$dst"
  rm -f "$raw" "$qa" "$qb" "$sc"
}

# --- clean + regenerate -----------------------------------------------------
rm -rf "$OUT"
mkdir -p "$OUT"

echo "$MANIFEST" | while read -r brand name relsrc; do
  [ -n "${brand:-}" ] || continue
  src="$BRAND_SRC/$relsrc"
  if [ ! -f "$src" ]; then
    echo "gen-brand-assets: missing source $src" >&2
    exit 1
  fi
  bdir="$OUT/$brand"
  mkdir -p "$bdir/svg" "$bdir/png" "$bdir/pdf"

  cp "$src" "$bdir/svg/$name.svg"
  render_pdf "$src" "$bdir/pdf/$name.pdf"
  for s in $LADDER; do
    render_png "$src" "$s" "$bdir/png/$name-$s.png"
  done
  echo "  $brand/$name  (svg + pdf + png x$(echo $LADDER | wc -w))"
done

# --- QR code (special asset — NOT laddered) ---------------------------------
# The sol QR is a raster-backed styled logo-QR: a 16px render is unscannable
# and the .svg is a raster-wrapper that won't vectorize, so it bypasses the
# svg+png-ladder+pdf pipeline above. Copy the canonical (cream) + secondary
# (white) masters straight into solstone/qr/ at their authored sizes; they
# ride solstone.zip + the global zip via the directory include below, and the
# mtime-pin (find ... touch, further down) keeps the zips deterministic.
QR_SRC="$BRAND_SRC/sol/qr"
QR_OUT="$OUT/solstone/qr"
mkdir -p "$QR_OUT"
for f in "sol-qr-solstone-app.svg" \
         "png/sol-qr-cream-512.png"  "png/sol-qr-cream-1024.png"  "png/sol-qr-cream-2048.png" \
         "png/sol-qr-white-512.png"  "png/sol-qr-white-1024.png"  "png/sol-qr-white-2048.png"; do
  if [ ! -f "$QR_SRC/$f" ]; then
    echo "gen-brand-assets: missing QR source $QR_SRC/$f" >&2
    exit 1
  fi
  cp "$QR_SRC/$f" "$QR_OUT/"
done
echo "  solstone/qr  (svg + cream/white png 512/1024/2048, not laddered)"

# --- deterministic zips -----------------------------------------------------
# Pin every generated file's mtime, then zip from a sorted file list with
# -X (no extra attrs). Same inputs -> byte-identical zip -> no git churn.
find "$OUT" -type f -exec touch -d "$EPOCH" {} +

build_zip() {
  zipfile="$1"; shift
  ( cd "$OUT" && find "$@" -type f | LC_ALL=C sort | zip -X -q "$zipfile" -@ )
  touch -d "$EPOCH" "$OUT/$zipfile"
}

# Per-brand zip = that brand's full svg + png-ladder + pdf set.
( cd "$OUT" && rm -f sol-pbc.zip solstone.zip vit.zip sol-pbc-brand-all.zip )
build_zip sol-pbc.zip  sol-pbc
build_zip solstone.zip solstone
build_zip vit.zip      vit
# Global zip = union of all brands (zips live at $OUT root, not under the
# brand dirs, so they are never recursively included in one another).
build_zip sol-pbc-brand-all.zip sol-pbc solstone vit

echo "gen-brand-assets: done -> $OUT"
( cd "$OUT" && ls -1 *.zip )
