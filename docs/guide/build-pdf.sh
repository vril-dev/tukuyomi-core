#!/usr/bin/env bash
# Build the tukuyomi-core operations guide as PDF.
#
# Usage:
#   docs/guide/build-pdf.sh all
#   docs/guide/build-pdf.sh ja
#   docs/guide/build-pdf.sh en
#
# Pipeline: pandoc (Markdown -> HTML5) -> Chrome headless (HTML -> PDF). The chapter list, the titles and Appendix A
# and B come from lib/guide_book.sh, which build-epub.sh shares, so the PDF has the same chapters as the EPUB. The
# Japanese sources put each sentence on its own line; cjk-line-breaks.lua drops those line breaks so that no space
# appears in the Japanese text. The PDF needs Google Chrome and the Noto Sans CJK JP font.
# When SOURCE_DATE_EPOCH (seconds since 1970-01-01 UTC) is set, the date on the cover is that day in UTC; without it,
# the date is the day of the build. Chrome writes the time of the build and identifiers into the PDF, so two builds
# of the same sources differ in those bytes only.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$DOCS_ROOT/.." && pwd)"
DIST="$SCRIPT_DIR/dist"
TMP_BASE="$SCRIPT_DIR/.tmp/build-pdf"
CSS="$SCRIPT_DIR/book-pdf.css"
FILTER="$SCRIPT_DIR/cjk-line-breaks.lua"

# shellcheck source=./lib/guide_book.sh
source "$SCRIPT_DIR/lib/guide_book.sh"

DOC_VERSION="${VERSION:-}"
if [[ -z "$DOC_VERSION" ]]; then
  DOC_VERSION="$(sed -n 's/^version = "\([0-9][0-9.]*\)"$/\1/p' "$REPO_ROOT/proxy/Cargo.toml" | head -n 1)"
fi
if [[ ! "$DOC_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "cannot read the version (set VERSION=x.y.z)" >&2
  exit 1
fi
if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
  if [[ ! "$SOURCE_DATE_EPOCH" =~ ^[0-9]{1,12}$ ]]; then
    echo "SOURCE_DATE_EPOCH is not a number of seconds" >&2
    exit 1
  fi
  TODAY="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y-%m-%d)"
else
  TODAY="$(date +%Y-%m-%d)"
fi

usage() {
  echo "usage: $0 all|ja|en" >&2
}

build_one() {
  local lang="$1"
  local book out
  if ! guide_book_load "$lang" "$DOC_VERSION"; then
    usage
    exit 64
  fi
  book="$GUIDE_BOOK_DIR"
  out="$DIST/tukuyomi-core-guide-${lang}.pdf"

  local tmp="$TMP_BASE-$lang"
  rm -rf "$tmp"
  mkdir -p "$tmp" "$DIST"
  # Do not leave a previous build in place if this one fails.
  rm -f "$out"

  local files=()
  local chapter
  for chapter in "${GUIDE_BOOK_CHAPTERS[@]}"; do
    if [[ ! -f "$book/$chapter" ]]; then
      echo "missing: $book/$chapter" >&2
      exit 1
    fi
    files+=("$book/$chapter")
  done

  echo "[1/4][$lang] appendices: taking the references from docs/operations"
  guide_book_appendices "$tmp" "$REPO_ROOT"

  local extra=("$tmp/appendix-a.md" "$tmp/appendix-b.md")
  if [[ -f "$book/C-release-notes.md" ]]; then
    extra+=("$book/C-release-notes.md")
  else
    echo "missing: $book/C-release-notes.md" >&2
    exit 1
  fi

  local cover_html
  cover_html=$(cat <<EOF
<section class="cover">
  <div class="eyebrow">Operations Guide</div>
  <h1>${GUIDE_BOOK_TITLE}</h1>
  <div class="tagline">${GUIDE_BOOK_SUBTITLE}</div>
  <div class="meta">
    ${GUIDE_BOOK_META_VERSION}<br/>
    ${TODAY}
  </div>
</section>
EOF
)

  echo "[2/4][$lang] pandoc: combining Markdown into a single HTML5"
  pandoc \
    --from gfm \
    --to html5 \
    --standalone \
    --toc \
    --toc-depth=2 \
    --lua-filter="$FILTER" \
    --metadata "title=${GUIDE_BOOK_TITLE}" \
    --metadata "subtitle=${GUIDE_BOOK_EDITION_SUBTITLE}" \
    --metadata "pagetitle=${GUIDE_BOOK_DOC_TITLE}" \
    --metadata "lang=${lang}" \
    --css="$CSS" \
    --section-divs \
    --variable=document-css:false \
    -o "$tmp/_body.html" \
    "${files[@]}" "${extra[@]}"

  TMP_DIR="$tmp" CSS_PATH="$CSS" COVER_HTML="$cover_html" python3 -I - <<'PY'
import os
import pathlib
import re

tmp = pathlib.Path(os.environ["TMP_DIR"])
css = pathlib.Path(os.environ["CSS_PATH"]).resolve()
src = (tmp / "_body.html").read_text(encoding="utf-8")
cover = os.environ["COVER_HTML"]

src = re.sub(r"<style>[\s\S]*?</style>\s*", "", src, count=1)

def absify(match):
    href = match.group(1)
    if href.startswith("file://") or href.startswith("http"):
        return match.group(0)
    return f'<link rel="stylesheet" href="file://{css}"'

src = re.sub(r'<link rel="stylesheet" href="([^"]+)"', absify, src)
src = src.replace("<body>", f"<body>\n{cover}", 1)

(tmp / "book.html").write_text(src, encoding="utf-8")
print(f"  HTML: {tmp / 'book.html'}  ({(tmp / 'book.html').stat().st_size} bytes)")
PY

  echo "[3/4][$lang] Chrome headless: rendering HTML -> PDF"
  google-chrome \
    --headless \
    --disable-gpu \
    --no-sandbox \
    --no-pdf-header-footer \
    --hide-scrollbars \
    --virtual-time-budget=10000 \
    --run-all-compositor-stages-before-draw \
    --print-to-pdf="$out" \
    "file://$tmp/book.html" \
    2>&1 | grep -v -E "(DevTools listening|Fontconfig|^$)" || true

  if [[ ! -s "$out" ]]; then
    echo "PDF was not generated: $out" >&2
    exit 2
  fi
  echo "[4/4][$lang] done"
  echo "  -> $out  ($(du -h "$out" | cut -f1))"
}

target="${1:-all}"
case "$target" in
  all)
    build_one ja
    build_one en
    ;;
  ja|en)
    build_one "$target"
    ;;
  *)
    usage
    exit 64
    ;;
esac
