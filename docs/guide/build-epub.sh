#!/usr/bin/env bash
# Build the tukuyomi-core operations guide as EPUB 3.
#
# Usage:
#   docs/guide/build-epub.sh all
#   docs/guide/build-epub.sh ja
#   docs/guide/build-epub.sh en
#
# Pipeline: pandoc (Markdown -> EPUB 3). The chapter list, the titles and Appendix A and B come from
# lib/guide_book.sh, which build-pdf.sh shares. The Japanese sources put each sentence on its own line;
# cjk-line-breaks.lua drops those line breaks so that no space appears in the Japanese text.
# When SOURCE_DATE_EPOCH (seconds since 1970-01-01 UTC) is set, the date of the book is that day in UTC, and pandoc
# takes the modification time and the times in the archive from it, so that the same sources give the same EPUB byte
# for byte. Without it, the date is the day of the build.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$DOCS_ROOT/.." && pwd)"
DIST="$SCRIPT_DIR/dist"
TMP_BASE="$SCRIPT_DIR/.tmp/build-epub"
CSS="$SCRIPT_DIR/book.css"
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
  local book rights out
  if ! guide_book_load "$lang" "$DOC_VERSION"; then
    usage
    exit 64
  fi
  book="$GUIDE_BOOK_DIR"
  out="$DIST/tukuyomi-core-guide-${lang}.epub"
  rights="BSD 2-Clause License"

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

  echo "[1/3][$lang] appendices: taking the references from docs/operations"
  guide_book_appendices "$tmp" "$REPO_ROOT"

  local extra=("$tmp/appendix-a.md" "$tmp/appendix-b.md")
  if [[ -f "$book/C-release-notes.md" ]]; then
    extra+=("$book/C-release-notes.md")
  else
    echo "missing: $book/C-release-notes.md" >&2
    exit 1
  fi

  echo "[2/3][$lang] pandoc: Markdown -> EPUB 3"
  pandoc \
    --from gfm \
    --to epub3 \
    --toc \
    --toc-depth=2 \
    --split-level=1 \
    --css="$CSS" \
    --lua-filter="$FILTER" \
    --metadata "title=${GUIDE_BOOK_TITLE}" \
    --metadata "subtitle=${GUIDE_BOOK_EDITION_SUBTITLE}" \
    --metadata "lang=${lang}" \
    --metadata "identifier=urn:tukuyomi-core:guide:${lang}:${DOC_VERSION}" \
    --metadata "creator=vril" \
    --metadata "rights=${rights}" \
    --metadata "date=${TODAY}" \
    --metadata "toc-title=${GUIDE_BOOK_TOC_TITLE}" \
    -o "$out" \
    "${files[@]}" "${extra[@]}"

  if [[ ! -s "$out" ]]; then
    echo "EPUB was not generated: $out" >&2
    exit 2
  fi
  echo "[3/3][$lang] done"
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
