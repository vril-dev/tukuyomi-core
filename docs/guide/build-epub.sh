#!/usr/bin/env bash
# Build the tukuyomi-core operations guide as EPUB 3.
#
# Usage:
#   docs/guide/build-epub.sh all
#   docs/guide/build-epub.sh ja
#   docs/guide/build-epub.sh en
#
# Pipeline: pandoc (Markdown -> EPUB 3). Appendix A and B are not kept in docs/guide: they are taken from
# docs/operations/operator-reference(.ja).md and admin-reference(.ja).md when the book is built, so the reference
# exists in one place only. Links between the two references go to the appendix in the book. A link to another
# document of the repository becomes its name followed by its path in the repository, as the chapters write it, so
# that the book has no link to a file that a release tag may not have.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$DOCS_ROOT/.." && pwd)"
DIST="$SCRIPT_DIR/dist"
TMP_BASE="$SCRIPT_DIR/.tmp/build-epub"
CSS="$SCRIPT_DIR/book.css"

DOC_VERSION="${VERSION:-}"
if [[ -z "$DOC_VERSION" ]]; then
  DOC_VERSION="$(sed -n 's/^version = "\([0-9][0-9.]*\)"$/\1/p' "$REPO_ROOT/proxy/Cargo.toml" | head -n 1)"
fi
if [[ ! "$DOC_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "cannot read the version (set VERSION=x.y.z)" >&2
  exit 1
fi
TODAY="$(date +%Y-%m-%d)"

CHAPTERS=(
  "00-preface.md"
  "01-introduction.md"
  "02-quickstart.md"
  "03-binary-deployment.md"
  "04-rules-and-generations.md"
  "05-managed-configuration.md"
  "06-access-control.md"
  "07-logs.md"
  "08-acme.md"
  "09-operations.md"
)

usage() {
  echo "usage: $0 all|ja|en" >&2
}

build_one() {
  local lang="$1"
  local book title subtitle rights suffix appendix_a appendix_b out
  case "$lang" in
    ja)
      book="$SCRIPT_DIR/ja"
      title="tukuyomi core"
      subtitle="運用ガイド ── 日本語版（${DOC_VERSION} ベース）"
      suffix=".ja.md"
      appendix_a="付録A　運用リファレンス"
      appendix_b="付録B　管理リファレンス"
      out="$DIST/tukuyomi-core-guide-ja.epub"
      ;;
    en)
      book="$SCRIPT_DIR/en"
      title="tukuyomi core"
      subtitle="Operations Guide ── English Edition (based on ${DOC_VERSION})"
      suffix=".md"
      appendix_a="Appendix A. Operator Reference"
      appendix_b="Appendix B. Admin Reference"
      out="$DIST/tukuyomi-core-guide-en.epub"
      ;;
    *)
      usage
      exit 64
      ;;
  esac
  rights="BSD 2-Clause License"

  local tmp="$TMP_BASE-$lang"
  rm -rf "$tmp"
  mkdir -p "$tmp" "$DIST"

  local files=()
  local chapter
  for chapter in "${CHAPTERS[@]}"; do
    if [[ ! -f "$book/$chapter" ]]; then
      echo "missing: $book/$chapter" >&2
      exit 1
    fi
    files+=("$book/$chapter")
  done

  echo "[1/3][$lang] appendices: taking the references from docs/operations"
  TMP_DIR="$tmp" REPO_ROOT="$REPO_ROOT" SUFFIX="$suffix" \
  APPENDIX_A="$appendix_a" APPENDIX_B="$appendix_b" python3 -I - <<'PY'
import os
import pathlib
import re

tmp = pathlib.Path(os.environ["TMP_DIR"])
repo = pathlib.Path(os.environ["REPO_ROOT"])
suffix = os.environ["SUFFIX"]
names = {"operator-reference": ("appendix-a", os.environ["APPENDIX_A"]),
         "admin-reference": ("appendix-b", os.environ["APPENDIX_B"])}
link = re.compile(r"(?<!!)\[([^\]\n]+)\]\(([^)\s]+)\)")

for stem, (anchor, heading) in names.items():
    src = repo / "docs" / "operations" / (stem + suffix)
    lines = src.read_text(encoding="utf-8").splitlines()
    # The language line and the blank line after it are not part of the book.
    if lines and lines[0].startswith("[English]"):
        lines = lines[2:] if len(lines) > 1 and lines[1] == "" else lines[1:]
    if not lines or not lines[0].startswith("# "):
        raise SystemExit(f"{src}: the first line is not the title")
    lines[0] = f'<a id="{anchor}"></a>\n\n# {heading}'

    def target(m):
        label, t = m.group(1), m.group(2)
        if t.startswith(("http://", "https://", "mailto:", "#")):
            return m.group(0)
        path, _, frag = t.partition("#")
        name = pathlib.PurePosixPath(path).name
        for other, (other_anchor, _) in names.items():
            if name in (other + ".md", other + ".ja.md"):
                return f"[{label}](#{other_anchor})"
        resolved = (pathlib.PurePosixPath("docs/operations") / path)
        parts = []
        for p in resolved.parts:
            if p == "..":
                if not parts:
                    raise SystemExit(f"{src}: the link {t} leaves the repository")
                parts.pop()
            elif p != ".":
                parts.append(p)
        if not (repo / pathlib.PurePosixPath(*parts)).exists():
            raise SystemExit(f"{src}: the link {t} points to no file")
        where = "/".join(parts)
        return f"{label}（`{where}`）" if suffix == ".ja.md" else f"{label} (`{where}`)"

    text = "\n".join(link.sub(target, line) for line in lines) + "\n"
    out = tmp / f"{anchor}.md"
    out.write_text(text, encoding="utf-8")
    print(f"  {out.name}: {len(lines)} lines from {src.relative_to(repo)}")
PY

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
    --metadata "title=${title}" \
    --metadata "subtitle=${subtitle}" \
    --metadata "lang=${lang}" \
    --metadata "identifier=urn:tukuyomi-core:guide:${lang}:${DOC_VERSION}" \
    --metadata "creator=vril" \
    --metadata "rights=${rights}" \
    --metadata "date=${TODAY}" \
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
