#!/usr/bin/env bash
# Chapter list, per-language metadata and the appendix step shared by the operations guide builders (build-epub.sh,
# build-pdf.sh). Source this file; it only defines variables and functions.

GUIDE_BOOK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

GUIDE_BOOK_CHAPTERS=(
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

# guide_book_load LANG VERSION
#
# Sets GUIDE_BOOK_DIR, GUIDE_BOOK_TITLE, GUIDE_BOOK_SUBTITLE, GUIDE_BOOK_META_VERSION, GUIDE_BOOK_EDITION_SUBTITLE,
# GUIDE_BOOK_DOC_TITLE, GUIDE_BOOK_TOC_TITLE, GUIDE_BOOK_SUFFIX, GUIDE_BOOK_APPENDIX_A and GUIDE_BOOK_APPENDIX_B for
# LANG. Returns 1 for an unknown LANG.
guide_book_load() {
  local lang="$1"
  local version="$2"

  case "$lang" in
    ja)
      GUIDE_BOOK_DIR="$GUIDE_BOOK_ROOT/ja"
      GUIDE_BOOK_TITLE="tukuyomi core"
      GUIDE_BOOK_SUBTITLE="運用ガイド ── 日本語版"
      GUIDE_BOOK_META_VERSION="${version} ベース"
      GUIDE_BOOK_EDITION_SUBTITLE="${GUIDE_BOOK_SUBTITLE}（${GUIDE_BOOK_META_VERSION}）"
      GUIDE_BOOK_DOC_TITLE="tukuyomi core 運用ガイド（日本語版）"
      GUIDE_BOOK_TOC_TITLE="目次"
      GUIDE_BOOK_SUFFIX=".ja.md"
      GUIDE_BOOK_APPENDIX_A="付録A　運用リファレンス"
      GUIDE_BOOK_APPENDIX_B="付録B　管理リファレンス"
      ;;
    en)
      GUIDE_BOOK_DIR="$GUIDE_BOOK_ROOT/en"
      GUIDE_BOOK_TITLE="tukuyomi core"
      GUIDE_BOOK_SUBTITLE="Operations Guide ── English Edition"
      GUIDE_BOOK_META_VERSION="based on ${version}"
      GUIDE_BOOK_EDITION_SUBTITLE="${GUIDE_BOOK_SUBTITLE} (${GUIDE_BOOK_META_VERSION})"
      GUIDE_BOOK_DOC_TITLE="tukuyomi core Operations Guide (English Edition)"
      GUIDE_BOOK_TOC_TITLE="Contents"
      GUIDE_BOOK_SUFFIX=".md"
      GUIDE_BOOK_APPENDIX_A="Appendix A. Operator Reference"
      GUIDE_BOOK_APPENDIX_B="Appendix B. Admin Reference"
      ;;
    *)
      return 1
      ;;
  esac
}

# guide_book_appendices TMP_DIR REPO_ROOT
#
# Writes appendix-a.md and appendix-b.md into TMP_DIR. Appendix A and B are not kept in docs/guide: they are taken
# from docs/operations/operator-reference and admin-reference, in the language that guide_book_load chose, so the
# reference exists in one place only. Links between the two references go to the appendix in the book. A link to
# another document of the repository becomes its name followed by its path in the repository, as the chapters write
# it, so that the book has no link to a file that a release tag may not have. Exits when a reference does not start
# with its title or links to a file that does not exist.
guide_book_appendices() {
  TMP_DIR="$1" REPO_ROOT="$2" SUFFIX="$GUIDE_BOOK_SUFFIX" \
  APPENDIX_A="$GUIDE_BOOK_APPENDIX_A" APPENDIX_B="$GUIDE_BOOK_APPENDIX_B" python3 -I - <<'PY'
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
    # The anchor follows the title, so that a link to the appendix opens its first page, not the end of the chapter
    # before it.
    lines[0] = f'# {heading}\n\n<a id="{anchor}"></a>'

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
}
