---
title: "tukuyomi core"
subtitle: "Operations Guide ── English Edition"
language: en
audience: "Engineers who deploy and operate tukuyomi core (infrastructure, SRE, platform teams)"
version: "based on 0.2.1"
build: "pandoc → EPUB 3; pandoc → HTML → Chrome → PDF"
---

# tukuyomi core Operations Guide (English Edition)

This book rearranges the English documentation in the tukuyomi core repository (`README.md` and `docs/**/*.md`) into a book that can be read from start to finish. The exact definitions of setting keys and behavior are in the documentation, and this book points to them.

## Policy of This Book

- **Readers**: engineers who deploy and operate tukuyomi core (infrastructure, SRE, platform teams). Basic knowledge of Linux, HTTP/HTTPS, TLS, and systemd is assumed.
- **Terms**: the same terms as the documentation.
- **Structure**: each chapter follows the order overview → how it works → configuration examples → operational notes.
- **Consistency**: setting keys, commands, log lines, and screen terms match the documentation. Every fact in this book is in the documentation or in the published release notes (Appendix C).
- **Scope**: only what 0.2.1 implements. What is not implemented or not decided is marked as such.
- **Languages**: the English edition has the same chapters and sections as the Japanese edition (`docs/guide/ja/`).

## Contents

- **Preface** — the scope of this book, how to read it, conventions, and its relation to the documentation
- **Chapter 1. Introduction to tukuyomi core** — what the product does, its components, and what is not implemented
  (source: docs/detailed-design/00_overview/system-overview.md, README.md)
- **Chapter 2. Quick Start** — from the release tarball to a first start with the first generation, and a check that a request is blocked
  (source: README.md, "First Start" in docs/build/binary-deployment.md)
- **Chapter 3. Deployment with systemd** — OS user and directories, units, the checks before start, and restricting the inspector processes
  (source: docs/build/binary-deployment.md)
- **Chapter 4. Rule Sets and Generations** — importing, choosing, and switching generations, detect-only mode, bypass routes, and choosing the inspection engine
  (source: "Commands", "Signals", and "Rule Sets and Generations" in docs/operations/operator-reference.md)
- **Chapter 5. Managed Configuration and the Admin Screens** — preparing the admin process, users and roles, managed configuration versions and applying them, and the admin screens
  (source: "Managed Configuration" in docs/operations/operator-reference.md, docs/operations/admin-reference.md)
- **Chapter 6. Access Control and Rate Limiting** — `access`, rate limiting, host policies, and the country database
  (source: "Access Control and Rate Limits" in docs/operations/operator-reference.md)
- **Chapter 7. Logs and the Records Shipper** — request logs, log files, and the records shipper
  (source: "Logs" and "Records Shipper" in docs/operations/operator-reference.md)
- **Chapter 8. Certificates with ACME** — requirements, the first issue, and renewal
  (source: "ACME" and "ACME Sites" in docs/operations/operator-reference.md)
- **Chapter 9. Operations** — monitoring, configuration reload, stopping, version updates, and going back
  (source: "Signals", "Stopping", "Monitoring", and "Version Updates" in docs/operations/operator-reference.md)
- **Appendix A. Operator Reference** — docs/operations/operator-reference.md, included when the book is built
- **Appendix B. Admin Reference** — docs/operations/admin-reference.md, included when the book is built
- **Appendix C. Release Notes** — 0.2.1, 0.2.0, and 0.1.0

## Files

```
docs/guide/
├── build-epub.sh          … the script that builds the EPUB
├── build-pdf.sh           … the script that builds the PDF
├── book.css               … the style of the EPUB
├── book-pdf.css           … the style of the PDF
├── cjk-line-breaks.lua    … the pandoc filter that drops the line breaks between Japanese sentences
├── lib/guide_book.sh      … the chapter list, the titles, and the appendix step that both scripts use
└── en/
    ├── index.md           … this file (policy and contents)
    ├── 00-preface.md      … Preface
    ├── 01-introduction.md … Chapter 1
    ├── 02-quickstart.md   … Chapter 2
    ├── 03-… to 09-….md    … Chapters 3 to 9
    └── C-release-notes.md … Appendix C
```

There are no files for Appendix A and Appendix B. `build-epub.sh` and `build-pdf.sh` build them from the operator reference and the admin reference in the documentation.

## How the Book Is Built (Notes)

- pandoc joins the chapter files, in the order of the contents, into an EPUB 3 with a table of contents, a title page, and a page break before each chapter.
- The PDF has the same chapters and appendices: pandoc joins them into one HTML file, and Google Chrome (headless) prints it as an A4 PDF. It needs Chrome and the Noto Sans CJK JP font.
- When the environment variable `SOURCE_DATE_EPOCH` (seconds since 1970-01-01 UTC) is set, the date of the book is that day (UTC), and the same files give exactly the same EPUB at every build. Without it, the date is the day of the build. Chrome writes the time of the build and identifiers into the PDF, so those parts of the PDF change at every build.
- Appendix A and Appendix B include the operator reference and the admin reference, with their titles replaced by the appendix titles. Links between the two documents become links to the appendices in the book, and links to other documents become the name of the document and its path in the repository (for example, Build and Deployment (`docs/build/binary-deployment.md`)).
- The cover is text only (title, subtitle, and version).
