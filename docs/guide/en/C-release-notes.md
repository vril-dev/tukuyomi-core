# Appendix C. Release Notes

The release notes as they were published, newest first.

## 0.2.1

### Summary

- **The operations guide, the documentation rearranged as a book, is now available in English and Japanese.**
  - Each release now comes with the book as EPUB and PDF: `tukuyomi-core_v0.2.1_guide_en.epub`, `tukuyomi-core_v0.2.1_guide_en.pdf`, `tukuyomi-core_v0.2.1_guide_ja.epub`, and `tukuyomi-core_v0.2.1_guide_ja.pdf`.
  - The book has a preface, nine chapters, and three appendices: the operator reference, the admin reference, and the release notes of earlier releases.
  - The books are not in the tarball, but the tarball's `docs/` now includes their sources and build scripts in `docs/guide/`.
  - `tukuyomi-core_v0.2.1_SHA256SUMS` has a line for the tarball and for each of the four books. The files are described in "Release Tarball" in the build and deployment guide.
- **The documentation is now in English and Japanese.** In 0.2.0, it was in Japanese only.
  - Each document has an English file, `foo.md`, and a Japanese file, `foo.ja.md`, with links at the top to switch between them.
  - The Japanese documents, which were `foo.md` in 0.2.0, are now `foo.ja.md`.
  - `README.md` links to the English documents, and `README.ja.md` to the Japanese ones.
- **The English text of the admin screens now reads naturally and uses the same terms as the documentation.**
  - For example, "Sign in" and "Sign out" are now "Log in" and "Log out", and "Serving" is now "Running".
  - "Not reachable" is now "Unreachable", and "Not known" is now "Unknown".
- **Descriptions on the admin screens that did not match the actual behavior were corrected, in English and Japanese.**
  - The screens now say correctly which APIs an API token can use and what each role allows.
  - They now describe correctly how the proxy closes connections when a managed configuration version is applied, and when to replace the records shipper as you start using the managed configuration.
  - They also correct which engine inspects requests to the admin screens, what a generation's fingerprint is, and the message for a control socket at its connection limit.
  - English row counts now read correctly for a single row ("Rows: 1").
- **Going back to the previous version now means restoring the backup taken before the update.**
  - The operator reference no longer has separate steps for going back to each version.
  - Instead, it describes one procedure for every version: before an update, back up the configuration file and the stores, such as the rules store; to go back, restore that backup.
  - It also states that, until 1.0, only updates from the previous release are supported.
- **Other documentation fixes.**
  - The first lines of a start, written before the log files are opened, go only to standard error, and the operator reference now says so.
  - The records shipper deletes old lines from the DB only when `records.ship.retention_days` is not 0.
  - `SSL_CERT_FILE` takes the certificate of the certificate authority that issued the DB server's certificate.
  - The English and Japanese text was rewritten to read more naturally.

### Upgrade notes

- **Updates are supported from 0.2.0.** Until 1.0, only updates from the previous release are supported.
  - Setting keys, commands, log lines, and the admin API are the same as in 0.2.0, so the 0.2.0 configuration file and stores are used as they are.
  - Inside the executables, only the text of the admin screens changed.
- **Before you update from 0.2.0, take a backup.**
  - The steps are in "Backup Before an Update" in the operator reference. The 0.2.0 documentation does not have this section.
  - Going back to 0.2.0 means restoring this backup.
  - After taking the backup, replace all the executables with those of this release. The admin process, the proxy, and the records shipper must be of the same release.
  - Start the admin process, the proxy, and the records shipper in this order, and then start the certificate renewal timer.
- **If you run 0.1.0, update to 0.2.0 first.** Follow the upgrade notes of the 0.2.0 release and "Updating from 0.1.0" in the operator reference.
- **To go back to 0.2.0, restore the backup taken before the update.** The steps are in "Going Back to the Previous Version" in the operator reference. Changes made after the update, such as generations imported or chosen and users created, are lost.
- The English text of the admin screens changed, so check any runbook or script that relies on that text. In Japanese, only the corrected descriptions changed, and the admin API did not change.

### Validation

- The whole test suite passed on the release tree, built with `--offline --locked`:
  - the inspection kernel;
  - the proxy: 942 unit tests and 112 process tests;
  - the ModSecurity inspector;
  - the records shipper with its database tests;
  - clippy and fmt.
- The 155 admin UI tests also passed.
- Built the four executables and the tarball, and verified the checksums. Two builds of the tarball are byte-identical.
  - The release ModSecurity inspector, with a Core Rule Set generation, passed an ordinary request and blocked SQL injection.
  - The dependencies are the same as in 0.2.0.
  - Requirements: Linux x86_64 with Landlock (5.13 or later), glibc 2.39 or later, and for the ModSecurity inspector, libstdc++ with `GLIBCXX_3.4.29` and `CXXABI_1.3.15`.
- Built the EPUB and PDF books from the same commit as the tarball. Two builds of each EPUB are byte-identical.
  - Two builds of a PDF differ, because Chrome writes the build time and identifiers into it. The SHA-256 values of the PDFs are in `tukuyomi-core_v0.2.1_SHA256SUMS`.

**Full changelog:** https://github.com/vril-dev/tukuyomi-core/compare/v0.2.0...v0.2.1

## 0.2.0

### Summary

- **Each upstream can choose its inspection engine.** In 0.1.0, one generation was chosen, and its engine inspected every request.
  - An upstream names its engine with `engine`: `coraza` or `modsecurity`.
  - An upstream without `engine` uses `kernel.default_engine`, which is `coraza` when it is not set.
  - The proxy runs one inspection kernel for each started engine, and inspects each request only with the engine of the upstream it goes to.
  - Upstreams with a server at the same address must use the same engine; a configuration that gives them different engines is rejected.
- **The rules store keeps one chosen generation for each engine.**
  - `rules activate` chooses a generation for its engine.
  - `rules list` can mark two generations as `current`.
  - The new `rules deactivate <config> <engine>` clears the chosen generation of an engine.
  - A `current` file written by 0.1.0 is read as the chosen generation for that generation's engine.
- **SIGUSR1 switches the engines one at a time.**
  - The default engine goes first, then the others by name.
  - SIGUSR1 also starts an engine that has a chosen generation but is not running.
  - A reload (SIGHUP or the control socket's `reload`) is refused while an upstream names an engine that is not running.
- **The admin API and screens handle each engine.**
  - `GET /api/status` reports `default_engine` and `engines`.
  - `POST /api/rollback` takes `engine`.
  - History rows carry `engine`.
  - The log search filters by engine.
  - The screens show the state of each engine, start an engine, and choose an upstream's engine.
  - With a 0.1.0 proxy, the admin process refuses to choose or roll back a generation (`409 the proxy does not report its engines`).
- **An import without an engine becomes a generation of the default engine.** This covers `rules import` without `--engine` and an admin API import without `engine`.
- `/metrics` adds `tukuyomi_inspector_engine_up` and `tukuyomi_inspector_engine_restarts_total` for each engine.

### Upgrade notes

- **Replace the admin process, the proxy and the records shipper with the same release.** The 0.1.0 records shipper does not accept `kernel.default_engine` or an upstream's `engine`. Write those keys only after it is replaced.
- **If 0.1.0 had a ModSecurity generation chosen, add `"default_engine": "modsecurity"` to `kernel`.** Without it, startup and `config check` are refused with `rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine`. If a Coraza generation was chosen, nothing needs to be added.
- **Going back to 0.1.0**: 0.1.0 reads only `current`.
  - If nothing has been chosen with 0.2.0 and the new keys have not been written, putting back the 0.1.0 executables is enough.
  - After `rules activate` with 0.2.0, follow the steps in the operator reference, section 「バージョンの更新」 (the documents are in Japanese).
- Each started engine runs its own inspector process, so starting a second engine adds one process and the memory it uses. The measured values are in the operator reference, section 「検査エンジンの選択」.

### Validation

- The whole test suite passed on the release tree, built with `--offline --locked`:
  - the inspection kernel;
  - the proxy: 942 unit tests and 112 process tests;
  - the ModSecurity inspector;
  - the records shipper with its database tests;
  - clippy and fmt.
- The 155 admin UI tests also passed.
- The new behaviour was checked with release executables:
  - two engines with the OWASP Core Rule Set, each passing ordinary requests and blocking SQL injection, with its own engine in the logs;
  - a reload refused until SIGUSR1 started the engine;
  - `kernel.default_engine` set to `modsecurity`;
  - a 0.1.0 proxy with the new admin process (409, nothing changed);
  - going back to 0.1.0 and forward again.
- Built the four executables and the tarball, and verified the checksums. Two builds of the tarball are byte-identical.
  - The release ModSecurity inspector, with a Core Rule Set generation, passed an ordinary request and blocked SQL injection.
  - The dependencies are the same as in 0.1.0.
  - Requirements: Linux x86_64 with Landlock (5.13 or later), glibc 2.39 or later, and for the ModSecurity inspector, libstdc++ with `GLIBCXX_3.4.29` and `CXXABI_1.3.15`.

**Full changelog:** https://github.com/vril-dev/tukuyomi-core/compare/v0.1.0...v0.2.0

## 0.1.0

The release notes of 0.1.0 were published in Japanese only. They are on the GitHub release page of v0.1.0 (<https://github.com/vril-dev/tukuyomi-core/releases/tag/v0.1.0>).
