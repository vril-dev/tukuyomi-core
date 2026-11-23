# Appendix C. Release Notes

The release notes as they were published, newest first.

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
