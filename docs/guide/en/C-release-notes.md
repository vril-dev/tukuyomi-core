# Appendix C. Release Notes

The release notes as they were published, newest first.

## 0.2.0

### Summary

- **Each upstream can choose its inspection engine.** In 0.1.0, the engine of the one chosen generation inspected every request. An upstream now names its engine with `engine` (`coraza` or `modsecurity`), and an upstream without it uses `kernel.default_engine` (`coraza` when it is not set). The proxy runs one inspection kernel for each started engine and inspects a request only with the engine of its upstream. Upstreams with a server at the same address must use the same engine.
- **The rules store keeps one chosen generation for each engine.** `rules activate` chooses a generation for its engine, and `rules list` can mark two generations as `current`. The new `rules deactivate <config> <engine>` removes the choice of an engine. The `current` file written by 0.1.0 is read as the chosen generation of its engine.
- **SIGUSR1 switches the engines one at a time** (the default engine first, then by name), and starts an engine that has a chosen generation but does not run. A reload (SIGHUP or the control socket's `reload`) is refused while an upstream names an engine that does not run.
- **The admin API and screens work for each engine.** `GET /api/status` reports `default_engine` and `engines`, `POST /api/rollback` takes `engine`, history rows carry `engine`, and the log search filters by engine. The screens show the state of each engine, start an engine, and choose the engine of an upstream. Against a proxy of 0.1.0, the admin process refuses to choose or roll back a generation (`409 the proxy does not report its engines`).
- **An import without an engine is for the default engine** (`rules import` without `--engine`, and the admin API import without `engine`).
- `/metrics` adds `tukuyomi_inspector_engine_up` and `tukuyomi_inspector_engine_restarts_total` for each engine.

### Upgrade notes

- **Replace the admin process, the proxy and the records shipper with the same release.** The records shipper of 0.1.0 does not accept `kernel.default_engine` or the `engine` of an upstream, so write those keys only after it is replaced.
- **If 0.1.0 had a ModSecurity generation chosen**, add `"default_engine": "modsecurity"` to `kernel`. Without it, the start and `config check` are refused with `rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine`. With a Coraza generation chosen, nothing needs to be added.
- **Going back to 0.1.0:** 0.1.0 reads only `current`. While nothing is chosen with 0.2.0 and the new keys are not written, putting back the 0.1.0 executables is enough. After `rules activate` with 0.2.0, follow the steps in the operator reference, section 「バージョンの更新」 (the documents are in Japanese).
- Each started engine runs its own inspector process, so starting a second engine adds one process and its memory. The measured values are in the operator reference, section 「検査エンジンの選択」.

### Validation

- The whole test suite passed on the release tree, built with `--offline --locked`: the inspection kernel, the proxy (942 unit tests and 112 process tests), the ModSecurity inspector, the records shipper with its database tests, and clippy and fmt. The admin UI tests (155) passed.
- The new behaviour was checked with release executables: two engines with the OWASP Core Rule Set, each passing ordinary requests and blocking SQL injection with its own engine in the logs; a reload refused until SIGUSR1 started the engine; `kernel.default_engine` set to `modsecurity`; a proxy of 0.1.0 with the new admin process (409, nothing changed); and going back to 0.1.0 and forward again.
- Built the four executables and the tarball; verified the checksums; two builds of the tarball are the same bytes. The release ModSecurity inspector, with a Core Rule Set generation, passed an ordinary request and blocked SQL injection. The dependencies are the same as in 0.1.0. Requirements: Linux x86_64 with Landlock (5.13 or later), glibc 2.39 or later, and for the ModSecurity inspector libstdc++ with `GLIBCXX_3.4.29` and `CXXABI_1.3.15`.

**Full changelog:** https://github.com/vril-dev/tukuyomi-core/compare/v0.1.0...v0.2.0

## 0.1.0

The release notes of 0.1.0 were published in Japanese only. They are on the GitHub release page of v0.1.0 (<https://github.com/vril-dev/tukuyomi-core/releases/tag/v0.1.0>).
