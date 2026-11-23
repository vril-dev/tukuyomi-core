# Chapter 4. Rule Sets and Generations

tukuyomi core handles the rules that inspect requests in units called generations. This chapter explains the three separate operations: creating a generation (import), choosing it (choice), and having the running proxy use it (SIGUSR1).

It then covers the flow from detect-only mode to block mode, bypass routes, ModSecurity generations, and choosing the inspection engine for each upstream. The list of command arguments and exit codes is in "`rules`" in Appendix A (Operator Reference).

## 4.1 How Generations Work

A generation is a rule set created by `rules import`. It is identified by its fingerprint (the SHA-256 of the manifest). Once created, a generation does not change.

Each generation is also tied to one engine, which inspects requests with its rules. The engines in this build are `coraza` (Coraza) and `modsecurity` (ModSecurity v3). Specify the engine with `rules import --engine`. If it is omitted, the engine is the one written in `kernel.default_engine` in the configuration, or `coraza` if that is not written.

Even with the same rule files, a different engine gives a different manifest, and so a different generation (a different fingerprint). A `modsecurity` generation can be imported, chosen, and started only when `kernel.engines` in the configuration has an inspector process.

A generation goes through three operations before it is in use. Each is a separate command or signal, and only the last one changes the running proxy.

| Operation | What it does | Effect on the running proxy |
|---|---|---|
| Import (`rules import`) | Builds a rule set from the input and puts it in the rules store. A rule set that passes the trial becomes a generation. The generation is not chosen at this point | None |
| Choice (`rules activate`) | Makes the generation the chosen generation of its engine | None. Proxies that start later, and proxies that receive SIGUSR1, use the chosen generation |
| Switch (SIGUSR1) | Switches each engine to its chosen generation | New requests that arrive after the switch are inspected with the new generation |

The `rules` commands are short-lived and run as processes separate from the running proxy, which does not notice the changes they make. The admin API, on the other hand, chooses a generation and then asks the running proxy to switch (see Chapter 5).

The fingerprint detects accidental corruption and mix-ups, and also a start in which the contents do not match the fingerprint that the running proxy holds. It does not stop a process running as the same OS user (the inspector process also runs as that user) from rewriting the rules store. For the contents of the rules store, see "Rule Sets and Generations" in Appendix A (Operator Reference).

## 4.2 Importing a Rule Set

```text
tukuyomi-proxy rules import <config> [--crs <dir>] [--crs-off <name>]... [--rules <file>]... [--data <file>]... [--routes <file>] [--engine <name>] [--accept-block] [--detect-only]
```

For the first import, we recommend creating a detect-only generation (section 4.5 explains why). Use the CRS that you downloaded in section 2.6. Run the command as the OS user of the service.

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules import /etc/tukuyomi-core/config.json --crs /var/lib/tukuyomi-core/crs-4.23.0 --detect-only
```

The main options are as follows.

- `--crs <dir>`: the CRS directory. To leave some of the `.conf` files in `crs/rules/` unloaded, name each one with `--crs-off <name>`.
- `--rules <file>`: an operator rule file. It can be given any number of times, and the files are loaded after the CRS, in the order given. Data files that the operator rules read are given with `--data <file>`.
- `--routes <file>`: the bypass route file (see section 4.6).
- `--engine <name>`: the inspection engine of the generation, `coraza` or `modsecurity` in lowercase.
- `--detect-only`: makes a detect-only generation (see section 4.5).
- `--accept-block`: does not fail the trial even if a trial request is blocked.

The naming rules for the files in a rule set, and the limits on their number and size, are in "`rules`" in Appendix A (Operator Reference).

### The Trial

An import starts one inspector process and inspects three fixed requests (`GET /`, `POST /` with the form body `a=b`, and `POST /` with the JSON body `{"a":"b"}`). This is the trial.

A generation is created only if the trial passes, and `<fingerprint> created` is written to standard output. If a generation with the same content already exists, `<fingerprint> already exists` is written.

- For a generation in block mode, the trial fails if even one trial request is blocked (unless `--accept-block` is given). If, for example, you made the settings in `crs-setup.conf` stricter, read the log and adjust them, or add `--accept-block`. For a detect-only generation, a match with a rule does not fail the trial.
- The trial shows only that the rule set starts and lets ordinary requests through. It does not show that the rules are correct.
- An import starts an inspector process, so it also runs the checks before start (see Chapter 3). The inspector process started for the trial is also restricted (Landlock) in the same way as the other inspector processes.

### Constraints on Operator Rules

In a Coraza generation, the inspector process adds settings and rules after the operator rules given with `--rules`. Operator rules cannot change these settings and rules. For the constraints on ModSecurity generations, see section 4.7.

- Rule IDs 4000001 to 4000003 are used by the inspector process in all generations. 4000010 and 4000011 are used in detect-only generations. If an operator rule uses the same ID, the rule set of that generation cannot be built.
- A rule that contains `Include`, `SecIgnoreRuleCompilationErrors`, a directive whose name starts with `SecAuditLog`, `SecDebugLog`, or `SecUpload`, `ctl:ruleEngine`, `ctl:requestBodyAccess`, `ctl:requestBodyLimit`, `@inspectFile`, `@rbl`, `setenv:`, or the variable name `reserved_body_cut` is rejected. The check looks only at the text, so it also matches words inside `msg`, and it ignores case.
- Intentionally removing blocking rules with `ctl:ruleRemoveById`, `SecRuleRemoveById`, and so on is left to the operator's judgment and is not refused.
- By default, the CRS blocks `application/<name>+json` bodies. To accept them, add their types to the accepted types in `crs-setup.conf` before the import.

For the other constraints, see "Settings and Rules Added by the Inspector" and "Operator Responsibilities" in Appendix A (Operator Reference).

## 4.3 Listing, Choosing, Deactivating, and Removing Generations

```text
tukuyomi-proxy rules activate <config> <fingerprint>
tukuyomi-proxy rules deactivate <config> <engine>
tukuyomi-proxy rules remove <config> <fingerprint>
tukuyomi-proxy rules list <config>
```

- `list` lists the generations. Each line shows the fingerprint, the creation time, the mode (`block` or `detect`), and the engine (`coraza` or `modsecurity`). The chosen generation has the `current` marker. If generations are chosen for two engines, the marker is on two lines.
- `activate` chooses a generation. Each engine has one chosen generation. `<fingerprint> current` is written to standard output. If the generation's engine cannot be used, the command refuses and chooses nothing (exit 2).
- `deactivate` removes the choice for that engine and writes `<fingerprint> deactivated` to standard output (see section 4.9).
- `remove` deletes a generation that is not chosen for any engine and is not used by any proxy. A generation in use cannot be deleted.

## 4.4 Switching Generations with SIGUSR1

To make the running proxy use the generation chosen with `rules activate`, send SIGUSR1. Send it only to the proxy's main process, as described in section 3.7.

- The proxy switches the engines whose chosen generation differs from the running one, one at a time. The default engine goes first, and the others follow in order of name.
- To switch, the proxy first starts a new inspection kernel and inspector process with the chosen generation. When the new one is ready, the proxy sends new requests for that engine to it. The old one finishes inspecting the requests it holds and then stops.
- If the new one fails to start or does not become ready, the switch fails. The log gets a `reload: generation <fingerprint> failed to start: <reason>` line, and the old one keeps inspecting as before.
- An engine that has a chosen generation and is not running yet starts in the same switch. For an engine whose chosen generation is the same as the running generation, the proxy writes a `reload: generation <fingerprint> is already running` line and goes on to the next engine.
- A SIGUSR1 received during a switch only writes a `reload: a switch is in progress, ignored` line. During a switch, that engine has one extra inspector process.
- SIGHUP (configuration reload) does not touch the rule generations and does not read the rules store. Generations are switched by SIGUSR1.

For the detailed behavior, see "SIGUSR1 (Generation Switch)" in Appendix A (Operator Reference).

## 4.5 From Detect-Only Mode to Block Mode

We recommend running in detect-only mode first. Check for false positives and add exclusions, and then import a generation in block mode again. The flow is as follows.

1. Import a detect-only generation with `--detect-only`. The command is the first example in section 4.2.
2. Choose it with `rules activate <config> <fingerprint>`, and switch with SIGUSR1.
3. A detect-only generation lets through even the requests that match a rule. For such a request, the request log shows `class` as `forwarded` and `reason` as `detected by a rule`, and `rule` holds the ID of the matching rule (for logs, see Chapter 7).
4. Look at `rule` in the log to find false positives, and add exclusions for those rules.
5. Import a generation in block mode again, without `--detect-only`. Choose it with `rules activate` and switch with SIGUSR1.

A detect-only generation and a generation in block mode use the same rule files and differ only in whether they block. Note the following:

- Even a detect-only generation blocks on the rules 4000001 to 4000003 that the inspector process adds.
- A Coraza detect-only generation adds marker rules (IDs 4000010 and 4000011) before and after the rules. If an operator rule removes or skips them, the request is treated as one that could not be inspected and gets 503. It is never silently blocked or passed through. A ModSecurity generation does not add marker rules.
- An upstream whose engine has a detect-only chosen generation does not block requests, even those that match a rule. At start, reload, and `config check`, the proxy writes an `upstream <name>: engine <engine>, mode detect` line for each such upstream (the line starts with `start:`, `reload:`, or `config check:`). This line shows which upstreams do not block.

## 4.6 Bypass Routes

A bypass route forwards requests for the given `host` and `path` to the upstream without inspection. Write the routes in the file passed to `rules import --routes <file>`. The file is a JSON array of the following form:

```json
[
  {"host": "app.example.com", "path": "/api/uploads", "action": "bypass"}
]
```

- `host` is optional. Other setting keys are rejected. `action` can only be `bypass`.
- A request that matches a route is forwarded to the upstream without inspection. It does not take an inspection slot, so it passes even when inspection is busy or the inspector process is stopped. The proxy still makes its own checks (the header section and the body size limit) before forwarding.
- `path` cannot be only `/`, because that would remove inspection of all requests. `host` cannot contain a wildcard.
- Routes are part of the generation's manifest, and so of its fingerprint. A request is subject only to the routes in the running generation of the engine that inspects it.

For how `host` and `path` match, the limit on the number of routes, and how the upstream is chosen, see "Bypass Routes" in Appendix A (Operator Reference). Section 5.4 shows how to make paths of the admin screens bypass routes.

## 4.7 ModSecurity Generations

A generation created with `rules import --engine modsecurity` inspects requests with libmodsecurity (ModSecurity v3.0.17). The inspector process of this generation is a separate executable (`tukuyomi-inspector-modsecurity`), set in `kernel.engines.modsecurity.inspector` in the configuration. Hosts that do not use ModSecurity generations can omit this setting key.

To write it, add `engines` to `kernel` as follows (the other setting keys of `kernel` are left out):

```json
"kernel": {
  "inspector": "/opt/tukuyomi-core/bin/tukuyomi-inspector",
  "engines": {"modsecurity": {"inspector": "/opt/tukuyomi-core/bin/tukuyomi-inspector-modsecurity"}}
}
```

The import procedure, the trial, `--detect-only`, bypass routes, and the CRS import are the same as for Coraza generations. The differences are as follows.

- Rule IDs 4000001 to 4000011 are reserved for the inspector process. If an operator rule uses one of them, the rule set of that generation cannot be built, whatever the mode.
- Operator rules are accepted only in the fixed form that can be checked. A file with CR at the end of a line, a file that contains NUL, and a file that does not end with a newline are rejected. So is anything not in the fixed form, anything that breaks the limits on directives and actions, and anything that contains an operator or variable that cannot be used. In each case the inspector process does not start (exit 11) and the import fails. The reason and the name of the rule file appear in the `rules import: the inspector said:` line on standard error. Even syntax that ModSecurity can read is rejected unless it is in the fixed form that can be checked, so a harmless rule may be rejected.
- The same rules and requests can give different results. For example, a JSON body nested 62 to 64 levels deep is blocked by Coraza but not by ModSecurity. A multipart body with an empty boundary is treated as uninspectable in a ModSecurity generation and gets 503.

For the details of the accepted form and the differences from Coraza generations, see "ModSecurity Generations" in Appendix A (Operator Reference). To build the inspector process from source, see "ModSecurity Inspector" in Build and Deployment (`docs/build/binary-deployment.md`) in the repository documentation.

## 4.8 Choosing the Inspection Engine

### The `engine` of an Upstream

You can choose the inspection engine for each upstream: set the upstream's `engine` to `coraza` or `modsecurity`. To write `modsecurity`, `kernel.engines` in the configuration needs an inspector process, as described in section 4.7. Without one, the configuration is rejected with `kernel.engines has no inspector for the engine of an upstream`.

```json
"upstreams": {
  "app": {
    "servers": [
      {"address": "127.0.0.1:8080", "weight": 1, "max_fails": 0, "fail_timeout_ms": 10000, "backup": false}
    ],
    "engine": "modsecurity"
  }
}
```

- An upstream that omits `engine` is inspected by the default engine (`kernel.default_engine`; `coraza` if it is not written). The engine used when `rules import` is run without `--engine` is also the default engine.
- A request is inspected by the engine of the upstream it goes to. Only the inspection kernel of that engine is used, and the request is never sent to another engine. If that inspection kernel is unavailable, the proxy responds with 503.
- If upstreams that have a server at the same address use different engines, the configuration is rejected (`two upstreams with a server at the same address have different engines`). If that were allowed, a client could choose the `Host` to reach that server through the upstream with the weakest engine or mode. The operator must give the same engine to upstreams that reach the same server under different names.
- For the form of the setting keys and the values that are rejected, see "`forward`" and "`kernel`" in Appendix A (Operator Reference).

### Engines to Start

The proxy starts every engine that has a chosen generation and an inspector process in the configuration. The default engine starts first, and the others follow in order of name. An engine that no upstream uses starts as well.

- The default engine and the engines that upstreams use need a chosen generation. Without one, both start and `config check` are refused with `rules store refused: no generation is chosen`.
- If the default engine has no chosen generation but another engine has one, the configuration is refused with `rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine` (exit 1). To start with ModSecurity only, set `kernel.default_engine` in the configuration to `modsecurity` and choose a ModSecurity generation.
- An engine that has started does not stop until the proxy stops, even when you run `rules deactivate`. If its inspection kernel fails, the whole proxy stops, even for an engine that no upstream uses and that is not the default engine (`stop: the kernel failed: <reason>`, exit 1).
- For a guide to memory use, see "Choosing the Inspection Engine" in Appendix A (Operator Reference).

### Steps to Change the Default Engine

Changing the default engine also changes the inspection engine of the upstreams that omit `engine`, so for an upstream you do not want to change, first write its current engine in `engine`. `kernel` cannot change while running, so change `kernel.default_engine` by restarting the proxy.

The following example shows the steps to change the default engine from `coraza` to `modsecurity` in a configuration with `managed`. Run the commands as the same OS user as the service.

```text
tukuyomi-proxy rules import <config> --engine modsecurity --crs <crs-dir> --rules <rules-file> --routes <routes-file>   # the generation for the new default engine; do not choose it yet
tukuyomi-proxy managed import <config> <document>         # a version that writes the current engine in engine for every upstream
tukuyomi-proxy managed activate <config> <version>        # select the version made above
kill -HUP <proxy-pid>
   reload: configuration replaced <sha256> managed <version>
tukuyomi-proxy rules activate <config> <fingerprint>      # the generation for the new default engine; do not send SIGUSR1
tukuyomi-proxy rules list <config>                        # two lines have the current marker (the Coraza generation and the ModSecurity generation)
(write "default_engine": "modsecurity" in kernel of the configuration file)
tukuyomi-proxy config check <config>                      # accepted
(restart the proxy and the admin process)
   start: rules engine modsecurity
   start: rules engine coraza
```

- Create the generation for the new default engine with the first `rules import`. Put the CRS tuning for the admin Host and the bypass route for the import route into that generation as well (see "CRS Tuning for the Admin Host" and "Bypassing Inspection for the Import Route" in Appendix B (Admin Reference)).
- Choose that generation before you write `kernel.default_engine`. As long as you do not send SIGUSR1, that engine does not start and the proxy keeps running.
- If you write `kernel.default_engine` and run `config check` before you choose the generation, the configuration is refused with `rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine` (exit 1). Start is refused with the same message.
- Even if `config check` says `accepted`, SIGHUP to the running proxy is refused with `reload: configuration refused: kernel cannot change while running`. Restart to make the change. The admin process also reads `kernel.default_engine` from the configuration file, so restart it together with the proxy.
- After the restart, the `start: rules engine` line of the default engine comes first. Requests to the admin route are inspected by the new default engine. Requests to an upstream that has `engine` are inspected by the engine written there. The `engine` field of the request log shows which engine inspected a request.

## 4.9 Chosen Generation per Engine

The rules store holds one chosen generation for each engine. The files are `current.coraza` and `current.modsecurity`. `rules activate` writes `current.<engine>` for the engine of the chosen generation. Even if the write stops halfway, half-written content is never read.

- A `current` written by an earlier version is read as the chosen generation of the same engine. Once you choose with this version, however, the earlier version can no longer read the chosen generation of that engine (see section 9.4 and "Version Updates" in Appendix A (Operator Reference)).
- If, for the same engine, both `current` and `current.<engine>` exist and point to different generations, they are rejected with `the current generation records of the engine disagree`. `rules list`, `config check`, start, and SIGUSR1 all behave the same way. Choosing a generation for that engine again with `rules activate` brings it back to normal.

`rules deactivate <config> <engine>` removes the choice for that engine.

- An engine whose choice was removed does not start from the next restart. The running proxy does not stop the inspection kernel of an engine that has started, so that engine keeps running until you restart the proxy. A SIGUSR1 before the restart writes a `reload: rules store refused: no generation is chosen` line.
- If that engine is the default engine or is used by any upstream, the command writes a `rules deactivate: the configuration uses the engine` line and refuses (exit 1). If that engine has no chosen generation, the command refuses with a `rules deactivate: no generation is chosen` line (exit 1).

### Adding an Upstream for an Engine That Is Not Running

An engine can have a chosen generation and still not be running, for example when no ModSecurity generation was chosen at start. A configuration reload does not start inspector processes, and it refuses an upstream whose engine is not running, so the order of the steps matters when you write such an engine in an upstream.

The following example adds a ModSecurity upstream `mod` to a proxy that has only Coraza running. The configuration has `managed`.

1. Choose the ModSecurity generation with `rules activate`. Do not send SIGUSR1 yet.
2. Use `managed activate` to select a version that has the upstream `mod`. `managed activate` refuses, and selects nothing, when an engine used by an upstream of the version has no chosen generation, so do step 1 first.
3. Send SIGUSR1 to start ModSecurity.
4. Send SIGHUP (`systemctl reload`) to reload the configuration. The log gets a `reload: configuration replaced <sha256> managed <version>` line.

If you send SIGHUP before step 3, ModSecurity is not running, so the reload is refused with `reload: configuration refused: the engine of an upstream is not ready (upstream mod)`. The proxy keeps running with the previous configuration, and the `refused` count of `tukuyomi_config_reloads_total` goes up by 1.

## 4.10 Operational Notes

- **A generation needs three operations before it is in use**: import, choice, and switch (SIGUSR1). The commands alone do not change the running proxy.
- **Start with `--detect-only`**: check for false positives, then import a generation in block mode again. Even a detect-only generation blocks on rules 4000001 to 4000003.
- **Passing the trial does not mean that the rules are correct**: the trial shows only that the rule set starts and lets ordinary requests through (see section 4.2).
- **The `path` of a bypass route cannot be only `/`**: that would remove inspection of all requests. For the engine that inspects requests to the admin screens, keep the same route for the admin screens in every generation.
- **`rules deactivate` does not stop an engine of the running proxy**: restart to stop it.
- **Order for adding an upstream for an engine that is not running**: start the engine with SIGUSR1, then send SIGHUP.
- **Failure of an engine that is not used**: if its inspection kernel fails, the whole proxy stops, even when no upstream uses the engine.
- **Changing `kernel.default_engine` needs a restart**: SIGHUP is refused.
