[English](operator-reference.md) | [日本語](operator-reference.ja.md)

# Operator Reference

This document is a reference for the commands, signals, configuration file setting keys, rule set handling, managed configuration, request handling, access control and rate limits, logs, and monitoring of the current implementation. For deployment and systemd examples, see the [build and deployment guide](../build/binary-deployment.md). For the settings and API of the admin process (the `admin` command), see the [admin reference](admin-reference.md). This document covers only what is visible from the proxy.

The paths and names used in this document (`/etc/tukuyomi-core/config.json`, the OS user `tukuyomi`, `example.com`, and so on) are examples.

## Commands

Every command is run with the single executable `tukuyomi-proxy`. Pass the configuration file as an absolute path (a path that contains `.`, `..`, an empty component, or a trailing `/` is rejected).

No command can run as root. If any of the process's four user IDs (real, effective, saved, and file system) is 0, the command writes a `host check refused` line and refuses to run (exit 1). Run commands as the OS user of the service (for example, `sudo -u tukuyomi ...`).

### Start

```text
tukuyomi-proxy <config>
```

- Startup proceeds in this order:
  1. Checks before start (not root, SIGCHLD, file descriptors)
  2. The configuration file (if `managed` is present, also the selected version in the managed store and the files it points to; if `geo` is present, also loading and checking the country database)
  3. Upstream server name resolution, and the upstream CA files
  4. The TLS listeners' certificates and keys
  5. The rules store, and the chosen generation of each engine
  6. Opening the log files (when the configuration has `records`)
  7. Binding the monitoring listener (when the configuration has `status`)
  8. Binding the control socket (when the configuration has `admin`)
  9. Starting the inspection kernel and preparing the inspector process (for each engine that starts)
  10. Binding the listeners
- Every engine that has a chosen generation and an inspector process in the configuration starts. The default engine starts first, and the others follow in name order.
  - The default engine and the upstream engines need a chosen generation. If one has none, the proxy writes a `start: rules store refused: no generation is chosen` line and stops (exit 1).
  - If the default engine has no chosen generation but another engine has one, the proxy writes a `start: rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine` line and stops (exit 1). Set `kernel.default_engine`, or choose a generation for the default engine.
  - An engine that no upstream uses also starts if it has a chosen generation (see "Choosing the Inspection Engine" below).
- The log files are opened before the inspector processes. If a log file cannot be opened, the proxy writes a `start: record file refused: ...` line and stops without starting the inspector processes (exit 1).
- The monitoring listener and the control socket are bound before the inspector processes. If either cannot be bound, the proxy stops without starting the inspector processes (exit 1). For the control socket, it writes a `start: control socket refused: ...` line.
- All listeners are bound only after the inspection kernels of every starting engine are ready. If even one cannot be bound, none is used and the proxy stops.
- Signal handling becomes active after step 6. Any signal that arrives earlier (name resolution can take up to `resolve_timeout_ms`) simply ends the proxy.
- The log gets a `start: the kernel is ready` line when the kernels are ready, and a `start: listening` line when the listeners begin to listen (`line` log; see "Logs" below).
- If the environment variable `NOTIFY_SOCKET` is set, the proxy sends `READY=1` after binding all listeners (see "Notifications to systemd" below).
- The exit codes are as follows.

| Exit code | Meaning |
|---|---|
| 0 | Stopped by a signal, and the inspection kernels were confirmed to have stopped (the inspector processes ended and the work directories were removed) |
| 1 | Any other exit. This includes starting as root, a failed check before start, an upstream name that cannot be resolved, an unusable CA file, a rejected certificate or key, a rejected rules store or generation, a default engine or upstream engine without a chosen generation, a rejected managed store or version, a log file that cannot be opened, and a monitoring listener or control socket that cannot be bound (nothing has started in these cases) |
| 2 | An argument error, or a configuration file that was rejected |

### `config check`

```text
tukuyomi-proxy config check <config>
```

- This command runs the same checks as start, up to the chosen generations and the inspection kernel settings (steps 2 to 5 above, and the values of the inspection kernel settings). The only check before start (step 1 above) that it runs is that the process is not root.
  - If everything passes, it writes a single `accepted` line to standard output and exits 0.
  - Other lines go to standard error and begin with `config check:`. Only an argument error gives a line that begins with `config:`, followed by a usage line.
  - The exit codes are the same as for start.
  - It checks the inspection kernel settings for each engine that has a chosen generation. If the inspection kernel settings of a generation cannot be built, it writes a `config check: rules generation refused: <reason>` line and exits 1. The inspection engines in this build are `coraza` and `modsecurity`. `modsecurity` can be used only when `kernel.engines` in the configuration has an inspector process (see `engines` under "`kernel`" below).
  - With the same messages as start, it rejects a default engine or an upstream engine that has no chosen generation (`config check: rules store refused: no generation is chosen`, `config check: rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine`; both exit 1).
  - If the default engine or an upstream engine is `modsecurity` and the configuration has no `kernel.engines`, it rejects the configuration file or version. An engine that no upstream uses is neither checked nor started if the configuration has no inspector process for it, even when a generation is chosen.
  - For each upstream that points to an engine whose chosen generation is detect-only, it writes a `config check: upstream <name>: engine <engine>, mode detect` line.
- If `managed` is present, it loads and checks the selected version of the managed store (`current`) as start does, and writes a `config check: managed version <version>` line. If no version is selected, it writes a `config check: managed store refused: no managed version is chosen` line and exits 1 (see "Managed Configuration" below). While it is reading the version, that version cannot be deleted.
- If `geo` is present, it also loads and checks the country database as start does (`geo` in "Access Control and Rate Limits").
- What it does not check:
  - SIGCHLD and file descriptors (the parts of step 1 above other than the root check)
  - The work directory (`kernel.tmp_root`). It is checked when an inspector process starts
  - That the inspector process executable can start, and that Landlock is available
  - That the generation's engine (Coraza or ModSecurity) can build the rules. This is checked at start. `rules import` runs the trial on the rules before it makes them a generation
  - That the log files can be opened (step 6 above)
  - That the ports of the listeners and of the monitoring listener, and the control socket, can be bound
  - systemd settings
  - The reasons a running proxy refuses a configuration reload (a difference in a setting key that cannot change while running, an upstream engine that is not running, and binding a new listener; see "SIGHUP (Configuration Reload)" below)
- The only thing this command writes is a marker. As at start, it creates a marker in the rules store's `using/` (if one is not there yet) to show that the chosen generation of each engine that would start is in use. The lock on the marker is released when the command exits.
- Run the command as the same OS user as the service. Under a different OS user, the command rejects the configuration when it checks the owner of the rules store and the managed store, and when it reads the key files.

### `rules`

```text
tukuyomi-proxy rules import <config> [--crs <dir>] [--crs-off <name>]... [--rules <file>]... [--data <file>]... [--routes <file>] [--engine <name>] [--accept-block] [--detect-only]
tukuyomi-proxy rules activate <config> <fingerprint>
tukuyomi-proxy rules deactivate <config> <engine>
tukuyomi-proxy rules remove <config> <fingerprint>
tukuyomi-proxy rules list <config>
```

Each of these is a short-lived command that runs as a process separate from the running proxy. The running proxy does not notice the changes these commands make, so to have it use a new generation, send it SIGUSR1 (see "Signals" below). The API of the admin process chooses a generation and then asks the running proxy to switch (see the [admin reference](admin-reference.md); for the request, see "Control Socket").

| Command | What it does | Standard output |
|---|---|---|
| `import` | Builds a rule set from the input, puts it in the rules store, and makes it a generation if it passes the trial. It does not choose the generation | `<fingerprint> created`, `<fingerprint> already exists`, `<fingerprint> recreated, the stored copy was broken` |
| `activate` | Chooses a generation. One generation can be chosen per engine (see "Chosen Generation per Engine" below). Proxies that start later, and proxies that receive SIGUSR1, use it. If the generation's engine cannot be used, the command refuses without choosing it (exit 2) | `<fingerprint> current` |
| `deactivate` | Clears an engine's chosen generation. The next proxy to start does not start that engine. A running proxy does not stop an engine it has started. For the default engine and for an upstream engine, the command refuses without clearing the choice (exit 1; see "Chosen Generation per Engine" below) | `<fingerprint> deactivated` (the generation that is no longer chosen) |
| `remove` | Deletes a generation that is not chosen for any engine and is not used by any proxy | `<fingerprint> removed` |
| `list` | Lists the generations | The fingerprint, the creation time (seconds since the epoch), the mode (`block`, `detect`, or `unknown` if the manifest cannot be read), the engine (`coraza`, `modsecurity`, or `unknown` if the manifest cannot be read), `routes` and the count if the generation has bypass routes, and `current` on the chosen generation of each engine (if two engines have a chosen generation, two lines have it). When the chosen generation cannot be determined (the file cannot be read, the content is invalid, or `current` and `current.<engine>` disagree), it writes all the generation lines, then writes a `rules list: <reason>` line to standard error and exits 1 |

`import` takes the following input. The paths in the options can also be relative to the current directory.

| Option | Content |
|---|---|
| `--crs <dir>` | The CRS directory fetched with `scripts/fetch-crs.sh`. It must contain only `crs-setup.conf` (and optionally `crs-setup.conf.example`) and the `.conf`, `.data`, and `.example` files in `rules/`. Anything else (hidden files, directories such as `plugins`, other extensions, symbolic links) is rejected |
| `--crs-off <name>` | A `.conf` file in `crs/rules/` that is not loaded. It can be given any number of times. Requires `--crs` |
| `--rules <file>` | An operator rule file. It can be given any number of times, and the files are loaded after the CRS, in the order given |
| `--data <file>` | A data file that the operator rules read. It goes into the rule set but is not loaded as rules |
| `--routes <file>` | The bypass route file (see "Bypass Routes" below) |
| `--engine <name>` | The name of the generation's inspection engine: `coraza` or `modsecurity` (lowercase). If omitted, the engine of `kernel.default_engine` in the configuration (`coraza` if `kernel.default_engine` is not set). Any other name, and `modsecurity` when `kernel.engines` in the configuration has no inspector process, is rejected without storing anything (exit 2) |
| `--accept-block` | Does not fail the trial even if a trial request is blocked (the matched rules are printed) |
| `--detect-only` | Makes a detect-only generation (see "Detect-Only Mode" below) |

- The loading order is `crs/crs-setup.conf`, the `.conf` files in `crs/rules/` (in byte order of the names), and then the operator rule files (in the order given).
- The `--rules` and `--data` files are stored in the rule set as `rules/<name>`, where the name is the file name without its directory.
  - A name is 1 to 128 characters of letters and digits, `.`, `_`, and `-`, and cannot start with `.`.
  - The same name is rejected, even across `--rules` and `--data`.
  - An input file that is a symbolic link is rejected, and so is a `--crs` directory that is a symbolic link.
- One file can be up to 2 MiB, and a whole rule set can have up to 128 files and 8 MiB. Up to 1024 directory entries are read. The manifest can be up to 64 KiB, and the file list and the bypass routes share that size.
- The only files that rules can read (with `@pmFromFile` and the like) are files inside the rule set. In a rule, write them as paths inside the rule set (`rules/<name>` and so on).
- The trial starts one inspector process and inspects three fixed requests (`GET /`, `POST /` with the form body `a=b`, and `POST /` with the JSON body `{"a":"b"}`).
  - If the inspector process becomes ready within `ready_wait`, every request is allowed within `inspect_wait`, and the inspector process exits normally, the trial passes.
  - For a generation in block mode, the trial fails if even one trial request is blocked (unless `--accept-block` is given). For a detect-only generation, a match with a rule does not fail the trial.
  - The trial shows only that the rule set starts and lets ordinary requests through. It does not show that the rules are correct.
- If SIGINT (Ctrl-C) or SIGTERM arrives during the trial, the command stops the trial, cleans up the inspector process and the work directory, and exits without making a generation. After the trial, these two signals do not stop the command.
- `import` starts an inspector process, so it also runs the checks before start (see "Checks Before Start" in the [build and deployment guide](../build/binary-deployment.md)).

The exit codes are as follows. 0 is success. 1 is any other exit (a rejected rules store or input, a failed trial, a rules store in use, a generation whose manifest cannot be read in `list` (the whole list is still written), a rules store whose chosen generation cannot be determined, `deactivate` for an engine that the configuration uses or an engine that has no chosen generation, and running as root). 2 is an argument error, a configuration file that was rejected (for `deactivate`, this includes the selected version of `managed`), or an engine that cannot be used (`import` and `activate`). `list` exits 0 for a rules store that has no chosen generation.

### `managed`

```text
tukuyomi-proxy managed import <config> <document>
tukuyomi-proxy managed activate <config> <version>
tukuyomi-proxy managed remove <config> <version>
tukuyomi-proxy managed list <config>
```

These are short-lived commands that work with managed configuration versions (see "Managed Configuration" below), and each runs as a process separate from the running proxy. The commands do not ask the proxy to do anything, so the running proxy loads the selected version at the next SIGHUP (`systemctl reload`) or start. When the admin process applies a version, it asks the proxy over the control socket to reload the configuration and then selects the version (see "Applying" under "Managed Configuration" below). The configuration file must have `managed`. `<version>` is the SHA-256 of the version (64 lowercase hexadecimal digits).

| Command | What it does | Standard output |
|---|---|---|
| `import` | Builds a version from a document and puts it in the managed store. It reads the files that the document points to, checks them in the same way as the proxy, and puts them in `files/`. It does not select the version | `<version> created`, `<version> existing`, `<version> recreated, the stored copy was broken` |
| `activate` | Runs the startup steps that come before the rules store (the configuration file and the version, upstream name resolution and the CA files, the certificates), confirms in the rules store that every engine the version's upstreams use has a chosen generation, and selects the version only if everything passes (it changes `current`). If an upstream uses an engine that has no chosen generation, it writes a `managed activate: rules store refused: no generation is chosen for the engine of an upstream (upstream <name>)` line and refuses without selecting (exit 1). `import` does not make this check | `<version> current` |
| `remove` | Deletes a version that is neither selected nor in use, and cleans up the files that no version points to any longer and the ACME site certificates. It does not check whether the version is a rollback target | `<version> removed` |
| `list` | Lists the versions | The version, the update time of the file (seconds since the epoch), and `current` for the selected version |

- The document path for `import` can also be relative to the current directory. For the document format, see "Managed Store and Versions" below.
- `import` and `activate` also load and check the country database. `remove` and `list` load only the configuration file.
- `import`, `activate`, and `remove` take the managed store lock. If something else holds the lock, for example while the admin process is applying a version, they refuse without waiting (`the managed store is in use by another command`).
- When the certificate of an ACME site is not yet there, `activate` writes a `managed activate: tls certificate not issued yet (site <name>)` line. It does not refuse.
- A version selected with `activate` does not take effect in the running proxy until the next SIGHUP. Run `systemctl reload` right away and check for the `reload: configuration replaced <sha256> managed <version>` line (see "Applying" under "Managed Configuration" below).
- If `remove` cannot finish the whole cleanup, it writes a `managed remove: the files that no version names were not cleaned up` line to standard error and exits 0 (the version has been deleted). The next removal cleans up again.
- Lines other than the result line go to standard error and begin with the name of the command (`managed import: document refused: <reason>` and so on). In a path written in the document, bytes outside 0x20 to 0x7e are printed as `\xNN`.

The exit codes are as follows. 0 is success. 1 is any other exit (a rejected managed store, document, or file, a managed store in use, a name that cannot be resolved or a file that cannot be used in `activate`, a version that `activate` rejects, a version that `remove` refused, a managed store in which `current` cannot be read or in which the version `current` points to does not exist in `list`, and running as root). 2 is an argument error, or a configuration file that was rejected (this includes a configuration file without `managed`).

### `acme renew`

```text
tukuyomi-proxy acme renew <config>
```

- It checks the certificates that have `acme`, in configuration order (with `managed`, the admin route first and then the version's sites; see "ACME Sites" below). A certificate that meets any of the following needs renewal, and the command places a new order for it with a new key.
  - The certificate or key file cannot be read
  - The key does not match the certificate
  - The certificate does not contain all the hosts
  - The time until the end of the validity period is shorter than `renew_before_days` days (exactly that number of days is not shorter)
- A certificate that needs no renewal is `valid`.
- If any certificate needs renewal, the command loads or creates the account key, and then creates an account with the CA or finds the existing one. The account is created with agreement to the CA's terms of service, with `contact_email` as the contact.
- The whole command (including the responses of the CA and the waiting time) takes at most `timeout_ms`. When the time runs out, the certificates that have not been renewed yet, including those after it, become `failed`. A certificate that needs no renewal stays `valid`.
- The result is one line on standard output for each certificate that has `acme`.
  - Without `managed`, the form is `<listener>.<certificate> renewed|valid|failed`. Both numbers count from 1. The listener number is the position in `proxy.listeners`, and listeners without TLS are counted too.
  - With `managed`, the forms are `admin route renewed|valid|failed` and `site <name> renewed|valid|failed`.
  - A `failed` certificate leaves its files as they were.
- With `managed` and `acme`, if no certificate has `acme` (neither the admin route nor a site of the version), the command writes no result line, writes one line to standard error, and exits 0.
- With `managed`, the command loads the `current` version, and that version cannot be deleted until the command exits. It does not take the managed store lock.
- From what it receives from the CA, the only thing it writes to standard error is the `type` of a problem document.
- When it receives SIGINT or SIGTERM, it deletes the challenge files and exits at once.
- The running proxy does not notice new certificates, so after the command, send it SIGUSR2 (`systemctl kill -s SIGUSR2 --kill-whom=main tukuyomi-core.service`).
- The exit codes are as follows.
  - 0: every certificate is `renewed` or `valid` (also when, with `managed`, no certificate has `acme`)
  - 1: at least one is `failed`, the command was stopped, it could not run, or it was run as root
  - 2: an argument error, a configuration file that was rejected (with `managed`, this includes a managed store, `current`, or version with which the proxy would not start), or a configuration file without `acme`

For the procedure, see "ACME" below.

### `admin` (Admin Process Commands)

```text
tukuyomi-proxy admin <config>
tukuyomi-proxy admin bootstrap <config> <name>
tukuyomi-proxy admin reset <config> <name>
```

- `admin <config>` runs the admin process, and `bootstrap` and `reset` are its short-lived commands. The configuration file must have `admin`. For the setting keys, the API, and what the commands do, see the [admin reference](admin-reference.md).
- The admin process is a separate process from the running proxy. All it can ask the proxy for is a status query, a generation switch, and a configuration reload with a specified version of the managed configuration (see "Control Socket" below).
- It runs the same checks before start as the proxy, and like the proxy it cannot run as root (`host check refused`).
- While `admin <config>` runs, the admin process writes its log as JSON to standard error (the journal under systemd). `bootstrap` and `reset` write plain-text lines for people to read.
- The exit codes are as follows. 0 is success, 1 is any other exit, and 2 is an argument error, a configuration file that was rejected, or a configuration file without `admin`.

## Signals

Send signals only to the proxy's main process. The inspector processes ignore SIGUSR1 and SIGUSR2, but exit when SIGTERM, SIGINT, or SIGHUP arrives. Under systemd, use `systemctl reload` (if the unit's `ExecReload` runs `config check` and then sends SIGHUP to the main process) or `systemctl kill --kill-whom=main`.

| Signal | What it does |
|---|---|
| SIGTERM, SIGINT | Stops the proxy (see "Stopping" below) |
| SIGHUP | Reloads the configuration file and switches to the new configuration without stopping |
| SIGUSR1 | Switches each engine to the generation chosen for it in the rules store, one engine at a time. An engine that has a chosen generation and is not running is started |
| SIGUSR2 | Reloads the certificate and key files of all TLS listeners (with `managed`, the certificate of `admin.route` and the certificates of the sites in the managed store) |

Earlier versions stop when they receive SIGHUP. When upgrading from such a version, install the new executable first and then change the unit (see "systemd" in the [build and deployment guide](../build/binary-deployment.md)).

### SIGHUP (Configuration Reload)

- The proxy reads the configuration file from the same path as at start, in a separate thread. If `managed` is present, it also reads the version selected at that time (`current`). It runs the startup steps that come before the rules store (the configuration file and the version, upstream server name resolution and `ca_file`, the listeners' certificates and keys, the ACME challenges, and the `geo` country database) with the same checks as at start, and the log lines begin with `reload:`.
- A `reload` request on the control socket reloads the configuration in the same way (it loads the version that the request specifies instead of `current`; see "Control Socket" below). Only one reload can run at a time.
- If everything passes and every setting key that cannot change while running (below) is the same as at start, the proxy switches to the new configuration in a single step. At the end it writes a `reload: configuration replaced <sha256>` line (with `managed`, `reload: configuration replaced <sha256> managed <version>`). Use this value to check which file and version are in effect.
- If anything is refused, the proxy changes nothing and writes a line with the reason (`reload: configuration refused: <reason>`, `reload: upstream refused: <reason>`, `reload: tls refused: <reason>`, and with `managed`, `reload: managed store refused: <reason>`, `reload: managed version refused: <reason>`, and so on). A refusal line does not contain values from the file.
- The proxy also refuses, changing nothing, when an upstream engine in the new configuration is not running or not ready (`reload: configuration refused: the engine of an upstream is not ready (upstream <name>)`, where `<name>` is the name of that upstream). A reload does not start inspector processes, so start that engine first with SIGUSR1 (see "SIGUSR1 (Generation Switch)" and "Chosen Generation per Engine" below). For a `reload` request on the control socket, this refusal has `reason` `fixed`.
- Both a switch and a refusal are counted in `tukuyomi_config_reloads_total` (`replaced`, `refused`). A reload started with `reload` on the control socket is counted in the same way.
- What can change:
  - The `proxy` setting keys (except those that cannot change, below), and the listeners (adding, removing, reordering, TLS and certificates, `http2`, `redirect`)
  - `forward` (the upstreams and the routes). The names of the upstream servers are resolved again at every reload. An upstream's `engine` can change if the new engine is running. With `managed`, this means the version's sites, upstreams, routes, and default upstream
  - An upstream's `ca_file`, the listeners' certificates and keys, and the ACME challenges
  - The global `access` and `rate_limit`, `host_policies`, and `geo` (the country database is loaded)
  - The admin route's certificate and `access`
  - `records.keep`
- Setting keys that cannot change while running: `proxy.max_conns`, `max_buffered_bytes`, `drive_slice_ms`, `ready_wait_ms`, `stop_inspect_ms`, `stop_wait_ms`, `records` (everything except `keep`, and whether it is present), `status`, `admin`, `admin.route.host`, `rules.store`, `managed` (whether it is present, and `dir`), and `kernel` (everything, including `default_engine`). A configuration in which any of them differs from start is refused as a whole (`reload: configuration refused: <key> cannot change while running`). To change them, restart.
  - The admin process and the records shipper also read `records`, `status`, `admin`, `rules.store`, `managed`, and `kernel` from the same file at start, so if only the proxy changed them, the values would no longer match. `admin.route.host` is used together with `admin.origin`, which the admin process reads at start, so it cannot change.
- Connections:
  - Connections accepted after the switch use the new configuration. Open connections keep using the configuration they were accepted with, and are closed as follows. Requests are not refused.
  - HTTP/1.1: a connection that is waiting for the next request after a response is closed at once. A connection in the middle of a response is closed with `Connection: close` added to that response. A connection that has just been accepted, or that is in the middle of receiving the header section of the next request, gets a response to that request and is then closed.
  - HTTP/2: the proxy sends `GOAWAY` and closes the connection after the open streams end.
  - WebSocket tunnels and the responses of routes with `stream` continue under the previous configuration until their own timeouts.
- Listeners:
  - Before switching, the proxy binds every address in the new configuration that it is not listening on now. If even one cannot be bound, the whole configuration is refused (`reload: configuration refused: listener <number> cannot be bound`; the number is the position in the new configuration, counted from 1).
  - An address that stays in the new configuration keeps its socket and moves to its new position in the order. Connections to that address are not refused.
  - An address that no longer exists is closed after the switch. Connections that have not started there yet (those in the system backlog, and those waiting for a connection slot) are disconnected. Open connections continue as described above.
  - An address that overlaps an address the proxy is listening on now cannot be bound, so the whole configuration is refused. For example, `127.0.0.1:8080` while `0.0.0.0:8080` is being listened on (and the reverse), or `[::ffff:127.0.0.1]:8080` while `127.0.0.1:8080` is being listened on. To make such a change, split it into one reload that removes the address and another that adds the new one, or restart.
  - `listener` in the log is the listener's number in the configuration under which the connection was accepted. After the order changes, the same number can point to a different listener.
- What is carried over:
  - The rate limit tables are carried over table by table (see "Rate Limits (`rate_limit`)" and "Host Policies (`host_policies`)" below). The global table continues if both the old and the new configuration have a global `rate_limit` and `keys`, `rate`, and `burst` are all the same (`exempt_cidrs` uses the new value). If any of them differs, or only one side has it, the new table counts from 0 and the proxy writes a `reload: rate limit table started anew` line.
  - The following are created anew: which upstream servers are marked as failed, the upstream failure counts, the idle connections waiting to be reused for the upstreams, and the listeners' TLS sessions. `tukuyomi_upstream_failures_total` counts from 0 again.
  - The rule generations are not touched. The running generation stays as it is, and the rules store is not read (SIGUSR1 switches generations). The proxy does not start engines either; it only checks that the upstream engines of the new configuration are ready (the refusal above).
- Even for a file with the same content and the same version, everything is created anew as above and the waiting connections are closed.
- A SIGHUP received during a reload only writes a `reload: a configuration reload is in progress, ignored` line. A SIGHUP received after signal handling becomes active but before the listeners are bound, or during a stop, also only writes one line. A `reload` request accepted on the control socket during a reload gets the response `busy` (`reload under way`).
- A SIGUSR2 received during a reload loads the certificates of the current configuration after the reload ends (whether it switched or was refused). The `reload: SIGUSR2` line is written at that time.
- If a stop starts during a reload, the reload is discarded.
- A SIGHUP that arrives before SIGHUP handling becomes active (before step 6 of the start) ends the proxy, like the other signals.

### SIGUSR1 (Generation Switch)

- The proxy reads the rules store for each engine and switches the engines whose chosen generation differs from the running one. It switches them one at a time, the default engine first and then the others in name order, and starts on the next engine after the current switch has finished.
  - To switch, it starts a new inspection kernel and inspector process with the chosen generation. When the new one is ready, it sends that engine's new requests to it.
  - The old one inspects the requests it holds until `stop_inspect` and then stops.
  - If the new one fails to start or is not ready within `ready_wait`, the switch fails (the proxy writes a `reload: generation <fingerprint> failed to start: <reason>` line). The old one keeps inspecting as before.
  - The new inspector process starts with the executable of that engine (`kernel.inspector` for Coraza, `kernel.engines` for ModSecurity).
  - If the engine of the chosen generation cannot be used, the proxy does not switch. It writes a `reload: rules store refused: <reason>` line, and the old one keeps inspecting as before. `rules activate` and the admin process do not choose such a generation.
- An engine that has a chosen generation and is not running starts in the same switch. If the start fails, the engine stays not running.
  - For an engine whose chosen generation is the same as the running generation, the proxy writes a `reload: generation <fingerprint> is already running` line and goes on to the next engine.
  - If an engine that is not running has no chosen generation, nothing happens (not even a line).
  - If an engine that is running has no chosen generation (after `rules deactivate`, for example), the proxy writes a `reload: rules store refused: no generation is chosen` line and counts it as `refused` in `tukuyomi_rules_switches_total`. The engine keeps running.
- If an inspection kernel fails after it is ready, the whole proxy stops. This also applies to an engine started by SIGUSR1 and to an engine that no upstream uses (see "`kernel`" and "Choosing the Inspection Engine" below).
- Each engine has its own bypass route table. When the new generation starts accepting requests, that engine's table is replaced along with it.
- During a switch, there is one more inspector process for that engine. Only one switch can run at a time in the whole proxy, so at most one more is added. For memory estimates, see "Choosing the Inspection Engine" below.
- A SIGUSR1 received after signal handling becomes active but before the listeners are bound, during a switch, or during a stop only writes one line to the log and does nothing else (during a switch, `reload: a switch is in progress, ignored`). If an engine is still waiting to be switched by an earlier SIGUSR1, the proxy continues with it after the switch in progress finishes.
- While a generation is in use, the proxy holds a shared lock on each engine's marker for the running generation (`using/<fingerprint>` in the rules store), so `rules remove` cannot delete a generation that is in use.
- The admin process can also ask for the same switch over the control socket, naming the engine (see "Control Socket" below). The switch procedure and the way `tukuyomi_rules_switches_total` is counted are the same as for SIGUSR1.

### SIGUSR2 (Certificate Reload)

- The proxy replaces the certificates and keys all at once, and only when every reloaded certificate and key passes the checks (for the checks, see `cert_file` and `key_file` under `proxy.listeners` below). Handshakes that start after the replacement use the new ones. Open connections keep using the current ones.
- With `managed`, it reloads the `cert_file` and `key_file` of `admin.route` and the certificates of the sites in the managed store (for an ACME site, the current files under `acme/`). Listeners in such a configuration do not have `certificates`.
- If even one fails, none is replaced, and the log lines show which ones failed.
- If the files of a certificate that has `acme` do not exist, that is not a reason to refuse the replacement. The proxy writes a line, leaves the certificate out of the handshakes, and starts using it at the first SIGUSR2 after the files exist. If you delete the files while running and then send SIGUSR2, that certificate is also left out of the handshakes, and connections to that host fail.
- SIGUSR2 does not reload the upstream CA files (SIGHUP does).
- To reload only certificates and keys (after an ACME renewal, for example), send SIGUSR2, not SIGHUP. SIGHUP reads the whole configuration file, so it can read a configuration that is only half written.
- A SIGUSR2 received after signal handling becomes active but before the listeners are bound, or during a stop, only writes one line to the log. It is independent of SIGUSR1.

### What Is Not Reloaded

The following are read at start and stay as they are until the proxy is restarted.

- The setting keys that cannot change while running, listed under "SIGHUP (Configuration Reload)" above (the location and size of `records`, `status`, the control socket path of `admin`, `admin.route.host`, `rules.store`, `managed`, `kernel`, and so on)
- The admin process and the records shipper do not reload the configuration (both stop on SIGHUP). After you change the configuration, restart them (see the [admin reference](admin-reference.md) and "Records Shipper" below).

## Stopping

Here, t0 is the time of the first reason to stop (a signal, or a failure at start or in the driver).

1. The proxy closes the listeners and refuses new requests. It also closes the control socket and deletes its file (a client that was waiting for a response does not receive it). It closes the connections that are waiting for the next request. `/readyz` becomes 503 `stopping`, and if `NOTIFY_SOCKET` is set, the proxy sends `STOPPING=1`.
2. Inspection ends by `t0 + stop_inspect`.
3. The proxy waits until `t0 + stop_wait` for connections to finish, and cuts off the rest. WebSocket tunnels do not end when a stop begins, so they are cut off at this point. After this, it closes the monitoring listener.
4. It waits until `t0 + stop_wait + kill_grace` for the inspection kernels of all running engines to end.
5. It flushes the logs for at most 200 ms and exits.

At the end, a `stop: kernel ..., engine <engine>, bye ..., exit_confirmed ..., dir_removed ..., held_left ..., waiting_left ..., results ..., retired_clean ...` line is written. If an inspection kernel could not be confirmed to have ended, a `stop: the driver stopped: ...` or `stop: the driver gave no end` line is written instead.

- Before that, a `driver: stop, engine <engine>, records <count>, held <count>, waiting <count>` line is written for each engine that is running.
- There is one `stop: kernel` line. The values `bye`, `exit_confirmed`, `dir_removed`, and so on are those of the running engine that comes first in name order, and `engine` shows its name. The results of the other engines, and of the inspection kernels that stopped earlier in a switch, are combined in `retired_clean`.
- `bye true` shows that the inspector process sent the end notice before it exited.
- The exit code is 0 only if the reason to stop is not a failure and, for every stopped inspection kernel (including those of the other engines and those stopped earlier in a switch), the inspector process was confirmed to have ended and the work directory to have been removed.

## Configuration File

### Overall Structure

```text
{"proxy": {..}, "forward": {..}, "kernel": {..}, "rules": {"store": {..}}, "acme": {..}, "status": {..}, "records": {..}, "access": {..}, "rate_limit": {..}, "host_policies": [..], "geo": {..}, "admin": {..}, "managed": {..}}
```

- `acme`, `status`, `records`, `access`, `rate_limit`, `host_policies`, `geo`, `admin`, and `managed` can be omitted (see the sections below).

- The file is one JSON object in UTF-8, up to 256 KiB.
- No value has a default. Write every setting key except those described as optional.
- The following are rejected: an unknown setting key, a duplicate of the same setting key, a value of the wrong type, and an array in place of an object. Writing `null` for a setting key that can be omitted is also rejected (omit it, or write a value).
- A rejection message is one fixed English sentence for each kind of error, and does not contain values from the file.
  - Format errors (not JSON, a missing, unknown, or duplicate setting key, a wrong type) do not name the setting key.
  - Range errors and errors in the relation between values name the setting key of the rule that was violated (for example, `max_conns is out of range`).
  - The values are checked in a fixed order, and the first rule that is violated is returned.
- Every path in the configuration is written as an absolute path that does not contain `.`, `..`, an empty component, or a trailing `/`.
- Times are written as integers in milliseconds, in setting keys whose names end in `_ms`.
- For the setting keys that give a number of bytes, 1 KiB is 1024 and 1 MiB is 1048576.
- Without `managed`, write `acme` only when a certificate has `acme`, and in that case it is required. With `managed`, `acme` is required if the admin route's certificate has `acme`, and can be written even if it does not, because the ACME sites are in the version (see "ACME Sites" below).
- Write `geo` whenever there is any country list (`deny_countries` or `allow_countries` in the global `access`, the `access` of `host_policies`, or the `access` of a route). With `managed`, it is also needed for the country lists in the version.
- With `managed`, `forward` has only `resolve_timeout_ms`, and the TLS listeners' `certificates`, the global `access` and `rate_limit`, and `host_policies` cannot be written (they are rejected if written). These go in the version. If `admin` is present, `admin.route` is needed (see "Managed Configuration" below).

### Example

This example shows a TLS listener (with HTTP/2 and an ACME certificate), a listener that redirects to https, one upstream, a log file, and a rate limit. Of the optional setting keys, the example includes only `acme`, `records`, and `rate_limit`. For the other setting keys, see the sections below. The values are a starting point for running the proxy; the accepted ranges are in the tables below.

```json
{
  "proxy": {
    "listeners": [
      {"address": "0.0.0.0:80", "redirect": {"https_port": 443}},
      {
        "address": "0.0.0.0:443",
        "tls": {
          "min_version": "1.2",
          "certificates": [
            {
              "cert_file": "/var/lib/tukuyomi-core/tls/www.pem",
              "key_file": "/var/lib/tukuyomi-core/tls/www.key",
              "hosts": ["www.example.com"],
              "acme": {"renew_before_days": 30}
            }
          ],
          "http2": {
            "max_streams": 128,
            "stream_window": 65535,
            "connection_window": 262144,
            "max_header_list": 32768,
            "send_buffer": 16384
          }
        }
      }
    ],
    "max_conns": 256,
    "max_head_bytes": 8192,
    "max_body": 104857600,
    "inspect_body": 16384,
    "max_body_wire": 209715200,
    "max_buffered_bytes": 33554432,
    "upstream_max_headers": 100,
    "upstream_max_head_bytes": 16384,
    "upstream_head_wire": 65536,
    "drive_slice_ms": 1,
    "ready_wait_ms": 30000,
    "head_read_ms": 10000,
    "body_read_ms": 10000,
    "inspect_wait_ms": 55000,
    "upstream_connect_ms": 2000,
    "upstream_header_ms": 30000,
    "request_total_ms": 60000,
    "response_idle_ms": 30000,
    "conn_total_ms": 3700000,
    "stop_inspect_ms": 10000,
    "stop_wait_ms": 20000,
    "keepalive_timeout_ms": 15000,
    "keepalive_requests": 1000,
    "keepalive_time_ms": 3600000,
    "lingering_time_ms": 30000,
    "lingering_timeout_ms": 5000,
    "lingering_bytes": 262144,
    "trusted_proxies": [],
    "upstream_keepalive": 32,
    "upstream_keepalive_timeout_ms": 30000,
    "upstream_keepalive_requests": 1000
  },
  "forward": {
    "resolve_timeout_ms": 5000,
    "upstreams": {
      "app": {
        "servers": [
          {"address": "127.0.0.1:8080", "weight": 1, "max_fails": 0, "fail_timeout_ms": 10000, "backup": false}
        ]
      }
    },
    "routes": [],
    "default_upstream": "app"
  },
  "acme": {
    "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "contact_email": "admin@example.com",
    "account_key_file": "/var/lib/tukuyomi-core/acme/account.key",
    "challenge_dir": "/var/lib/tukuyomi-core/challenges",
    "ca_file": "/etc/tukuyomi-core/acme-roots.pem",
    "timeout_ms": 300000
  },
  "kernel": {
    "inspector": "/opt/tukuyomi-core/bin/tukuyomi-inspector",
    "tmp_root": "/var/lib/tukuyomi-core/tmp",
    "gomaxprocs": 1,
    "gomemlimit": 268435456,
    "slots": 2,
    "wait_queue": 16,
    "records": 64,
    "discard_limit": 8,
    "tick_ms": 20,
    "hello_wait_ms": 20000,
    "frame_io_ms": 1000,
    "verdict_wait_ms": 3000,
    "wait_deadline_ms": 5000,
    "closed_wait_ms": 3000,
    "stop_after_ms": 5000,
    "drain_wait_ms": 3000,
    "exit_wait_ms": 3000,
    "kill_grace_ms": 2000,
    "restarts": 3,
    "restart_window_ms": 60000
  },
  "rules": {
    "store": {"kind": "file", "dir": "/var/lib/tukuyomi-core/store"}
  },
  "records": {
    "dir": "/var/lib/tukuyomi-core/records",
    "file_bytes": 16777216,
    "files": 8
  },
  "rate_limit": {
    "rate": 50,
    "burst": 100,
    "keys": 65536,
    "exempt_cidrs": ["192.0.2.0/24"]
  }
}
```

### `proxy`: Connections and Sizes

| Setting key | Range | Meaning |
|---|---|---|
| `listeners` | 1 to 8 | The listeners (see `proxy.listeners` below) |
| `max_conns` | 1 to 65536 | The number of client connections held at the same time. All listeners are counted together |
| `max_head_bytes` | 1024 to 32768 | The maximum size of the request header section (in bytes). Beyond it, 431 (414 if the limit is reached before the end of the request line appears) |
| `max_body` | 1 KiB to 4 GiB | The maximum size of the request body (the length after decompression). Beyond it, 413. A gzip body on a route that is inspected can be up to `inspect_body` (see "Request Body Limits and Inspected Length" below). A gzip body on a bypass route is not decompressed, so it is counted at the length as sent |
| `inspect_body` | 1 KiB to 1 MiB, and at most `max_body` | How many bytes from the start of the body are inspected. For a longer body, the rest is passed on without inspection |
| `max_body_wire` | `max_body` to `2 × max_body + 4 MiB` | The maximum number of bytes on the wire for a chunked body (including the chunk size lines and delimiters). Beyond it, 413 |
| `max_buffered_bytes` | `2 × inspect_body + 24 KiB + 32 KiB` to 4 GiB | The total budget of bytes that requests buffer (see "Request Body Limits and Inspected Length" below). When it runs out, 503 |
| `upstream_max_headers` | 1 to 1024 | The maximum number of fields in the header section of a response from an upstream |
| `upstream_max_head_bytes` | 8192 to 1 MiB | The maximum size of the header section of a response from an upstream (in bytes). It is also the size of the read buffer used on a connection to an upstream |
| `upstream_head_wire` | `2 × upstream_max_head_bytes` to 4 MiB | The maximum number of bytes read from an upstream up to the final response header section (including 1xx) |
| `trusted_proxies` | 0 to 256 networks | The peers whose `X-Forwarded-For` is trusted (see "Client Address" below). If empty, the peer is always the client. Write each as an `address/prefix` whose host part is 0 (`10.1.2.3/24`, and an address without a prefix, are rejected) |
| `upstream_keepalive` | 0 to 1024 | The number of connections per upstream that wait to be reused (counted over all of the upstream's servers). If 0, connections are closed after the response |
| `upstream_keepalive_requests` | 1 to 1000000 | The maximum number of requests sent on one connection to an upstream |
| `keepalive_requests` | 1 to 1000000 | The maximum number of requests accepted on one client connection. The connection is closed with the response to the last request. With HTTP/2 it is approximate (see `http2` below) |
| `lingering_bytes` | 1 to 4 MiB | The maximum number of bytes read and discarded before a connection is closed |

### `proxy`: Times

Every range is 1 ms to 3600 s, except that `keepalive_timeout_ms` can also be 0 and `conn_total_ms` can be up to 24 hours.

| Setting key | Meaning |
|---|---|
| `drive_slice_ms` | The time the inspection driver spends in one turn running the inspection kernels of engines that have work. The inspection kernel of an engine that has no work runs at the shortest step (1 ms). New requests are accepted between turns, so when other requests are in progress, a new request waits at most roughly this time multiplied by the number of engines that have work. The recommended value is 1 |
| `ready_wait_ms` | The time to wait for an inspection kernel to be ready (start, a generation switch, the `rules import` trial) |
| `head_read_ms` | The time to finish reading the request header section. The first header section on a connection is counted from `accept` (including the TLS handshake), and later ones from their first byte. An HTTP/2 header block is counted from the first byte of the `HEADERS` frame |
| `body_read_ms` | The time to finish reading the first part of the body (up to `inspect_body`, or the whole body), counted from the end of the header section. For the rest of a longer body, the connection is cut when the time between reads exceeds this time |
| `inspect_wait_ms` | The time a request waits for the inspection result |
| `upstream_connect_ms` | The time to connect to an upstream (including the TLS handshake) |
| `upstream_header_ms` | The time from the start of sending the request to the upstream until the response header section is received. It includes the time to send. For a request whose body is streamed, it is counted from when the last piece is handed to the upstream connection |
| `request_total_ms` | The maximum time from the start of a request to the response header section. It includes receiving the body and inspection. It does not include the time to stream the response body. For the first request on a connection it is counted from `accept` (including the TLS handshake), and for later requests from the later of the first byte and the previous response |
| `response_idle_ms` | The maximum time a connection to an upstream can go without traffic, and the maximum time the client can go without receiving. It applies not only during the response body but also while waiting for the response header section from the upstream (for a request whose body is streamed, it does not apply until the response header section arrives). So for a request whose body is buffered, making `upstream_header_ms` longer than this has no effect |
| `conn_total_ms` | The maximum time one client connection can last (from `accept`). Only the response of a route that has `stream` can continue beyond it |
| `stop_inspect_ms` | At a stop, the time to finish inspection (see "Stopping" above) |
| `stop_wait_ms` | At a stop, the time to wait for connections to end |
| `keepalive_timeout_ms` | After a response, the time to wait for the next request. If 0, the connection is closed after every response |
| `keepalive_time_ms` | The time during which a connection can be reused (from `accept`). For a request whose response is sent after this time has passed, the connection is closed with that response |
| `lingering_time_ms` | The maximum time spent reading and discarding what the client is still sending before a connection is closed |
| `lingering_timeout_ms` | Likewise, the maximum time to wait for the next read before a connection is closed. With HTTP/2, it is also the time to wait for the client after `GOAWAY` and the time to keep a connection that has no streams |
| `upstream_keepalive_timeout_ms` | The time a connection to an upstream waits to be reused |

### `proxy.listeners`

A listener is `{"address", "tls"?, "redirect"?}`.

- `address`: An IP literal and a port (`[..]:port` for IPv6). Port 0 is rejected.
- Neither present: a normal listener. It accepts HTTP and forwards to the upstreams.
- `tls` present: it terminates TLS and then does the same.
- `redirect` present: it responds to every request with a redirect to https (308) or 404, and forwards nothing. A client refused by the global `access` or `rate_limit`, or by a host policy, gets 403 or 429 (see "Access Control and Rate Limits" below).
- `tls` and `redirect` cannot be written together.
- Rules between listeners:
  - At least one normal listener or `tls` listener is needed.
  - If there is a `redirect` listener, a `tls` listener is also needed.
  - Two listeners cannot have the same address. Nor can two listeners have the same port when one of them has `0.0.0.0` or `::`.

`tls` is `{"min_version", "certificates", "http2"?}`. With `managed`, it is `{"min_version", "http2"?}`, and writing `certificates` is rejected (`a tls listener has certificates while the configuration has managed`). In that case, write the certificates in the sites of the managed configuration version and in `admin.route` (see "Managed Configuration" below).

| Setting key | Range | Meaning |
|---|---|---|
| `min_version` | `"1.2"`, `"1.3"` | The oldest TLS version accepted. TLS 1.3 is always accepted |
| `certificates` | 1 to 16 | `{"cert_file", "key_file", "hosts", "acme"?}` |
| `cert_file`, `key_file` | Absolute path, up to 3840 bytes | The files of the certificate chain and the private key. They are read at start, at a reload by SIGHUP or by `reload` on the control socket, and at a reload by SIGUSR2 |
| `hosts` | 1 to 64 | Names contained in the certificate (lowercase letters, digits, `-`, `.`), or `*.` and a name. IP literals cannot be written. Within one listener, the same host can appear only once |
| `acme` | `{"renew_before_days"}` (1 to 60) | Marks the certificate as one that `acme renew` issues and renews. `*.` cannot be written in the hosts. The files do not have to exist at start |
| `http2` | Object | Accepts HTTP/2 (see `http2` below). If absent, HTTP/1.1 only |

- `cert_file` and `key_file` are checked as follows at start, at a reload by SIGHUP or by `reload` on the control socket, and at a reload by SIGUSR2.
  - Both are regular files of up to 1 MiB.
  - The certificate file has 1 to 10 PEM certificates, and the first is the host's certificate. The key file has exactly one key.
  - The key pairs with the first certificate, and the first certificate contains all of `hosts`.
  - The validity period is not checked.
- In the handshake, the certificate is chosen from `hosts` by the server name that the client sent. An exact name matches before a wildcard. A handshake without a server name, and a handshake with no matching host, fail.
- `*.` followed by a name matches exactly one label before the name (`*.a.example` matches `www.a.example`, and does not match `a.example` or `x.y.a.example`). Matching is case-insensitive.
- A request on a TLS connection gets 421 if its `Host` is not among the hosts of the certificate used in the handshake (this check comes after the global `access` and `rate_limit` and the host policies, and before the route is chosen).

All five setting keys of `http2` must be written.

| Setting key | Range | Meaning |
|---|---|---|
| `max_streams` | 1 to 256 | The number of streams a client can open at the same time |
| `stream_window` | 65535 to 1 MiB | The receive window of a stream |
| `connection_window` | 65535 to 4 MiB | The receive window of a connection |
| `max_header_list` | 1 KiB to `4 × max_head_bytes` | The size of the request header fields after expansion |
| `send_buffer` | 1 KiB to 1 MiB | The number of response bytes per stream waiting to be sent |

- There is also a limit on how much one connection can hold.
  - `connection_window + max_streams × (send_buffer + 32 KiB)` is at most 16 MiB.
  - With `max_header_list` and `upstream_max_head_bytes` added for each stream, the total is still at most 16 MiB.
- This amount is not included in `max_buffered_bytes`. Each connection can hold this much, so in total it is `max_conns` times as much. For example, with the values in the example above it is about 12.3 MiB per connection, and 256 connections could reach about 3 GiB. Decide these values together with `max_conns`.
- With HTTP/2, `keepalive_requests` and `keepalive_time_ms` are approximate.
  - A stream that the client sent in the same write, before the connection-closing notice (`GOAWAY`), counts as accepted.
  - Even after `GOAWAY`, new streams are accepted for `lingering_timeout_ms`.
- HTTP/2 is handled only on TLS listeners, when the client chooses `h2` in the handshake. Plaintext HTTP/2 (h2c) is not handled.

`redirect` is `{"https_port"}` (1 to 65535).

- The redirect target is `https://<host>:<https_port><target>`, where `<target>` is as received. If `https_port` is 443, the port is not written. The port written in `Host` is not used.
- The proxy redirects only when `Host` is among the hosts of a certificate on one of the TLS listeners and a route (or the default upstream) matches the request.
- If `Host` is an IP literal, cannot be read, or does not meet the condition above, the response is 404.
- The body is not read.
- A client refused by the global `access` or `rate_limit`, or by a host policy, gets neither the redirect nor 404, but 403 or 429 (see "Access Control and Rate Limits" below). This decision is made after the ACME challenge and before the redirect. Requests for the admin route's host (`admin.route`) are redirected without these checks.
- The proxy answers ACME challenge requests before redirecting (see "ACME" below).

### `forward`

```text
{"resolve_timeout_ms", "upstreams": {"<name>": {..}}, "routes": [..], "default_upstream"}
```

With `managed`, `forward` is only `{"resolve_timeout_ms"}`, and writing `upstreams`, `routes`, or `default_upstream` is rejected (`forward has upstreams, routes or default_upstream while the configuration has managed`). Write the upstreams, routes, and default upstream in the same form in the managed configuration version (see "Managed Configuration" below).

| Setting key | Range | Meaning |
|---|---|---|
| `resolve_timeout_ms` | 1 ms to 3600 s | The time to finish resolving the upstream server names, at start and at a reload by SIGHUP or by `reload` on the control socket. It also affects how long a `reload` request on the control socket, and the admin process when it applies a version, wait for a response (see "Control Socket" and "Applying" under "Managed Configuration" below) |
| `upstreams` | 1 to 64 | A map from the name of an upstream (1 to 64 characters of letters, digits, `-`, and `_`) to `{"servers", "tls"?, "engine"?}` |
| `routes` | 0 to 1024 | The routes that choose an upstream from the `Host` and the path of a request |
| `default_upstream` | The name of an upstream, or an empty string | The upstream for a request that matches no route. If empty, such a request gets 404 |

A server is `{"address", "weight", "max_fails", "fail_timeout_ms", "backup"}`, and every setting key must be written. One upstream can have 1 to 64 servers.

| Setting key | Range | Meaning |
|---|---|---|
| `address` | An IP literal and a port, or a name and a port (`name:port`) | A name is lowercase letters, digits, `-`, `_`, and `.`, up to 253 bytes. Each label is 1 to 63 bytes, and the last label starts with a letter. The port is 1 to 65535 and has no leading 0. The following cannot be written as an IP literal: the unspecified addresses (`0.0.0.0`, `::`), multicast addresses, and the address of a listener (if the listener has an unspecified address, the loopback address on its port). The admin process's listener (`admin.listen`) can be written, so that the admin process can be reached through a proxy route. It cannot be written in a managed configuration version (the admin screens are reached through `admin.route`) |
| `weight` | 1 to 100 | The weight |
| `max_fails` | 0 to 100 | If the server fails this many times within `fail_timeout_ms`, it is excluded for `fail_timeout_ms`. If 0, failures are not counted |
| `fail_timeout_ms` | 1 ms to 3600 s | The period over which the failures above are counted, and how long the server is excluded |
| `backup` | true, false | Used only when no other server is usable |

- A name is resolved at start and at every reload by SIGHUP or by `reload` on the control socket, and is not resolved again in between (SIGUSR1 does not resolve it again either).
  - If the address of a name changes (a container name, for example), reload with SIGHUP.
  - Every address that a name resolves to becomes an upstream server, with the same values as the server entry that was written. After name resolution, an upstream can have at most 64 servers.
  - If a name cannot be resolved, has no address, points to an unspecified, multicast, or listener address, or cannot be resolved within the time limit, the proxy does not start. A reload by SIGHUP refuses that configuration.
- Servers are chosen in turn from the usable ones, according to their weights (smooth weighted round robin).
- If an upstream has only one server, it is not excluded. If none of an upstream's servers is usable, the proxy responds with 502 without trying anything.
- The following count as a server failure.
  - The connection was refused or cut off, the server is unreachable, or the connection cannot be made within `upstream_connect_ms` (a failed TLS handshake is included)
  - The request cannot be sent, the response header section does not arrive within `upstream_header_ms`, or the connection was cut off in the middle of the header section
- An unreadable response, a response that is too large, and a status code that the upstream returned are not counted as a server failure.
- When a request cannot be sent on a connection that was waiting to be reused, it is not counted as a server failure, because the server may simply have closed the connection while it waited. A request with an idempotent method is sent again once, on a new connection to the same server. Other methods are not sent again, and the proxy responds with 502.
- After a failure, the request is passed on to the next server only in these two cases.
  - The connection could not be made (nothing was sent)
  - The method is idempotent (GET, HEAD, OPTIONS, PUT, DELETE, TRACE)
- A request whose body is streamed is not sent again, except when the connection could not be made.
- In the following cases, the request is not counted as a server failure and is not passed on to another server.
  - The connection was cut because the request time (`request_total_ms`) ran out. This keeps a slow client from getting a server excluded
  - The proxy itself cannot make a connection (file descriptors or ports ran out, for example). It responds with 503

An upstream's `tls` is `{"ca_file", "server_name"?}`.

- The proxy uses TLS to connect to every server of the upstream. It always verifies the server certificate, and there is no setting to turn the verification off.
- `ca_file` is a PEM file that holds the root certificates to trust. It is an absolute path of up to 3840 bytes, the file is up to 1 MiB, and it holds 1 to 100 certificates. It is read at start and at a SIGHUP reload (not by SIGUSR2).
- `server_name` is a lowercase name and must be in a form that can be used in TLS. If present, the server is verified against that name; if absent, against the name written for the server. A server written as an IP literal is verified with that address.
- Connections to the upstream use TLS 1.2 and 1.3, and the only ALPN is `http/1.1` (HTTP/2 is not used to the upstream). The proxy sends no client certificate.

An upstream's `engine` is the name of the engine that inspects requests to that upstream.

- It is `coraza` or `modsecurity` (lowercase). If omitted, the engine of `kernel.default_engine` inspects the requests (`coraza` if `kernel.default_engine` is not set). `null` cannot be written.
- Any other name is rejected with `an upstream engine is not coraza or modsecurity`. `modsecurity` is also rejected, with `kernel.engines has no inspector for the engine of an upstream`, when `kernel.engines` in the configuration has no inspector process.
- Upstreams that have servers with the same address must all use the same engine (see "Relations Between Values" and "Choosing the Inspection Engine" below).
- It can be changed by a configuration reload if the new engine is running (see "SIGHUP (Configuration Reload)" above).

A route is `{"host"?, "path"?, "upstream", "access"?, "rewrite"?, "stream"?, "max_body"?, "records"?}`.

| Setting key | Meaning |
|---|---|
| `host` | A lowercase name, optionally with `:port` (up to 253 bytes including `*.` and the port). If a port is written, it matches only that port; if not, any port. If it starts with `*.`, it matches one or more labels before the name |
| `path` | A path of 1 to 255 bytes that starts with `/`. If it ends with `/`, it matches every path that starts with it; otherwise it matches only that path. The allowed bytes are letters and digits, and `-._~!$&'()*+,=:@/%`, and `%` must be followed by two hexadecimal digits. A form that can be read in more than one way (see "Notes on using `access`" below) cannot be written |
| `upstream` | The name of an upstream |
| `access` | `{"deny_cidrs"?, "allow_cidrs"?, "deny_countries"?, "allow_countries"?}`. Up to 256 networks per list, and up to 256 countries per list (see `access` in "Access Control and Rate Limits" below) |
| `rewrite` | Rewrites the request sent to the upstream and the response returned (see below) |
| `stream` | `{"idle_ms", "total_ms", "websocket"}`. Write all three (see "Streaming Responses and WebSocket (`stream`)" below) |
| `max_body` | The body limit for that route. It is at most `proxy.max_body`, so it can only lower the limit. If 0, no body is accepted |
| `records` | How logs are kept for that route's requests: one of `best_effort`, `required`, and `security`. If omitted, it follows `records.keep` (see "How Logs Are Kept (`keep` and the `records` of a Route)" under "Logs" below) |

- A route compares the request's `Host`, and the request target up to the first `?`, as the bytes received.
  - Nothing is decoded or normalized. The path is case-sensitive.
  - The host is case-insensitive, and one trailing `.` is removed from the name.
- Two routes with the same `host` and `path` cannot be written.
- A request target with a path that can be read in more than one way (the forms listed in "Notes on using `access`" below) does not match a route that has `path`. It goes to a host-only route or to the default upstream.
- When several routes match, the most specific one is used.
  - The host is compared first: a name before a wildcard, a longer wildcard before a shorter one, a route with a port before one without, and a route with a host before one without.
  - Then the path: a route for exactly that path before a prefix, a longer prefix before a shorter one, and a route with a path before one without.
- The default upstream has no `access`, `rewrite`, `stream`, `max_body`, or `records`. The log of a request that goes to the default upstream follows `records.keep`.
- Before a route is chosen, the proxy handles the admin route, applies the global `access` and `rate_limit` and the host policies, and checks `Host` on TLS connections (see "Order of Request Checks" under "Access Control and Rate Limits" below).
- After a route is chosen, and before reading the body or inspecting, the proxy responds as follows.
  - No route matches and there is no default upstream: 404
  - A client refused by `access`: 403
  - `Content-Length` exceeds the route's `max_body`: 413
- `access`: A client is refused if its address (see "Client Address" below) is in `deny_cidrs`, or if its country is in `deny_countries`. It is also refused if `allow_cidrs` is not empty and the client is not in it, or if `allow_countries` is not empty and its country is not in it. If both `allow_cidrs` and `allow_countries` are written, only a client that is in both passes. The country is looked up in the country database of the global `geo`, so a country list requires `geo` (see `geo` in "Access Control and Rate Limits" below).

Notes on using `access`:

- A route is chosen by the bytes received, but the application behind the upstream may read a different spelling as the same path (for example, reading `/priv%61te/x` as `/private/x`). So while any route has `access`, a request must pass the `access` of every route that the request could be mistaken for. An `access` that has only country lists also counts as `access`. The same holds for the following rules.
- While any route has `access`, the following requests get 403 when the client is outside the `access` of any route whose `Host` matches (including routes that have no host).
  - A request target whose path (before `?`) can be read in more than one way. This is a target that contains `\`, `;`, `//`, a segment of `.` or `..`, or `%2e`, `%2f`, `%5c`, `%00`, or `%25` (in either case), or a target in which replacing an escape produces another escape (such as `%2%65`)
  - An unreadable `Host` (all routes are covered)
- The path of a route that has `access` is written in the canonical form: escapes in uppercase, and bytes that can be written literally are not escaped.
- If any route has `access`, no route can have a port in `host`.
- When the proxy looks for the routes that a request could be mistaken for, it checks the request path with a trailing `/` added, but not with a trailing `/` removed. So a restriction on the exact-match route `/admin` does not apply to `/admin/`; if the upstream treats them the same, write both.
- The path is case-sensitive, so for an upstream that ignores case, the restriction applies only to the spelling that was written.

`rewrite` is `{"host"?, "path"?, "query"?, "request_headers"?, "response_headers"?}`.

- `host`: The `Host` sent to the upstream. It has the same form as the route's `host`, and a wildcard cannot be written.
- `path`: Replaces the route's path. It can be written only for a route that has `path`. If the route's path ends with `/`, the rest of the request target after it (including the query) is appended unchanged to the new path. The new path also ends with `/`. Otherwise the path is replaced and the query is kept.
- `query`: `{"remove"?, "remove_prefixes"?, "set"?, "add"?}`. Name comparison ignores ASCII case. An item whose name is followed by `[` (such as `debug[]`) is treated as the same name.
- `request_headers`, `response_headers`: `{"remove"?, "set"?, "add"?}`. `remove` is a list of names, and `set` and `add` are lists of `{"name", "value"}`. `set` removes every header with that name and adds one, and `add` appends one after any existing ones.
- The query, the request headers, and the response headers can each have up to 32 items.
- The following cannot be written in request headers.
  - A name that contains `_`
  - Hop-by-hop headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`, and so on)
  - Headers that carry the client address (`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Real-IP`, `Forwarded`, and so on)
  - `Host`, `X-Forwarded-Host`, `X-Request-ID`
  - Headers that carry the length and type of the body (`Content-Length`, `Content-Type`, `Content-Encoding`)
- In response headers, hop-by-hop headers, `Set-Cookie`, `X-Request-ID`, and headers that carry the length, type and range of the body (`Content-Length`, `Content-Type`, `Content-Encoding`, `Content-Range`) cannot be written. Responses that the proxy generates itself are not rewritten.
- Rewriting goes in this order: the request headers, `Host`, and the request target (the path, then the query). `X-Forwarded-Host` is built before that, from the `Host` that the client sent.
- Rewriting is done only once, after a route is chosen and the request is inspected. So write the WAF rules and exclusions, the bypass routes, and `access` against the public-side path and `Host` (before rewriting). Even when two public-side prefixes are rewritten to the same internal path, a rule aimed at one public-side path does not apply to the other.
- `query` does not rewrite the parameters in a form body.
- A request that cannot be rewritten (the new request target is too long, for example) is not sent to the upstream, and is not counted as a server failure either.

#### Streaming Responses and WebSocket (`stream`)

- `total_ms` (1 ms to 24 hours): After the response header section, the connection continues for at least this long. A WebSocket tunnel always ends `total_ms` after the 101.
- `idle_ms` (1 ms to `total_ms`): How long the upstream may send nothing
- `websocket`: Whether to let WebSocket handshakes through
- The response of a route that has `stream` is the last response on that connection. The connection ends at the later of the original end (`conn_total_ms` from `accept`) and `total_ms` after the response header section. Even if `total_ms` is shorter than the connection's remaining time, the response is not cut off at that point.
- The GET of a WebSocket handshake is inspected like other requests (it is not inspected on a bypass route). The WebSocket frames after the 101 are not inspected, only relayed.
- Before the handshake, the proxy reserves the budget for the tunnel (16 KiB). If it cannot, it responds with 503 without sending anything.
- A tunnel ends in these cases.
  - Both directions have ended
  - The upstream sends nothing for `idle_ms`, or a write to either side makes no progress for `response_idle_ms` (while both directions are open, the client may send nothing)
  - The other direction does not end within `idle_ms` after one direction has ended (the tunnel ends however much traffic there is in the meantime)
  - `total_ms` has passed since the 101
  - A read or write failed, the upstream connection cannot be taken over, or the 101 cannot be sent to the client
  - The connection was cut off by a stop
- An `Upgrade` request to a route that does not let WebSocket through (this includes `Upgrade: h2c`) does not become a tunnel. The proxy forwards it as an ordinary request without `Upgrade`, and closes the connection after the response. If the upstream returns a 101 that was not asked for, the proxy responds with 502.
- `CONNECT` is refused with 400.

### Client Address

- For a request from a peer that is in `trusted_proxies`, the proxy reads its `X-Forwarded-For` lines as one list, from right to left.
  - It skips the addresses of trusted proxies and takes the first address that is not a trusted proxy as the client.
  - If all are trusted proxies, the leftmost is the client.
  - If there is an item that is not an IP literal, it stops reading there and takes the peer as the client.
- For a request from a peer that is not trusted, the peer is the client. Claims such as its `X-Forwarded-For` are discarded.
- Even for a trusted peer, if the request has no `X-Forwarded-For` line, the peer is the client.
- This client address is used for inspection, the global `access`, `rate_limit`, the country lookup, route `access`, and logs.

The following headers are added to the request sent to the upstream.

| Header | Content |
|---|---|
| `X-Forwarded-For` | From a trusted peer: the received line with the peer's address added. Otherwise: only the peer's address |
| `X-Forwarded-Proto` | If a trusted peer sent exactly `http` or `https`, that value. Otherwise: the listener's scheme (`https` for a TLS listener, `http` for the others) |
| `X-Forwarded-Host` | The `Host` that the client wrote (whatever the peer) |
| `X-Request-ID` | The request ID (`id` in "Logs" below). One that the client sent is discarded and replaced, whatever the peer |

### `kernel`

Settings for the inspection kernel and the inspector processes. Every time is in the range 1 ms to 3600 s.

There is one inspection kernel for each engine that has started. `slots`, `wait_queue`, `records`, `restarts`, and `restart_window_ms` apply to each engine's inspection kernel separately, with the same value. For example, `slots` is the number of requests that one engine inspects at the same time.

| Setting key | Range | Meaning |
|---|---|---|
| `inspector` | Absolute path | The executable of the Coraza inspector process. This setting key is required, even on a host that uses only ModSecurity generations |
| `engines` | Optional. In the form `{"modsecurity": {"inspector": <absolute-path>}}`; the setting keys at both levels are required. The path is up to 4095 bytes | The executable of the ModSecurity inspector process. It starts when this setting key is present and a `modsecurity` generation is chosen (whether or not an upstream uses it). If omitted, a `modsecurity` generation is rejected at import and at choosing, with `kernel.engines has no inspector for the engine of the generation`. At start, `modsecurity` that is neither the default engine nor an upstream engine does not start even if a generation is chosen, and no line is written. A configuration that makes the default engine or an upstream engine `modsecurity` is rejected if this is omitted (`kernel.engines has no inspector for kernel.default_engine`, `kernel.engines has no inspector for the engine of an upstream`) |
| `default_engine` | Optional. `coraza` or `modsecurity` (lowercase). If omitted, `coraza` | The engine used when an upstream's `engine` is omitted or when `rules import` is run without `--engine`, and the engine that inspects the admin route when `managed` is present (see "Choosing the Inspection Engine" below). Setting it to `modsecurity` requires `engines`. Any other name is rejected with `kernel.default_engine is not coraza or modsecurity`. `null` cannot be written. It cannot change while running (see "SIGHUP (Configuration Reload)" above) |
| `tmp_root` | Absolute path, up to 3840 bytes | The parent directory in which a work directory is created at each start. It must be a directory that is not a symbolic link, owned by the proxy's OS user, with no permissions for the group and other users, and without setgid |
| `gomaxprocs` | 1 to 65535 | The inspector process's `GOMAXPROCS`. The ModSecurity inspector process runs in one thread and does not use it (it only returns the received value in the first message) |
| `gomemlimit` | 1 to 9223372036854775807 (bytes) | The inspector process's `GOMEMLIMIT`. The ModSecurity inspector process does not use it (it only returns the received value in the first message, and it is not a memory limit) |
| `slots` | 1 to 4 | The number of requests inspected at the same time |
| `wait_queue` | 1 or more, at most `max_conns` | The number of requests waiting for an inspection slot |
| `records` | At least `slots + wait_queue` | The number of request records held at the same time. This is a different setting key from the top-level `records` (the log files) |
| `discard_limit` | Less than the maximum value of `u32` | The number of responses that may be discarded in one run of an inspector process. Beyond it, it is treated as a connection error |
| `tick_ms` | Up to 1 s, and at most any other time | The longest wait in one step |
| `hello_wait_ms` | | The time from the start of the inspector process to the first message (HELLO) |
| `frame_io_ms` | | The time to write one frame, and to read after the first byte is received |
| `verdict_wait_ms` | | The time until the inspector process returns a verdict |
| `wait_deadline_ms` | | The time until a request is handed to the inspector process |
| `closed_wait_ms` | | The time from closing a request until the notice that it is closed |
| `stop_after_ms` | | The inspector process is stopped if the inspection slot is still not returned this long after the proxy stopped waiting for the verdict (`verdict_wait_ms` passed) or told the inspector process that inspection ended |
| `drain_wait_ms` | | The time from the instruction to end until the inspector process's end notice (BYE) |
| `exit_wait_ms` | | After the end notice, the time to wait for the inspector process to exit by itself |
| `kill_grace_ms` | | After SIGKILL, the time until the exit is confirmed |
| `restarts` | 0 to 1000 | The number of restarts allowed within `restart_window_ms`. If 0, the inspector process is not restarted |
| `restart_window_ms` | | The window in which the number of restarts is counted |

- Inspector process restarts are limited in number within the window. When the limit is reached, no restart happens until the number of restarts in the window falls below the limit, and requests that wait in the meantime get 503.
- A cause that would make every restart fail, such as an error in the rules, does not lead to a restart. If any engine's inspection kernel stops, the proxy stops too, even when that engine has been given no requests (`stop: the kernel failed`).

### `rules.store`

- Write `{"kind": "file", "dir"}`. For now, `kind` can only be `file`.
- `dir` is an absolute path of up to 3840 bytes. It must be a directory that is not a symbolic link, owned by the proxy's OS user, with no permissions for the group and other users.

### `acme`

Without `managed`, write it only when a certificate has `acme`. With `managed`, see "Overall Structure" above. When you write it, include all the setting keys.

| Setting key | Range | Meaning |
|---|---|---|
| `directory_url` | A URL that starts with `https://`, up to 2048 bytes | The ACME directory of the CA |
| `contact_email` | Up to 254 bytes | The contact passed to the CA. Only the format is checked |
| `account_key_file` | Absolute path | The ACME account key. If it does not exist, the command creates it (0600) |
| `challenge_dir` | Absolute path | The directory in which the challenge files are placed |
| `ca_file` | Absolute path | The root certificates for verifying the CA's server certificate (the same form as an upstream's `ca_file`; 1 to 100 certificates) |
| `timeout_ms` | 1 ms to 600 s | The timeout of the whole command |

- `account_key_file`, `ca_file`, and the `cert_file` and `key_file` of every certificate that has `acme` (including the admin route's certificate) must all be different files. The `cert_file` and `key_file` of certificates without `acme` must also differ from all of these.
- Do not place these files, or the `cert_file` and `key_file` of other certificates, directly under `challenge_dir` (see "Placement Notes" below).
- `challenge_dir` and the rules store, `records.dir`, the admin store (`admin.store.dir`), the control socket's directory, and the managed store cannot be the same directory, and none of them can be inside another. This also applies without `managed`. Overlaps are compared by the path as written, so do not use symbolic links (see "Relations Between Values" below).
- With `managed`, `account_key_file` and `ca_file` cannot be placed inside the managed store.
- At least one normal listener or redirect listener is needed, because the CA fetches the challenge over plaintext HTTP.

### `status`

Write it only when you want a monitoring listener (see "Monitoring" below). If omitted, there is no monitoring listener.

| Setting key | Range | Meaning |
|---|---|---|
| `listen` | A loopback IP (`127.0.0.0/8` or `::1`) and a port (0 is not allowed) | The address of the monitoring listener |

- Its responses are not authenticated, so use it from a monitoring program on the same host. The form `::ffff:127.0.0.1` is not regarded as loopback.
- It cannot overlap a listener (`proxy.listeners`) (the same rule as between listeners; `0.0.0.0` or `::` with the same port also overlaps).
- An upstream server cannot have this address, whether as written or after name resolution. It is rejected, just as a listener's address is.
- It is not counted in the number of listeners (1 to 8), nor in "at least one normal or TLS listener".

### `admin`

Settings for the admin process (`tukuyomi-proxy admin`). It is optional. If it is omitted, there is no admin process and the proxy does not create a control socket.

```text
{"listen", "control", "store", "origin", "trusted_proxies", "mfa", "session_idle_ms", "session_total_ms", "crs_dir"?, "route"?}
```

- The proxy and the admin process read the same configuration file. The proxy uses `listen`, `control`, and `route`, and only checks the values of the other setting keys, so that the proxy and the admin process both accept, or both reject, the same file. For the meaning and ranges of the other setting keys, see the [admin reference](admin-reference.md).

| Setting key | Range | Meaning |
|---|---|---|
| `listen` | A loopback IP (`127.0.0.0/8` or `::1`) and a port (0 is not allowed) | The address of the admin process's listener. The form `::ffff:127.0.0.1` is not regarded as loopback. It cannot overlap a listener (`proxy.listeners`) or the monitoring listener (the same rule as between listeners). Without `managed`, an upstream server can have this address. In a managed configuration version, it cannot |
| `control` | Absolute path, up to 107 bytes | The path of the control socket over which the admin process sends requests to the proxy (below) |
| `route` | `{"host", "certificate", "access"}` | The admin route (below). Required in a configuration file with `managed`, and not allowed in one without `managed` |

- Overlaps among `rules.store.dir`, `records.dir`, `admin.store.dir`, the directory of `admin.control`, and `managed.dir` are rejected (see "Relations Between Values" below), so that one cannot change the contents of another (for example, log file rotation replacing a socket in the same directory).

With `managed`, `route` is the route through which the proxy forwards requests to the admin process.

| Setting key | Range | Meaning |
|---|---|---|
| `host` | One name (`*.` cannot be written) | The host name of the admin screens. A request whose `Host` is this name is forwarded to `admin.listen` without choosing a route from the version |
| `certificate` | `{"cert_file", "key_file", "acme"?}` | The admin route's certificate. It is checked and loaded in the same way as a listener certificate whose `hosts` is only `host`. With `acme`, `acme renew` issues it, and the files do not have to exist at start (in that case the configuration file needs `acme`) |
| `access` | The same form as a route's `access`. `allow_cidrs` must be written and cannot be empty | The access control that applies to the admin route |

- The global settings (the global `access` and `rate_limit`) and the host policies do not apply to the admin route. The only network restriction that applies to the admin route is `access` (see "Order of Request Checks" below). The default engine does the WAF inspection (see "Choosing the Inspection Engine" below).
- A TLS listener chooses the admin route's certificate by SNI, along with the certificates of the version's sites. A request for the admin host is not forwarded: it gets 421 if it arrives on a connection that uses another certificate, and 404 if it arrives on a plaintext listener that is not a redirect listener. A redirect listener redirects it to https.
- The name in `host` cannot be written in the `hosts` of a version's site, a route's `host`, or a host policy's `hosts` (being covered by a `*.` wildcard is fine; the admin route matches first).
- The certificate and `access` can be changed by a configuration reload. `host` cannot change while running, so to change it, restart the proxy and the admin process.
- Without `managed`, an upstream and a route that point to `admin.listen` forward to the admin screens (see "Access from Outside" in the [admin reference](admin-reference.md)). The global settings and the host policies apply to that route. Requests are inspected by the upstream's engine (the default engine if `engine` is omitted).

#### Control Socket

A Unix domain socket through which the admin process queries the proxy's status and asks it to switch generations or to reload the configuration with a specified managed configuration version.

- How it is made:
  - The socket's directory must be a directory that is not a symbolic link, owned by the proxy's OS user, with no permissions for the group and other users (the same check as for the rules store). The socket is created with 0600.
  - It is bound before the inspection kernels start. If something already exists at the path, it is deleted and recreated only if it is a socket owned by the proxy's OS user with no process listening (connections are refused). If a process is listening on it, if it is not a socket, or if it belongs to another OS user, the proxy writes a `start: control socket refused: ...` line and refuses it (exit 1).
  - At a stop, it is closed together with the listeners, and the file is deleted. The file is deleted only if it is still the one the proxy created.
- Any process that runs as the same OS user as the proxy can use it. There is no authentication beyond the socket, and the only restrictions on use are the directory's permissions and the socket's mode 0600. Run the admin process as the same OS user as the proxy.
- Each connection sends one line of JSON (up to 4 KiB) within 2 seconds, receives a one-line response, and is closed. The proxy responds on up to 4 connections at the same time, and a connection beyond that is accepted and closed at once. A connection that sends no line, and a connection that was cut off, get no response.

The requests and responses are as follows.

| Request | Response |
|---|---|
| `{"op":"status"}` | `{"generation", "mode", "engine", "phase", "switching", "reloading", "ready", "uptime_ms", "requests", "blocked", "policy_refused", "upstream_failures", "config", "managed", "resolve_timeout_ms", "config_reloads", "engines"}`. In order: the fingerprint (64 hexadecimal digits) of the default engine's running generation, that generation's mode (`block`, `detect`), the engine (`coraza` or `modsecurity`), the inspection kernel's phase (`starting`, `ready`, `stopping`, `stopped`, `failed`), whether a switch is in progress, whether a configuration reload (SIGHUP or a `reload` request) is in progress, and whether `/readyz` responds with `ready`. The next nine are the proxy's counts and values (below). The last, `engines`, is the state of each engine that has started, listed in engine name order in the form `[{"engine", "generation", "mode", "phase"}, ..]` |
| `{"op":"switch","engine"?:"<engine>","expect":"<fingerprint>"}` | Only if the generation chosen in the rules store for `engine` (`coraza` or `modsecurity`; if omitted, the default engine) is the same as `expect`, it switches that engine in the same way as SIGUSR1 (an engine that is not running is started). After the switch ends, it responds with `{"result", "reason"?, "generation"}`. `generation` is the generation running on that engine at the time of the response (`null` if it is not running) |
| `{"op":"reload","managed":"<version>"}` | With the configuration file and the specified version, it reloads the configuration in the same way as SIGHUP. It does not read the managed store's `current`. It reloads even for the same version. It responds after the reload ends (below) |
| Any other line | `{"result":"error","reason":..}`. `reason` is one of `line too long`, `malformed request`, `unknown op`, `bad expect`, `bad engine`, `bad managed` |

The `status` counts and values are read when the response is built. Except for `uptime_ms`, `config`, `managed`, and `resolve_timeout_ms`, they are the same as the values that `/metrics` outputs (see "Metrics (`/metrics`)" below).

| Field | Content |
|---|---|
| `uptime_ms` | Milliseconds since the proxy started |
| `requests` | The number of requests. All seven `class` values of the log are counted (the total of `tukuyomi_requests_total`) |
| `blocked` | The number of requests that rules blocked (`block` of `tukuyomi_waf_rule_hits_total`) |
| `policy_refused` | The number of requests refused by access control and rate limits. These are the 403 responses from access control and the 429 responses from rate limits in the global settings and the host policies; 403 responses from a route's `access` and from `admin.route.access` are not counted (the total of `tukuyomi_policy_refusals_total`) |
| `upstream_failures` | The number of failures that occurred on all the upstream servers in the running configuration (the total of `tukuyomi_upstream_failures_total`). When the configuration is switched by a reload, it counts from 0 again, as `/metrics` does |
| `config` | The SHA-256 of the running configuration file (the file read at start or at the last reload that switched) (64 lowercase hexadecimal digits). After a switch by a reload, it is the same as the value in the `reload: configuration replaced` line |
| `managed` | The version of the running managed configuration (64 lowercase hexadecimal digits). `null` for a configuration without `managed` |
| `resolve_timeout_ms` | `forward.resolve_timeout_ms` of the running configuration |
| `config_reloads` | `{"replaced", "refused"}`. The number of configuration reloads by SIGHUP and by `reload` requests, split by whether they switched or were refused (`tukuyomi_config_reloads_total`) |

- A response without these values comes from a proxy of an earlier build. The admin process treats a missing value as `null` (see "Listing and Contents" in the [admin reference](admin-reference.md)). A response without `engines` also comes from a proxy of an earlier build, which does not return the state of each engine (see "Choosing and Rolling Back" in the [admin reference](admin-reference.md)).

The `result` of `switch` is as follows.

| `result` | `reason` | When |
|---|---|---|
| `switched` | None | The switch ended and the engine is running the chosen generation (an engine that was not running has started) |
| `unchanged` | `already serving` | The chosen generation is already in use |
| `refused` | `current changed` | The chosen generation in the rules store differs from `expect` (also when the engine has no chosen generation). Nothing is done |
| `refused` | `store refused` | The rules store or the configuration was rejected |
| `failed` | `driver did not take the order`, `not switched` | The switch could not be started, or the new generation did not start |
| `busy` | `starting`, `switch under way`, `too many orders`, `stopping` | The inspection kernel is not ready yet, another switch is in progress, there are too many requests, or the proxy is stopping |

- The result of a switch is counted in `tukuyomi_rules_switches_total`, as with SIGUSR1. The only responses not counted are `unchanged`, `busy`, and `current changed`. `store refused` is counted in `refused`, and `driver did not take the order` and `not switched` in `failed`.
- A switch request waits for the response for `ready_wait_ms` plus 5 seconds. After that it responds with `busy` (`switch under way`), and the switch continues.
- When the proxy cannot respond to the status query within 2 seconds (including when there are too many requests and during a stop), it returns `{"result":"error","reason":"no answer"}`.
- Every time the proxy responds to a switch request, one line `control: switch expect <fingerprint>: <result> (<reason>), serving <fingerprint>` is written to the log. This includes a `busy` response. When a switch that got the response `busy` ends later, one more is written at that time. This line does not name the engine. `serving` is the generation running on the engine of the request, or `none` if it is not running.

In every response to `reload`, `managed` is the version running at the time of the response (`null` for a configuration without `managed`).

| `result` | Form | When |
|---|---|---|
| `replaced` | `{"result":"replaced","config":"<sha256>","managed":"<version>"}` | It switched. The two values are the same as in the `reload: configuration replaced <sha256> managed <version>` line |
| `refused` | `{"result":"refused","reason":..,"detail":..,"managed":..}` | Nothing was changed. `reason` says where it was refused: one of `configuration` (the configuration file or the country database), `version` (the check of the version), `store` (the managed store, the names and contents of versions and files), `upstream` (name resolution, the CA of the upstreams), `tls` (the certificates of listeners, sites, the admin route), `fixed` (a setting key that cannot change while running, an upstream of an engine that is not running), `listener` (a new listener could not be bound), or `thread` (the reload thread could not be started, or the thread ended without responding). `detail` is the same text that follows `refused: ` in the log line |
| `refused` | `reason` is `unmanaged`, `detail` is `the configuration in force has no managed object` | The running configuration has no `managed`. It is refused without starting a reload |
| `busy` | `{"result":"busy","reason":..,"managed":..}` | `starting` (before the listeners are bound), `reload under way` (a reload by SIGHUP or by another `reload` is in progress, or this request's reload did not end within its waiting time; in that case too, the reload continues), `too many orders`, `stopping` |

- A `reload` request waits for the response for the running configuration's `forward.resolve_timeout_ms` plus 5 seconds.
- The version in the request must be 64 lowercase hexadecimal digits (anything else is `bad managed`), and cannot point outside the managed store. What this request can do is the same as what the same OS user can do by writing `current` and sending SIGHUP.
- A reload started by a `reload` request is counted in `tukuyomi_config_reloads_total`, as with SIGHUP. A request that did not start a reload (`busy`, `unmanaged`, `error`) is not counted.
- When a request starts a reload, the log gets a `reload: control reload <version>` line, and one `control: reload <version>: <result> (<reason>)` line for each response (`replaced` has no `(<reason>)`). For a request that got the response `busy` because the waiting time ran out, one more line is written when the reload ends.
- For how the admin process uses this request to apply a configuration, see "Applying" under "Managed Configuration" below.

### Relations Between Values

Besides the range of each value, start and `config check` check the following relations.

| Relation | Reason |
|---|---|
| `inspect_body ≤ max_body` | What is inspected is the first part of the body |
| `max_body ≤ max_body_wire ≤ 2 × max_body + 4 MiB` | A chunked body also carries the chunk size lines and delimiters on the wire |
| `max_buffered_bytes ≥ 2 × inspect_body + 24 KiB + 32 KiB` | The most that one request buffers: the first part to be inspected, the copy for the inspection kernel, the header fields, and the piece being streamed |
| `routes[].max_body ≤ max_body` | A route can only lower it |
| `http2.max_header_list ≤ 4 × max_head_bytes` | The size of the header fields after expansion |
| `connection_window + max_streams × (send_buffer + 32 KiB) ≤ 16 MiB` | The amount that one HTTP/2 connection can hold |
| The above plus `max_streams × (max_header_list + upstream_max_head_bytes)` is also at most 16 MiB | Same as above (the header fields of each stream, and the piece read from the upstream) |
| `upstream_head_wire ≥ 2 × upstream_max_head_bytes` | Reading the header section from the upstream |
| `drive_slice ≤ tick` | One turn of the driver is shorter than one step of the inspection kernel |
| `ready_wait ≥ hello_wait` | The wait for readiness includes waiting for the inspector process's first message |
| `head_read ≤ request_total`, `body_read ≤ request_total` | Stages within the request time |
| `inspect_wait ≥ wait_deadline + 2 × verdict_wait + 18 × (drive_slice + frame_io)` | The shortest time that one inspection needs |
| `inspect_wait ≤ request_total` | A stage within the request time |
| `upstream_connect + upstream_header < request_total` | The two stages of the exchange with the upstream end within the request time. Making `upstream_header` longer than `response_idle` has no effect for a request whose body is buffered (see `response_idle_ms` above) |
| `request_total ≤ conn_total`, `response_idle ≤ conn_total`, `keepalive_timeout ≤ conn_total` | Stages within the connection time |
| `upstream_keepalive_timeout ≤ response_idle` | The read idle limit also applies to a connection that waits to be reused |
| `keepalive_time + request_total ≤ conn_total` | A request that started before `keepalive_time` receives the response header section within the connection time |
| `lingering_timeout ≤ lingering_time` | Reading before closing |
| `stop_inspect < stop_wait`, `stop_inspect + kill_grace < stop_wait` | The order of the stop stages |
| `wait_queue ≤ max_conns` | One connection holds one inspection |
| `kernel.records ≥ slots + wait_queue` | The records of the inspection kernel |
| `tick ≤ 1 s`, and `tick` is at most any other time of the inspection kernel | One step of the inspection kernel |
| An upstream's `engine` and `kernel.default_engine` can only be engines for which the configuration has an inspector process (`modsecurity` needs `kernel.engines`) | An engine without an inspector process cannot inspect |
| Upstreams that have servers with the same address all have the same engine | Otherwise, a client could reach the same server through the upstream with the weakest engine or mode just by choosing `Host` (see "Choosing the Inspection Engine" below) |
| If there is a country list (`deny_countries` or `allow_countries` in the global `access`, in the `access` of `host_policies`, or in the `access` of a route), `geo` is also present | A database is needed to look up countries |
| `rules.store.dir`, `records.dir`, `admin.store.dir`, and the directory of `admin.control` are not the same as one another, and none is inside another. `admin.control` itself is not inside any of the first three | Prevents rotating or rewriting one from replacing the contents of another |
| `managed.dir` is not the same as any of the four directories above, is not inside any of them, and does not contain any of them | Same as above |
| `acme.challenge_dir` is not the same as any of the five above (including `managed.dir`), is not inside any of them, and does not contain any of them. This also applies without `managed` | `acme renew` replaces and deletes the challenge files, and a challenge response must never return a file inside another directory |
| With `managed`, `acme.account_key_file`, `acme.ca_file`, and the `cert_file` and `key_file` of `admin.route` are not inside `managed.dir` | Keeps `acme renew` from overwriting a name inside the managed store |
| `admin.listen` does not overlap `proxy.listeners` and `status.listen` | The same port cannot be bound by two listeners |
| If `records` of a route is `required`, `records` is present | A file to keep the logs in is needed |
| If `records.ship` is present and `records.keep` or the `records` of a route has `required`, `records.files ≥ 3` | Keeps the threshold at which requests are refused because the records shipper lags (`files − 2` files) from becoming 0 |

- In the time relations, the setting key names are written without `_ms`.

## Request Body Limits and Inspected Length

- The recommended values are 100 MiB for `max_body` and 16 KiB for `inspect_body`. We plan to review `inspect_body` after the inspection load has been measured.
  - On a host with 1 vCPU, inspecting a JSON body of almost 1 MiB took about 7 seconds.
  - If the inspection takes longer than `verdict_wait_ms`, the request gets 503. The inspector process keeps using CPU until that inspection finishes, even after the 503 has been returned.
  - If the inspection also exceeds `stop_after_ms`, the inspector process is stopped and restarted. Until the restart is complete, other requests to that engine also get 503. The restart also counts toward the number of restarts (`restarts`).
- If a body ends within `inspect_body`, the proxy buffers the whole body, inspects it, and forwards it in the inspected form.
- For a longer body, only the first `inspect_body` bytes are inspected. If the request is allowed, the rest is passed to the upstream as the client sends it (without buffering).
  - Nothing after the first part is inspected.
  - A streamed body is sent with the message framing the client used (length or chunked).
- The body of a bypass route is buffered and forwarded if it ends within `inspect_body`, and streamed in the same way if it is longer.
- gzip bodies:
  - Inspected routes: The proxy buffers and decompresses the whole body. Both the gzip length and the decompressed length can be at most `inspect_body` (or the route's `max_body`, if that is smaller). If either exceeds it, the response is 413. A body that cannot be read as gzip, bytes that follow the gzip data, and an empty gzip body get 400. The proxy inspects the decompressed body without `Content-Encoding` and forwards it as it is.
  - Bypass routes: The proxy does not decompress the body. It is handled like other bodies, and the limit applies to the gzip length.
- If `max_body` is exceeded while a chunked body is being streamed, the proxy cannot return 413 (it has already started sending to the upstream). It cuts the request to the upstream, closes the client connection, and writes the reason to the log.
- Budget (`max_buffered_bytes`):
  - A request that streams its body holds the following. During inspection: the first `inspect_body` bytes, the inspection kernel's copy (the first part and the header fields), and a small buffer for streaming (32 KiB). After the verdict: only the first `inspect_body` bytes and the 32 KiB buffer. This does not grow with the length of the body. A bypass route has no copy for the inspection kernel.
  - This amount is needed for each request in progress at the same time, so size the budget for the largest number of simultaneous requests you expect.
  - Outside the budget, the streamed body also occupies the upstream connection's read buffer (up to `upstream_max_head_bytes`). It does not grow with the length of the body, but it grows with the number of requests streamed at the same time.
  - The HTTP/2 windows and buffers are also outside the budget (see `http2` above).
- Time to send large requests:
  - `request_total_ms` covers the time until the response header section arrives, including the time to receive the body. For example, receiving 100 MiB in 60 seconds (`request_total_ms` 60000) requires about 14 Mbit/s. If you accept large requests, set it larger to match the line speed.
  - `upstream_header_ms` is counted from the moment the last piece of the body is handed to the upstream. Set it larger if the upstream takes a long time to process large requests.
  - While the body is being streamed, the interval between reads from the client can be at most `body_read_ms`.

## Rule Sets and Generations

- A generation is a complete rule set created by `rules import`. It is identified by its fingerprint (the SHA-256 of the manifest). It does not change after it is created.
- A generation also records the engine that inspects requests with its rules (`rules import --engine`; if omitted, the engine of `kernel.default_engine`; if that is not set, `coraza`). The engines in this build are `coraza` (Coraza) and `modsecurity` (ModSecurity v3). The same files give a different manifest under a different engine, and so a different generation (a different fingerprint). A `modsecurity` generation can be imported, chosen, and started only when `kernel.engines` in the configuration has an inspector process.
- "Settings and Rules Added by the Inspector" applies to Coraza generations. For ModSecurity generations, see "ModSecurity Generations".
- Contents of the rules store:
  - `generations/<fingerprint>/`: the generations
  - `current.<engine>` (`current.coraza`, `current.modsecurity`): the generation chosen for each engine. A `current` written by an earlier version is also read (see "Chosen Generation per Engine" below)
  - `current.<engine>.new`: what is left over when choosing a generation stopped halfway. The next choice for the same engine cleans it up
  - `using/<fingerprint>`: the marker for a generation in use
  - `staging/`: an import in progress
  - `lock`: the lock for commands
- Only one command or admin process at a time can change the rules store. The next command cleans up what a command that stopped halfway left behind.
- The fingerprint detects accidental corruption and mix-ups, and a start whose contents differ from the fingerprint held by the running proxy. It does not prevent a process running as the same OS user (the inspector process runs as the same OS user) from rewriting the rules store. It is not authentication across restarts either.
- If a file of a generation in use is corrupted after the start, the next restart of the inspector process fails (exit 11 if a file differs from the manifest, a fingerprint mismatch if the manifest has changed). The inspection kernel then stops, treating this as a failure that a restart cannot fix, and the proxy also stops.

### Detect-Only Mode

- A generation created with `rules import --detect-only` also lets requests that match a rule through. In the request log, `class` is `forwarded`, `reason` is `detected by a rule`, and `rule` holds the ID of the matching rule.
- It uses the same rule files as a generation in block mode; the only difference is whether it blocks. We recommend running in this form first, checking for false positives, adding exclusions, and then importing the generation in block mode again.
- Even a detect-only generation blocks on the rules in "Settings and Rules Added by the Inspector" below.
- A Coraza detect-only generation adds marker rules (IDs 4000010 and 4000011) before and after the rules. If an operator's rule removes or skips them, the request cannot be inspected and gets 503. It is never silently blocked or passed through. A ModSecurity generation does not add marker rules.

### Settings and Rules Added by the Inspector

The inspector process adds the following after the operator's rules. Operator rules cannot change them.

- The inspection engine is On, it reads the body, and it refuses a body that exceeds the body limit. JSON nesting is limited to 64 levels.
- The inspector process uses rule IDs 4000001 to 4000003 in all generations (in order, they block on a body parse failure, on reaching the limit on the number of arguments, and on a URI parse failure). 4000010 and 4000011 are used in detect-only generations. If an operator's rule uses the same ID, the rule set of that generation cannot be built. In a generation in block mode, a rule set that uses 4000010 or 4000011 can be built, but it can no longer be imported again as a detect-only generation, so do not use them.
- A rule that contains any of the following is rejected. The check looks only at the character sequence, ignores case, and also matches words inside `msg`.
  - `Include`, `SecIgnoreRuleCompilationErrors` (even if the argument is `Off`)
  - Directives whose names start with `SecAuditLog`, `SecDebugLog`, or `SecUpload`
  - `ctl:ruleEngine`, `ctl:requestBodyAccess`, `ctl:requestBodyLimit`
  - `@inspectFile`, `@rbl`, `setenv:`
  - The variable name `reserved_body_cut`
- If an operator's rule changes body processing (for example with `ctl:requestBodyProcessor`) or removes one of the rules above at run time, so that the proxy cannot verify that inspection has finished, the request gets 503. For other requests that a ModSecurity generation treats as uninspectable, see "ModSecurity Generations".

### Operator Responsibilities

- Intentionally removing blocking rules with `ctl:ruleRemoveById`, `SecRuleRemoveById`, and so on is left to the operator's judgment and is not refused.
- However, in a Coraza generation, if a `SecMarker` comes before `SecRuleRemoveByMsg`, Coraza terminates abnormally and the rule set cannot be built (exit 11). CRS uses many `SecMarker`s, so `SecRuleRemoveByMsg` cannot be used together with CRS.
- The import and the inspector process detect only `SecMarker` mistakes (a `skipAfter` to a `SecMarker` that does not exist or comes earlier, a mistyped name).
- Parsing can fail when a body is cut in the middle. So if an operator adds the rules that look at `REQBODY_ERROR` and `MULTIPART_STRICT_ERROR` (200002, 200003) from Coraza's recommended configuration, those rules also block a body that was cut to its first part.
  - Rule 4000001 of the inspector process does not block on a parse failure of a cut body.
  - CRS 4.23.0 has no rule of this kind.
- By default, the CRS blocks `application/<name>+json` bodies. To accept them, add the types to the accepted types in `crs-setup.conf` before the import.

### ModSecurity Generations

A generation created with `rules import --engine modsecurity` inspects requests with libmodsecurity (ModSecurity v3.0.17). The inspector process is a separate executable (`tukuyomi-inspector-modsecurity`), set in `kernel.engines.modsecurity.inspector` in the configuration (see the [build and deployment guide](../build/binary-deployment.md)). The import procedure, the trial, `--detect-only`, bypass routes, and the CRS import are the same as for Coraza generations. When the engine is chosen per upstream, the same request can give a different result depending on the engine. The differences are summarized in the second half of this section (for how to choose an engine, see "Choosing the Inspection Engine" below).

Settings and rules added by the inspector process (operator rules cannot change them):

- The inspection engine is On, body reading is enabled, and JSON nesting is limited to 64 levels. The inspector process sets these three before the operator's rules. ModSecurity uses the value that was set first, so writing `SecRuleEngine`, `SecRequestBodyAccess`, or `SecRequestBodyJsonDepthLimit` in a rule has no effect.
- The limits on the body and the arguments are not set in ModSecurity. The inspector process counts them itself. The number of arguments is limited to 1000 each for the query, a form body, and a JSON body. Above that, rule 4000002 blocks (for JSON, the number of values and the number of non-empty arrays are counted separately). A multipart body is not counted.
- Rule IDs 4000001 to 4000011 are reserved for the inspector process. If an operator's rule uses one of them, the rule set of that generation cannot be built, whatever the mode. A ModSecurity generation does not add the marker rules (4000010, 4000011), even in a detect-only generation.
- Rules 4000001 (body parse failure), 4000002 (limit on the number of arguments), and 4000003 (URI parse failure) block, even in a detect-only generation. 4000001 does not block a body that was cut at the inspected length.

In the import trial, the inspector process reads and checks the rule files. If any of the following is present, the inspector process does not start (exit 11) and the import fails. A line that starts with `rules import: the inspector said:` on standard error (the `detail` of `trial` in the admin API) gives the reason and the name of the rule file. Even syntax that ModSecurity can read is rejected unless it is in the fixed form that can be checked, so a harmless rule may be rejected.

- Files: a file with CR at the end of a line (CRLF line endings), a file that contains NUL, and a file that does not end with a newline
- Syntax: anything not in the fixed form. For example, a phase in quotes such as `phase:'request'`.
- Directives: the directives you can use are `SecRule`, `SecAction`, `SecDefaultAction`, `SecMarker`, `SecRuleRemoveById`, `SecRuleRemoveByTag`, `SecRuleRemoveByMsg`, `SecRuleUpdateTargetById`, `SecRuleUpdateTargetByTag`, `SecRuleUpdateTargetByMsg`, `SecRuleEngine`, `SecRequestBodyAccess`, `SecRequestBodyJsonDepthLimit` (accepted but without effect), `SecComponentSignature`, `SecAuditEngine Off`, and the response body directives (`SecResponseBodyAccess`, `SecResponseBodyLimit`, `SecResponseBodyLimitAction`, `SecResponseBodyMimeType`, `SecResponseBodyMimeTypesClear`). Others are rejected. For example:
  - `Include`, directives whose names start with `SecRemoteRules`, `SecIgnoreRuleCompilationErrors`
  - Directives whose names start with `SecAuditLog`, `SecDebugLog`, or `SecUpload`, `SecTmpSaveUploadedFiles`, `SecDataDir`, `SecTmpDir`
  - Directives that set the limits on the body and the arguments (`SecRequestBodyLimit`, `SecRequestBodyNoFilesLimit`, `SecRequestBodyLimitAction`, `SecRequestBodyInMemoryLimit`, `SecArgumentsLimit`)
  - Directives that ModSecurity does not know
- Actions: the actions you can use are `accuracy`, `allow`, `auditlog`, `block`, `capture`, `chain`, `ctl`, `deny`, `drop`, `expirevar`, `id`, `initcol`, `log`, `logdata`, `maturity`, `msg`, `multiMatch`, `noauditlog`, `nolog`, `pass`, `phase`, `redirect`, `rev`, `setrsc`, `setsid`, `setuid`, `setvar`, `severity`, `skip`, `skipAfter`, `status`, `t`, `tag`, `ver`, and `xmlns`. Others are rejected, including `exec` and `setenv`.
  - The `ctl` settings you can use are `auditEngine`, `auditLogParts`, `forceRequestBodyVariable`, `parseXmlIntoArgs`, `requestBodyProcessor`, `ruleRemoveById`, `ruleRemoveByTag`, `ruleRemoveTargetById`, and `ruleRemoveTargetByTag`. Others are rejected, including `ruleEngine`, `requestBodyAccess`, and `requestBodyLimit`.
  - A rule that has both an action that blocks the request (`deny`, `drop`, `redirect`, `block`) and `nolog` or `noauditlog` is rejected, because it would no longer be clear which rule blocked. `nolog`, `noauditlog`, or `skipAfter` in `SecDefaultAction` is also rejected.
  - A `skipAfter` whose `SecMarker` does not come after it (in the same file or in a file loaded later) is rejected.
- Operators: `@inspectFile`, `@rbl`, `@validateDTD`, `@validateSchema`, `@fuzzyHash`, `@geoLookup`, `@gsbLookup`, `@rsub`, and `@validateHash` are rejected. The operators that read a file (`@pmFromFile`, `@pmf`, `@ipMatchFromFile`, `@ipMatchF`) can be used only for a file in the rule set, written with a path of only letters and digits, `.`, `_`, and `-`. The path is either a path in the rule set (such as `rules/<name>`) or a path relative to the directory of that rule file.
- Variables and lengths: the variable `ENV` is rejected. A list of variables can have up to 256 entries, and rules joined with `chain` can have up to 64.
- Character sequences: separately from the reading above, the inspector process removes whitespace and quotes from the text of a rule and searches it, ignoring case, for `ctl:ruleEngine`, `ctl:requestBodyAccess`, `ctl:requestBodyLimit`, `exec:`, `setenv:`, `@inspectFile`, `@rbl`, `@validateDTD`, `@validateSchema`, and `@fuzzyHash`. A rule is rejected even if the sequence is inside `msg`.
- Mismatch with the reading: the inspector process compares the rules that ModSecurity built with what it read. A rule that does not match is rejected.

Intentionally removing blocking rules with `ctl:ruleRemoveById`, `SecRuleRemoveById`, and so on is left to the operator's judgment and is not refused, as with Coraza generations.

The differences from Coraza generations are as follows. The same rules and requests can give different results.

1. In a detect-only generation, after an operator's rule has decided that a request is to be blocked, ModSecurity skips only the rules that remain in that phase. As a result, `rules` (the matched rules) and `score` in the log can be shorter and smaller than in a Coraza generation.
2. When parsing of a body cut at the inspected length fails, ModSecurity does not pass the part of the body after the point where parsing stopped to the rules. When parsing does not start because of a `Content-Type` parameter (for example, when `Boundary=` is written in capitals), ModSecurity passes no body at all. For a body that was not cut, a parse failure is blocked by 4000001.
3. A JSON body nested 62 to 64 levels deep is not blocked by ModSecurity, but is blocked by Coraza. From 65 levels, both block (the specified limit is 64 levels).
4. For a request-blocking rule with `multiMatch`, and for a request-blocking `SecAction` without `msg`, ModSecurity treats every request that they blocked as uninspectable. It gets 503, and the proxy does not let it through.
5. If a regular expression written in a variable selection such as `ARGS:/re/` fails, ModSecurity leaves no failure marker, so the request is not treated as uninspectable.
6. Failures of `@verifyCC`, `@verifyCPF`, and `@verifySSN` are the same as in 5: no failure marker is left (CRS does not use them). A failure of `@rx` is treated as uninspectable.
7. The values of a JSON body go only into `ARGS`, not into `ARGS_POST` (CRS reads `ARGS`).
8. `REQUEST_URI` is the URL with `%XX` decoded (the form before decoding is `REQUEST_URI_RAW`). So a rule that looks at `REQUEST_URI` can match an attack encoded with `%XX` in the path in a ModSecurity generation, even if it does not match in a Coraza generation.
9. A multipart body without a closing boundary is blocked by 4000001 in ModSecurity as a body parse failure (except a cut body). Coraza lets it through.

The following requests are treated as uninspectable in a ModSecurity generation and get 503. In a Coraza generation, they are not.

- A request for which the regular expression of a rule failed or reached the match limit (except those in 5 and 6)
- A multipart body with an empty boundary (`boundary=` or `boundary=""`). This is because ModSecurity parses nothing of this body and does not report it.
- A non-empty body with two or more `Content-Type` headers. However, the proxy refuses it first with 415 (see "Body Types"), so it does not reach the inspector process.

As with Coraza generations, a request for which the inspector cannot verify that inspection has finished, for example because body processing was changed, gets 503 (see "Settings and Rules Added by the Inspector").

### Choosing the Inspection Engine

Each upstream can have its own engine for inspecting requests. The engines are `coraza` and `modsecurity`.

- Choose it with the upstream's `engine`. Requests to an upstream that omits it are inspected by the default engine (`kernel.default_engine`; `coraza` if not set). The default engine is also used when `rules import` is run without `--engine`. For the form and the values that are rejected, see "`forward`" and "`kernel`" above.
- A request is inspected by the engine of the upstream it goes to. Only the inspection kernel of that engine is used, and the request is never sent to another engine. If that inspection kernel is unavailable, the proxy responds with 503.
- Depending on the engine, the same request can give a different detection result (see "ModSecurity Generations").
- An upstream that uses an engine whose chosen generation is in detect-only mode does not block even a request that matches a rule. At start, reload, and `config check`, the proxy writes an `upstream <name>: engine <engine>, mode detect` line for each such upstream (it starts with `start:`, `reload:`, or `config check:`).

Admin route:

- With `managed`, the admin route (`admin.route`) is inspected by the default engine.
- For the default engine, use a generation in which the import route is a bypass route (for the reason, and for what to do when you change the default engine, see "Bypassing Inspection for the Import Route" in the [admin reference](admin-reference.md)).
- Without `managed`, requests to an upstream that forwards to the admin process are inspected by that upstream's engine (see "`admin`" above).

Servers at the same address:

- A configuration in which upstreams that have a server at the same address use different engines is rejected (`two upstreams with a server at the same address have different engines`). Otherwise, a client could reach the same server through the upstream with the weakest engine or mode, just by choosing `Host`.
- For a server written as an IP literal, addresses are compared by the canonical form of the IP address (an IPv4 address written in IPv6 form is the same as the IPv4 address) and the port. For a server written as a name, they are compared by name and port. Different names that point to the same IP address are not recognized as the same address. The operator must give the same engine to upstreams that reach the same server under different names.

Engines to start:

- The proxy starts every engine that has a chosen generation and has an inspector process in the configuration. The default engine goes first, and the others in name order. It also starts an engine that no upstream uses.
- The default engine and the upstream engines need a chosen generation. If there is none, both start and `config check` reject the configuration with `rules store refused: no generation is chosen`.
- When the default engine has no chosen generation and another engine has one, the configuration is rejected with `rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine`. This happens, for example, when you update a host on which a ModSecurity generation was chosen with an earlier version. Write `kernel.default_engine`, or choose a generation for the default engine (see "Version Updates" below).
- An engine that has started keeps running until the proxy stops, even if you run `rules deactivate`.

Number of processes and memory estimates:

- One proxy always runs, plus one inspector process for each engine that has started. When only Coraza is started, there is one inspector process.
- The number of inspector processes increases in the following cases.
  - During a generation switch, that engine has one more inspector process. Only one switch at a time can run in the whole proxy, so there is at most one extra. The inspector processes that are child processes of the proxy therefore number at most the number of started engines plus 1.
  - A trial (`rules import` and an import through the admin API) starts one inspector process.
- The admin process and the records shipper are separate from these.

The memory estimate has three parts: the values measured for each inspector process, an estimate made by adding them, and a measurement with two engines started. The unit is MiB. The values change with the host and the content of the requests.

- The values measured for each inspector process. They were measured with the same inspector executables as this version and CRS 4.23.0, on a Linux host with 4 logical CPUs and 8 GiB of memory, with only one engine started.

  | Process | Right after start | After requests up to 16 KiB | After streaming a 1 MiB body |
  |---|---|---|---|
  | Coraza inspector process | about 57 | about 69 | about 110 to 112 (maximum about 125). It does not go down after this |
  | ModSecurity inspector process | about 43 | about 43 | about 43 (maximum about 52) |

  The 1 MiB column is the value with `proxy.inspect_body` set to 1 MiB and a 1 MiB body streamed. When `inspect_body` is the recommended 16 KiB, the values for up to 16 KiB apply.
- The estimate made by adding. It adds up the values above that were taken under the same conditions, and is not a measured total. The proxy is not included.
  - When two engines are started, about 100 to 112 for ordinary requests (the sum of about 57 to 69 for Coraza and about 43 for ModSecurity). The maximum while a 1 MiB body is streamed is about 178.
  - The worst case, when one generation switch and one trial overlap, is about 240 for ordinary requests and about 305 at the maximum while a 1 MiB body is streamed. The figures of about 240 and about 305 include an assumption: the process that runs the trial is assumed to use about 9 itself, the same as the proxy right after start (not measured).
- The measurement with two engines started. A Core Rule Set generation was chosen for both engines, and a few ordinary requests and a few SQL injection requests were sent. After that, the resident memory (VmRSS) was about 10 for the proxy, about 52 for the Coraza inspector process, and about 43 for the ModSecurity inspector process. The conditions (generation and requests) differ from those of the per-process measurements, so the values do not match. No 1 MiB body was streamed. During a generation switch, the number of inspector processes rose from 2 to at most 3.

An engine that no upstream uses:

- An engine may be running that no upstream uses and that is not the default engine, for example when you start ModSecurity to try it out. Even for such an engine, if its inspection kernel fails, the whole proxy stops, writes a `stop: the kernel failed, engine <engine>: <reason>` line, and exits with 1 (see "`kernel`" above). For example, when `kernel.restarts` is 0 and you stop the inspector process of that engine with SIGKILL, the proxy writes a `stop: the kernel failed, engine <engine>: BudgetExhausted` line and stops.
- After trying it out, clear that engine's choice with `rules deactivate`. From the next restart, that engine does not start. The running proxy does not stop an engine that has started, so restart the proxy to stop it (see "Chosen Generation per Engine" below).

Steps to change the default engine:

Changing the default engine also changes the inspection engine of the upstreams that omit `engine`. For an upstream you do not want to change, first write its current engine in `engine`. `kernel` cannot change while running, so changing `kernel.default_engine` requires restarting the proxy. The following example shows the steps to change the default engine from `coraza` to `modsecurity` in a configuration with `managed`. Run the commands as the same OS user as the service.

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

- Create the generation for the new default engine with the first `rules import`. Put the CRS tuning for the admin Host (see "CRS Tuning for the Admin Host" in the [admin reference](admin-reference.md)) and the bypass route for the import route (see "Bypassing Inspection for the Import Route" in the admin reference) into that generation as well.
- Choose that generation before you write `kernel.default_engine`. As long as you do not send SIGUSR1, that engine does not start and the proxy keeps running.
- If you write `kernel.default_engine` and run `config check` before you choose the generation, the configuration is rejected with `rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine` (exit 1). Start also rejects it with the same message.
- SIGHUP to the running proxy is refused with `reload: configuration refused: kernel cannot change while running`, even if `config check` says `accepted`. To make the change, restart.
- After the restart, the `start: rules engine` lines appear with the default engine first. Requests to the admin route are inspected by the new default engine, and requests to an upstream that has `engine` are inspected by the engine written there (`engine` in the request log).
- The admin process also reads `kernel.default_engine` from the configuration file, so restart it together with the proxy (see "Admin Screens" in the [admin reference](admin-reference.md)).

### Chosen Generation per Engine

The rules store holds one chosen generation for each engine.

- The files are `current.coraza` and `current.modsecurity`. The content is the fingerprint of the generation (64 lowercase hexadecimal digits) and a newline, 65 bytes in all.
- `rules activate <config> <fingerprint>` writes `current.<engine>` for the engine of that generation. It writes to `current.<engine>.new`, syncs, and then replaces the file, so half-written content is never read even if the command stops halfway. A `current.<engine>.new` left behind by a command that stopped halfway is never read. The next `rules activate` for the same engine removes it.
- `rules list` puts the `current` marker on the chosen generation of each engine. If generations are chosen for two engines, the marker is on two lines.

The `current` written by an earlier version:

- This version does not write `current`. A `current` written by an earlier version is read as the chosen generation of the same engine. If an engine has no `current.<engine>` and the generation that `current` points to belongs to that engine, that generation is the chosen generation of that engine.
- After writing `current.<engine>`, `rules activate` removes the `current` that points to a generation of the same engine. So once you choose a generation with this version, the earlier version can no longer read that engine's chosen generation (see "Version Updates" below).
- If both `current` and `current.<engine>` exist for the same engine and point to different generations, the proxy uses neither and rejects them with `the current generation records of the engine disagree`. `rules list`, `config check`, start, and SIGUSR1 all behave the same way. This state arises, for example, when you choose again with an earlier version. Choosing that engine's generation again with `rules activate` writes `current.<engine>` and removes `current`, which resolves it.
- If `current.<engine>` points to a generation of another engine, or the content of the file is not valid, the proxy rejects it with `the current generation record is broken`. If the file cannot be read, it rejects it with `the current generation record cannot be read`.

`rules deactivate <config> <engine>`:

- It clears that engine's choice: it deletes `current.<engine>` and the `current` that points to a generation of the same engine, and writes the generation that is no longer chosen in a `<fingerprint> deactivated` line. From the next restart, that engine does not start.
- The running proxy does not stop the inspection kernel of an engine that has started. That engine keeps running until you restart the proxy. A SIGUSR1 before the restart writes a `reload: rules store refused: no generation is chosen` line (see "SIGUSR1 (Generation Switch)" above).
- It reads the configuration file and the selected version of the managed store. If the default engine or any upstream engine is that engine, it writes a `rules deactivate: the configuration uses the engine` line and refuses (exit 1). When the engine has no chosen generation, it also refuses, with a `rules deactivate: no generation is chosen` line (exit 1).
- With `managed`, when the configuration is rejected, for example because the selected version cannot be read, it writes a `rules deactivate: configuration refused: <reason>` line (exit 2). Of the `rules` commands, only this one reads the managed store.

Adding an upstream for an engine that is not running:

Follow these steps to have an upstream use an engine that has a chosen generation but is not running (for example, when no ModSecurity generation was chosen at start). A reload does not start an inspector process and refuses an upstream whose engine is not running, so start that engine with SIGUSR1 first. The following example adds a ModSecurity upstream `mod` to a proxy that has only Coraza running, in a configuration with `managed`.

```text
tukuyomi-proxy rules activate <config> <fingerprint-modsecurity>   # choose the ModSecurity generation; do not send SIGUSR1 yet
tukuyomi-proxy managed activate <config> <version>                 # a version that has the upstream mod; accepted because a ModSecurity generation is chosen
kill -HUP <proxy-pid>
   reload: SIGHUP
   reload: configuration accepted
   reload: configuration refused: the engine of an upstream is not ready (upstream mod)
kill -USR1 <proxy-pid>                                             # ModSecurity starts
   reload: SIGUSR1
   reload: generation <fingerprint-coraza> is already running
   reload: starting generation <fingerprint-modsecurity>
   reload: rules engine modsecurity
   reload: rules mode block
   reload: rules routes 0
   reload: generation <fingerprint-modsecurity> is ready, switched
kill -HUP <proxy-pid>
   reload: SIGHUP
   reload: configuration accepted
   reload: configuration replaced <sha256> managed <version>
```

- The first SIGHUP is refused because ModSecurity is not running. The proxy keeps running with the previous configuration, and the `refused` count of `tukuyomi_config_reloads_total` goes up by 1.
- If you start ModSecurity with SIGUSR1 first and then send SIGHUP, the reload is not refused.
- `managed activate` refuses without selecting the version if an engine used by the version's upstreams has no chosen generation (see "`managed`" above). So run `rules activate` first.

### Bypass Routes

The file for `rules import --routes <file>` is a JSON array of the following form:

```json
[
  {"host": "app.example.com", "path": "/api/uploads", "action": "bypass"}
]
```

- `host` is optional. Other setting keys are rejected. `action` can only be `bypass`.
- A request that matches a route is not inspected and is forwarded to the upstream.
  - The proxy does its own checks (the header section and the body size limit) before that. It does not check the body type (see "Body Types" below).
  - The upstream is chosen by a `forward` route or the default upstream, not by the bypass route. Matching a bypass route does not change the response to a request that gets 404, 403, or 421 there, a request refused by the global `access` and `rate_limit` or by the host policies (403, 429), or a request refused by the admin route (`admin.route`) (421, 404, 403).
  - A bypass request does not take an inspection slot, so it passes even when inspection is busy or the inspector process is stopped.
- Routes belong to each engine's generation. A request is affected only by the routes of the running generation of the engine that inspects it (its upstream's engine). Routes in other engines' generations do not make that request a bypass.
- The form and the matching of `path` and `host` are the same as for `forward` routes. In addition:
  - `path` cannot be only `/` (it would remove inspection of all requests). Write it with 2 to 255 bytes.
  - `host` cannot contain a wildcard.
  - A generation can have up to 256 routes. The same combination of `host` and `path` cannot be written twice.
- A bypass route with `host` does not match a `Host` with a trailing `.` (`app.example.com.`), and the request is inspected, because the upstream might interpret it as a different host. A route without `host` also matches a `Host` with a trailing `.`.
- A request whose path can be read in more than one way (the forms listed in "Notes on using `access`") does not match a bypass route and is inspected.
- Routes are part of the generation's manifest and of its fingerprint. When the running proxy switches an engine's generation, it switches that engine's routes too.

## Managed Configuration

The managed configuration is a mechanism that stores sites (hosts and certificates), upstreams, routes, the default upstream, the global access control and rate limits, and host policies as versions in the managed store, outside the configuration file. Write `managed` in the configuration file to use it. You can edit it from the admin screens and the admin API and apply it to the running proxy (see "Managed Configuration Operations" in the [admin reference](admin-reference.md)). For the commands, see "`managed`" above. A configuration file without `managed` is read as before.

### Whether to Use the Managed Configuration

What you can do:

- You can edit the settings listed above in the admin screens and the admin API, check them, save them, and apply them to the running proxy. Applying advances the selected version only after the proxy has reloaded its configuration with that version, so a version that the proxy refused is never used at the next start (see "Applying" below).
- Saved versions remain, and you can go back to an earlier version (rollback, applying by name).
- Applying from the admin screens and the admin API is recorded in the admin process's configuration history, and the operations in the audit log (see "Configuration History" and "Audit Log" in the [admin reference](admin-reference.md)). Changes made with commands are recorded in neither.

What you need instead:

- Some setting keys can no longer be written in the configuration file. `forward` can have only `resolve_timeout_ms`, and the `certificates` of a TLS listener, the global `access` and `rate_limit`, and `host_policies` cannot be written either (the configuration is rejected if you write them). Write these in a version.
- If the configuration has `admin`, the admin route (`admin.route`) is required (see "`admin`" above). The proxy creates the admin route, and neither the global settings nor the host policies apply to it. The only network restriction that applies to the admin route is `allow_cidrs` of `admin.route.access`.
- `managed` (whether it is present) and `managed.dir` are setting keys that cannot change while running, so when you add or remove `managed`, restart the proxy and the admin process (a configuration reload is refused).
- Requests to the admin route are also inspected by the WAF, with the default engine. Check and save requests from the admin screens can contain a certificate and a private key, so a generation in block mode can block them. For the default engine, use a generation that has those two paths as bypass routes (see "Admin Route with the Managed Configuration" in the [admin reference](admin-reference.md)). When you change the default engine, put the same routes into the new default engine's generation as well (see "Choosing the Inspection Engine" above).
- For a site whose certificate is issued by ACME, the certificate chain and private key are kept in `acme/` in the managed store, not at a path in the configuration file (see "ACME Sites" below).
- If you use the records shipper, replace it with the same build as the proxy first, and then write `managed` in the configuration file. The records shipper also reads the configuration file, and an earlier build that does not know `managed` does not start, because it rejects a configuration file with unknown setting keys (see "Starting the Records Shipper" below). `kernel.default_engine` and the `engine` of an upstream are also unknown setting keys to an earlier build. Replace it with the same build before you write them (see "Version Updates" below).

If you manage the configuration with the file only and do not change it from the admin screens, you do not need `managed`.

### Managed Store and Versions

The setting key `managed` has only `{"dir"}`. `dir` is the managed store directory, an absolute path of at most 3840 bytes.

- The directory must not be a symbolic link, must be owned by the proxy's OS user, and must have no permissions for the group and other users (0700). Neither the proxy nor the commands create this directory, so create it first. It is checked every time it is opened, and a directory that does not meet the conditions is rejected.
- It cannot be the same directory as the rules store, `records.dir`, the admin store directory (`admin.store.dir`), the directory for the control socket, or `acme.challenge_dir`, and none of them can be inside another. `acme.account_key_file`, `acme.ca_file`, and the certificate and private key files used by the admin route cannot be placed inside the managed store (see "Relations Between Values" above).

Contents of the managed store:

| Name | Content |
|---|---|
| `versions/<version>.json` | A version. Up to 1 MiB |
| `files/<sha256>` | A certificate chain, private key, or upstream CA file that a version points to. Up to 1 MiB |
| `acme/<hosts-sha256>/chain`, `acme/<hosts-sha256>/key` | The certificate chain and private key of an ACME site (see "ACME Sites" below) |
| `current` | The SHA-256 of the selected version (64 hexadecimal digits) and a newline |
| `lock` | The lock held by the commands and the admin process that change the managed store |

- Versions and files are named by the SHA-256 of their contents (64 lowercase hexadecimal digits) and do not change after they are created. Each time one is read, its name is checked against its contents, and one that does not match is not used.
- If they do not exist, `versions/` and `files/` are created at import, and `acme/` by `acme renew` (0700). Versions, files, and `current` are written under a name ending in `.new`, synced, and then renamed over the old file, so even if a write stops halfway, a reader reads either the old one or the new one in full.
- A version is accepted only in one canonical form (JSON without whitespace, with the setting keys of each object in byte order), so the same contents always give a version with the same name. Do not write a version by hand; create it with `managed import` or in the admin screens.
- The times in `managed list` are the modification times of the version files.

A version is JSON in the following form.

```text
{"sites": [..], "upstreams": {..}, "routes": [..], "default_upstream": "..", "access"?: {..}, "rate_limit"?: {..}, "host_policies"?: [..]}
```

- `upstreams`, `routes`, `default_upstream`, `access`, `rate_limit`, and `host_policies` are written in the same form and with the same rules as `forward` in a configuration file without `managed` (see "`forward`" above) and as in "Access Control and Rate Limits" below, and they are rejected with the same messages. The only difference is that the `tls` of an upstream is `{"ca", "server_name"?}`, and `ca` is the SHA-256 of a file in `files/` of the managed store. The `engine` of an upstream can be written in the same form as in `forward`.
- `sites` is the list of sites, 0 to 64 of them. A site is written as `{"name", "hosts", "certificate"}`.
  - `name` follows the same rule as the name of an upstream (1 to 64 characters of letters and digits, `-`, and `_`), and the same name cannot be used for two sites.
  - `hosts` has 1 to 64 entries and is written like the `hosts` of a listener's certificate (a name, or `*.` and a name). The same host cannot be written in two sites.
  - `certificate` is either `{"chain", "key"}` (the SHA-256 of the certificate chain and of the private key in `files/` of the managed store) or `{"acme": {"renew_before_days"}}` (see "ACME Sites" below).
- Do not write paths in a version.
- A version is checked together with the configuration file. The `engine` of an upstream is checked against `kernel` in the configuration file (`engines` and `default_engine`), and an upstream that omits `engine` uses the engine of `kernel.default_engine`. The host of the admin route (`admin.route.host`) cannot appear in the `hosts` of a site or in the `host` of a route (a `*.` site may contain it; the admin route matches first). An upstream server cannot use the address of `admin.listen` (this also applies to an address that a name resolves to). If there is a TLS listener, at least one certificate is required, from a site or from the admin route.
- Each TLS listener chooses a certificate from those of the admin route and all the sites, by the host that the client sends in SNI. A certificate for exactly that name is chosen before one that covers the name through `*.`.

The document for `managed import` has the same form as a version, but files are written as paths instead of SHA-256. The `certificate` of a site is `{"chain_file", "key_file"}` or `{"acme": {..}}`, and the `tls` of an upstream is `{"ca_file", "server_name"?}`. A path is absolute and at most 3840 bytes. The document can be up to 1 MiB, and its layout, such as whitespace, is up to you.

- The command reads each file that the document points to once (regular files up to 1 MiB) and checks them in the same way as the proxy (the certificate chain matches the private key and covers the hosts of the site; the CA file is usable). If the checks pass, it places the files in `files/`, and a version that points to them by SHA-256 in `versions/`.
- After the import, the document and the certificate chain, private key, and CA files of the sites that the document points to are no longer used. They have been copied into the managed store, so you can delete them.

The admin process keeps its own configuration history of changes made in the admin screens and the admin API (see "Configuration History" in the [admin reference](admin-reference.md)).

### First Start with the Managed Configuration

This section shows how to start the proxy for the first time with a configuration that has `managed`. Without a selected version, both start and `config check` refuse (`config check: managed store refused: no managed version is chosen`, exit 1), so import and select a version before you start. The other steps are the same as in "First Start" in the [build and deployment guide](../build/binary-deployment.md).

The example has a redirect listener, a TLS listener, one site with a certificate in a file, one upstream, and the admin route. For an ACME site, see "ACME Sites" below.

1. Create the directories. In addition to the directories in the table in "OS User and Directories" in the [build and deployment guide](../build/binary-deployment.md), create the managed store directory with 0700.

   ```bash
   sudo install -d -m 0700 -o tukuyomi -g tukuyomi /var/lib/tukuyomi-core/managed
   ```

2. Place the certificate files.
   - The certificate and private key of the admin route (for example, `/var/lib/tukuyomi-core/tls/admin.pem` and `admin.key`). The configuration file points to them by these paths.
   - The certificate chain and private key of the site (for example, `/var/lib/tukuyomi-core/import/www.pem` and `www.key`). The import reads them, so place them where the OS user of the service can read them.
3. Write the configuration file. It differs from a configuration file without `managed` as follows (write the other setting keys as usual).

   ```json
   "proxy": {
     "listeners": [
       {"address": "0.0.0.0:80", "redirect": {"https_port": 443}},
       {"address": "0.0.0.0:443", "tls": {"min_version": "1.2"}}
     ]
   },
   "forward": {"resolve_timeout_ms": 5000},
   "managed": {"dir": "/var/lib/tukuyomi-core/managed"},
   "admin": {
     "listen": "127.0.0.1:9100",
     "control": "/var/lib/tukuyomi-core/control/proxy.sock",
     "store": {"kind": "file", "dir": "/var/lib/tukuyomi-core/admin"},
     "origin": "https://admin.example.com",
     "trusted_proxies": ["127.0.0.1/32"],
     "mfa": "required",
     "session_idle_ms": 1800000,
     "session_total_ms": 43200000,
     "route": {
       "host": "admin.example.com",
       "certificate": {
         "cert_file": "/var/lib/tukuyomi-core/tls/admin.pem",
         "key_file": "/var/lib/tukuyomi-core/tls/admin.key"
       },
       "access": {"allow_cidrs": ["203.0.113.0/24"]}
     }
   }
   ```

   - `proxy` shows only `listeners`; its other setting keys are left out here. Do not write `certificates` in a TLS listener (`http2` can be written).
   - Write only `resolve_timeout_ms` in `forward`. Write the global `access` and `rate_limit` and `host_policies` in the version.
   - In the `allow_cidrs` of `admin.route.access`, write the networks that the people who use the admin screens connect from.
4. Write the version document (for example, `/etc/tukuyomi-core/managed-import.json`). Place it where the OS user of the service can read it.

   ```json
   {
     "sites": [
       {
         "name": "www",
         "hosts": ["www.example.com"],
         "certificate": {
           "chain_file": "/var/lib/tukuyomi-core/import/www.pem",
           "key_file": "/var/lib/tukuyomi-core/import/www.key"
         }
       }
     ],
     "upstreams": {
       "web": {"servers": [{"address": "127.0.0.1:8080", "weight": 1, "max_fails": 0, "fail_timeout_ms": 10000, "backup": false}]}
     },
     "routes": [],
     "default_upstream": "web"
   }
   ```

5. Import the rule set and choose a generation (steps 2 to 4 of "First Start" in the [build and deployment guide](../build/binary-deployment.md)). `managed activate` in step 7 checks that each engine that the upstreams of the version use has a chosen generation, so do this step before step 7. `rules import` and `rules activate` read only the configuration file, not the managed store, so they succeed even before `current` exists (you may also run them after step 6). `rules deactivate` also reads the selected version of the managed store (see "Chosen Generation per Engine" above).
6. Import the version.

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy managed import /etc/tukuyomi-core/config.json /etc/tukuyomi-core/managed-import.json
   ```

   - A `<version> created` line is written. The command only places the version and does not select it (`current` does not exist yet).
   - After this, the input files of the site (`www.pem` and `www.key`) are no longer used, so you can delete them.
7. Select the version.

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy managed activate /etc/tukuyomi-core/config.json <version>
   ```

   - The command runs the same checks as start (the configuration file and the version, name resolution of the upstreams and their CA files, the certificates) and selects the version only if the checks pass. A `<version> current` line is written.
8. Check the configuration.

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
   ```

   - If it passes, `accepted` is written to standard output. A `config check: managed version <version>` line is written to standard error.
9. Start the service (see "systemd" in the [build and deployment guide](../build/binary-deployment.md)). A line `start: managed version <version>` appears in the log.
10. Start the admin process and create the first user (step 7 of "First Start" in the [build and deployment guide](../build/binary-deployment.md)). Open the admin screens at the host name in `admin.route.host`, from a network that `admin.route.access` allows. After this, make changes in the admin screens or the admin API (see "Applying" below).

### Moving to the Managed Configuration

These steps move a proxy and an admin process from a configuration file without `managed` to the managed configuration. After the move, the routes and so on in the configuration file go into a version, and the route for the host of the admin screens goes into `admin.route`. There is no conversion command, so write the configuration file and the version document by hand.

If you use the records shipper, first replace it with an executable of the same build as the proxy (see "Whether to Use the Managed Configuration" above).

The settings move as follows.

| Current configuration file | After the move |
|---|---|
| The certificate for the host of the admin screens, among the `certificates` of a TLS listener | `admin.route.certificate` (`cert_file`, `key_file`, and `acme` as they are) |
| Other certificates | Sites of the version. A certificate in a file goes into `chain_file` and `key_file` of the document, and an ACME certificate into `{"acme": {..}}` (do not write paths) |
| The upstream that points to `admin.listen`, among `forward.upstreams` | Remove it (an upstream server in a version cannot use the address of `admin.listen`) |
| Other upstreams | `upstreams` of the version |
| The route for the host of the admin screens, among `forward.routes` | Remove it and copy its `access` to `admin.route.access` (`allow_cidrs` is required) |
| Other routes and `default_upstream` | `routes` and `default_upstream` of the version |
| Global `access` and `rate_limit`, and `host_policies` | The same setting keys of the version |
| `forward.resolve_timeout_ms`, `acme`, and the other setting keys of `admin` (including `origin`) | Leave them as they are in the configuration file |

- Set `admin.route.host` to the current host of the admin screens (the host of `admin.origin`).
- The global settings do not apply to the admin route, so if you forget to copy the `access` of the current route, who can reach the admin screens changes.

Steps:

1. Create the managed store directory (step 1 of "First Start with the Managed Configuration" above).
2. Write the new configuration file under another name (for example, `/etc/tukuyomi-core/config.managed.json`), and also write the version document (for example, `/etc/tukuyomi-core/managed-import.json`).
3. With the new configuration file, import the version and select it.

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy managed import /etc/tukuyomi-core/config.managed.json /etc/tukuyomi-core/managed-import.json
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy managed activate /etc/tukuyomi-core/config.managed.json <version>
   ```

   - The certificate of the ACME site is not yet in the managed store, so `managed activate` writes a `managed activate: tls certificate not issued yet (site <name>)` line, but it does not refuse.
4. For each ACME site, copy the current certificate chain and private key to `acme/<hosts-sha256>/` (for how to compute `<hosts-sha256>`, see "ACME Sites" below). If you do not copy them, TLS connections to the hosts of that site fail until you run `acme renew` and send SIGUSR2.

   ```bash
   sudo -u tukuyomi mkdir -m 0700 /var/lib/tukuyomi-core/managed/acme
   d=/var/lib/tukuyomi-core/managed/acme/$(printf '%s\n' www.example.com | LC_ALL=C sort | sha256sum | cut -d' ' -f1)
   sudo -u tukuyomi mkdir -m 0700 "$d"
   sudo -u tukuyomi install -m 0600 /var/lib/tukuyomi-core/tls/www.pem "$d/chain"
   sudo -u tukuyomi install -m 0600 /var/lib/tukuyomi-core/tls/www.key "$d/key"
   ```

5. Run `config check` with the new configuration file and check that `accepted` is written and that there is no `not issued yet` line. When you run `acme renew`, a copied certificate shows as `site <name> valid` if it expires in `renew_before_days` days or more. Otherwise, the certificate is issued again and shows as `site <name> renewed`.
6. Keep the configuration from before the move (the original configuration file under a name such as `config.json.before-managed`, and the original executables and units).
7. Put the new configuration file at the original path (for example, `/etc/tukuyomi-core/config.json`). Copy it into the same directory, and then rename it over the original.
8. Restart the admin process, the proxy, and the records shipper, in this order (`systemctl restart`).
   - This procedure adds `admin.route`, so setting keys that cannot change while running (`admin.route.host` and `managed`) differ, and `systemctl reload` refuses (`reload: configuration refused: admin.route.host cannot change while running`; `admin.route.host` is compared first).
   - Between restarting the admin process and restarting the proxy, you can reach the admin screens through the original route, and requests to change the managed configuration are refused with 409 (nothing is changed).
   - While the proxy restarts, connections are cut.
9. Check.
   - A line `start: managed version <version>` appears in the proxy's log, and a line `records-ship: configuration accepted` in the records shipper's log.
   - Every host returns the same certificate as before, and the routes and `access` work as before.
   - You can enter the admin screens through the admin route.

To go back to the configuration from before the move, use what you kept in step 6 above. A site certificate that `acme renew` renewed after the move exists only in the managed store; the file that the original configuration file points to still holds the old certificate.

### Applying

There are two ways to make the running proxy use another version.

1. Applying from the admin screens and the admin API (save and apply, applying by name, rollback): The admin process sends a `reload` request on the control socket (see "Control Socket" above), and the proxy reloads its configuration with that version. The admin process sets `current` to that version only after the proxy's configuration has switched, so a version that the proxy refused does not become `current`. For the operations and responses, see "Managed Configuration Operations" in the [admin reference](admin-reference.md).
   - While applying, the admin process holds the managed store lock, so `managed import`, `managed activate`, and `managed remove` are refused (`the managed store is in use by another command`).
   - The proxy responds when the reload ends, waiting up to the `forward.resolve_timeout_ms` of the running configuration plus 5 seconds. A longer `resolve_timeout_ms` makes applying take longer, and commands are also refused for that time.
   - For how long the admin process waits for the response, and how it handles a refusal in the certificate check (`tls`; for example, when the check overlaps with `acme renew` replacing a certificate), see "Control Socket" in the [admin reference](admin-reference.md).
2. Commands and SIGHUP: `managed activate` runs the same checks as start and changes `current`. The command does not send a request to the proxy, so the running proxy reads the `current` version at the next SIGHUP (`systemctl reload`) or start (see "SIGHUP (Configuration Reload)" above).
   - If SIGHUP is refused (for example, because a setting key that cannot change while running differs, an upstream uses an engine that is not running, or a new listener cannot be bound), `current` stays at the version that the running proxy refused, and that version is used at the next start.
   - To change the version of the running proxy, use the admin screens or the admin API. When you change it with a command, run `systemctl reload` immediately and check the line `reload: configuration replaced <sha256> managed <version>`.

Both ways work as follows.

- A reload also reads the configuration file together with the version. If you have rewritten the configuration file and have not yet sent SIGHUP, applying from the admin screens also puts that rewrite into effect. If the configuration file has an error, applying is also refused (`configuration`).
- The proxy reloads even for the same version. As with SIGHUP, it closes idle keep-alive connections, sends `GOAWAY` to HTTP/2 connections, and resets which upstream servers are marked as failed, along with the failure counts of the upstreams (see "SIGHUP (Configuration Reload)" above).
- The log shows `reload: control reload <version>` (when the reload was started by a request on the control socket), the same `reload:` lines as for SIGHUP, and `control: reload <version>: <result> (<reason>)` (see "Other Log Lines" below).

If applying stops halfway:

| State | When it happens | SIGHUP and restart | How to fix |
|---|---|---|---|
| An unused version remains | The admin process stopped after saving in the admin screens and before requesting the reload | Stays at `current` (the previous version) | It does no harm. Remove it if you do not need it (see "Removing Versions" below) |
| Nothing is changed | The proxy stopped during the reload, or the reload was refused | Stays at `current` (the previous version) | If the proxy stopped, restart it and apply again |
| The proxy is on the new version and `current` is the previous version | The admin process stopped after the proxy's configuration switched and before `current` was changed, `current` could not be written, or the proxy's configuration switched later, for an apply whose result was not known | It goes back to the previous version | Apply the same version again (applying the previous version also makes the two match) |
| The proxy is on the previous version and `current` is the new version | A SIGHUP arrived after the proxy's configuration switched and before `current` changed, or the proxy stopped and restarted with the previous version | It switches to the new version | Apply again |

- `managed` in the control socket's `status` shows the running version, and `current` in `managed list` shows the selected version. For how they appear in the admin screens and the admin API, see "Managed Configuration Operations" in the [admin reference](admin-reference.md).
- The proxy and the admin process do not resolve this mismatch automatically, because which version is correct depends on why it stopped.

### Placement Notes

- Use `acme.challenge_dir` only for challenges, and do not put other files in it. Do not put the records shipper's connection string file, the country database, upstream CA files, or the inspector process executables there either.
- Do not use symbolic links for `acme.challenge_dir` and the managed store. The check for overlapping directories compares the paths as written.
- Do not put `acme.account_key_file` and the certificate and private key files used by the admin route inside the rules store, `records.dir`, the admin store directory, or the managed store. `acme renew` rewrites these files.

### ACME Sites

If you set the `certificate` of a site in a version to `{"acme": {"renew_before_days": 30}}` (1 to 60), `acme renew` issues and renews that site's certificate. Write it in the same form in the `managed import` document as well (do not write paths).

- The `hosts` of an ACME site are names only; `*.` cannot be written. The configuration file needs `acme`.
- A configuration file with `managed` can have `acme` even if no certificate in the configuration file has `acme` (because ACME sites are in the version).
- The certificate chain and the private key are in `acme/<hosts-sha256>/chain` and `key` in the managed store. `<hosts-sha256>` is the SHA-256 of the site's `hosts`, sorted in byte order and joined, each followed by a newline. The site name is not included, so the same set of hosts uses the same directory even if the name changes, and in other versions too.

  ```bash
  printf '%s\n' www.example.com app.example.com | LC_ALL=C sort | sha256sum | cut -d' ' -f1
  ```

- `acme/` and the directories in it are created by `acme renew` if they do not exist (0700). If something other than a directory, such as a symbolic link, is in its place, that site becomes `failed` without an order being placed with the CA.
- `acme renew` reads the `current` version. It handles the admin route first, if the route has `acme`, and then the sites of the version. The result lines are `admin route renewed|valid|failed` and `site <name> renewed|valid|failed`.
  - If there is neither an admin route that has `acme` nor an ACME site, it writes no result line, writes one line to standard error, and ends with exit 0 (so that the timer does not fail).
  - If `current` or the version cannot be read, it rejects the configuration and ends with exit 2. It does not renew the certificate of the admin route in the configuration file either.
- While the files of a site do not exist yet, its certificate counts as not issued. Start, a configuration reload, `config check`, and `managed activate` do not refuse; they write a `tls certificate not issued yet (site <name>)` line and refuse handshakes for the hosts of that site. The certificate is used from the first SIGUSR2 after the files exist.
- When you apply a version that changes the hosts of an ACME site (a host was added to a site or changed, or `{"chain", "key"}` was changed to `acme`), the new directory has no certificate yet, so TLS connections to all the hosts of that site fail (including hosts that could connect before). Run `acme renew` and send SIGUSR2 right after applying (start the service from "Certificate Renewal Timer" in the [build and deployment guide](../build/binary-deployment.md) with `systemctl start tukuyomi-core-acme.service`). If you leave it to the timer, connections fail until the next timer run.
- When you go back to an earlier version (rollback, applying by name), if the old certificate is still in the directory for that set of hosts, it is used without being issued again. The proxy does not check certificate expiry, so it uses an expired certificate too. Run `acme renew` after going back (it issues the certificate again if it is close to expiry).
- The proxy responds to challenges for the host of the admin route, if it has `acme`, and for the hosts of the ACME sites in the running version. These hosts change together with the version when applying switches it. `admin.route.access` does not apply to challenges (because the CA can connect from any address).
  - If you run `acme renew` after selecting a version with the `managed activate` command but before SIGHUP, the hosts that are only in the new version become `failed`, because the proxy does not respond to challenges for them. After `managed activate`, reload the configuration immediately (see "Applying" above).
- When you put `acme` on the certificate of the admin route, write the file locations in `cert_file` and `key_file` in the configuration file (the files need not exist at start). While the files do not exist, handshakes for the admin route are refused. Issue the first certificate as in "First Issue" under "ACME" below.
- When you remove a version, the `acme/` directories for sets of hosts that no remaining version has as a site are also removed (see "Removing Versions" below).

### Removing Versions

Remove a version with `managed remove` (see "`managed`" above) or the admin API (see "Managed Configuration Operations" in the [admin reference](admin-reference.md)).

- The selected version (`current`) and versions in use cannot be removed (`the managed version is the current one`, `the managed version is in use`). A version is in use while the proxy is running it, while a configuration reload is reading it, from when `acme renew` reads it until the command ends, and while `config check` or `managed activate` is reading it. If removal is refused because `acme renew` or a similar command is reading the version, run it again after that command ends. The admin API also does not remove the version that is the rollback target.
- Files that no version points to any more are cleaned up at the same time. The certificate chains, private keys, and CA files in `files/`, and the directories in `acme/` (the certificates and private keys of ACME sites), are also removed. If you later use an ACME site with the same set of hosts, the certificate is issued again (the CA counts this as another issuance).
- When you replace the build of the proxy, restart the proxy with the new build first, and then remove versions.
- Put the managed store on a file system that supports `flock` locks. Removal and reading by the proxy are protected by a lock on the version file, and if the lock cannot be taken, import, removal, and start are refused.

## Request Handling

### Header Checks

Before HTTP parsing, the header section of a request is checked in the following order, and the first rule that is broken decides the response. A header section with more than 64 header fields, however, gets 431 before checks 1 and 2.

1. Line endings are CRLF only. The header section does not start with an empty line.
2. The method is a token of 1 to 32 bytes and is not `CONNECT`. The request target starts with `/`, is 1 to 4096 bytes long, and has no `#`. The path has none of `<`, `>`, and `` ` ``, and the query has none of `"`, `<`, and `>`. The version is `HTTP/1.1` or `HTTP/1.0`. If the request target is too long, the response is 414.
3. There are at most 64 header fields. A name is 1 to 256 bytes, a value is at most 4096 bytes, and the names and values of all the fields together are at most 24 KiB. A value has no control characters other than HTAB. If a limit is exceeded, the response is 431.
4. There is exactly one non-empty `Host`.
5. `Transfer-Encoding` and `Content-Length` are not both present. `Transfer-Encoding` is exactly one line with `chunked`, and an `HTTP/1.0` request does not have it. `Content-Length` is one line of digits and does not exceed the body limit (if it does, the response is 413).
6. `Expect` is absent or is exactly one line with `100-continue`. Otherwise the response is 417.
7. `Connection` is a list of tokens and does not name `host`, `content-length`, `content-type`, or `content-encoding`.
8. `Content-Encoding` is absent or is exactly one line with `gzip`. Otherwise the response is 415. A request with a `Content-Length` greater than 0 does not have two or more `Content-Type` headers. Otherwise the response is 415.

Other violations get 400. A response that refuses a request has no body.

- For the first request of an HTTP/1.1 connection, the proxy returns the response and closes the connection.
- When the proxy refuses the header section of the second or a later request, it returns no response. It closes the connection after it has finished sending the previous response, and logs a connection log with `class` `closed` and `status` 0.
- The header fields of an HTTP/2 stream are also converted into an HTTP/1.1 header section and then checked with the same rules. When the proxy refuses one, it returns a response only for that stream, and the connection continues.

- A header whose name contains `_` is neither inspected nor forwarded. Many upstream servers read `X_Forwarded_For` and `X-Forwarded-For` as the same variable, so this keeps a client from using such a name to pose as the address that the proxy adds.
- `Expect: 100-continue` is accepted, but it is left out of what is inspected and of the request sent to the upstream. The proxy returns 100 when it starts reading the body.
- Request trailers are rejected (400).
- On an HTTP/1.1 connection, the following requests are the last request of the connection.
  - A chunked request, and a request with `Upgrade`
  - An HTTP/1.0 request (the response is also returned as HTTP/1.0)
  - A request with `Connection: close`
  - A request whose response was sent before its body was read to the end (for example, a request with a body that was refused with 403, 404, 415, 421, or 429)
- Up to 2 empty lines between requests (after the previous request and before the next header section) are discarded.

### Body Types

The body type is checked after the header section checks, once the route has been chosen (check 10 in "Order of Request Checks" below). The rules differ depending on whether the route is inspected.

- On an inspected route, a non-empty body has exactly one `Content-Type`, which is one of the following (the part before `;` is compared ignoring case). Otherwise the response is 415.
  - `application/x-www-form-urlencoded`
  - `multipart/form-data`
  - `application/json`
  - `application/<name>+json` (the name is 1 to 122 bytes of letters and digits, `.`, and `-`)
- On a bypass route, the type is not checked. A body without `Content-Type` and a body of another type are streamed as they are. However, a non-empty body with two or more `Content-Type` headers gets 415 on any route, because different readers interpret different lines as the type.
- A body with `Content-Length` is checked before the body is read. For a chunked body, whether it is empty is not known until it is read, so it is checked after it is read (for a body longer than the inspected length, after its first part of that length is read). An empty body can have any type.

### Headers Removed Before Forwarding

The proxy removes the per-connection headers (`Connection` and the headers it names, `Keep-Alive`, `TE`, `Transfer-Encoding`, `Upgrade`, `Expect`, and so on) and `Proxy-Authorization`. It adds the headers in "Client Address" above after this removal, so a client cannot make the proxy remove them by naming them. It does not send the trailers of an upstream response to the client.

### Responses

| Status code | Case |
|---|---|
| The status code of the rule | A rule blocked the request (500 if the code is outside 200 to 599) |
| 400, 408, 413, 414, 415, 417, 431 | The header section or the body was refused |
| 403 | Refused by the global `access`, the `access` of a host policy, the `access` of a route, or the `admin.route.access` of the admin route (`denied by route access`) |
| 404 | No route matches and there is no default upstream; a `Host` that is not redirected; or the host of the admin route received on a plain listener that is not a redirect listener (`admin host over plain http`) |
| 421 | The `Host` is not in the TLS certificate; or the host of the admin route was received on a connection that does not use its certificate (`admin host on another certificate`) |
| 429 | Refused by the global `rate_limit` or the `rate_limit` of a host policy. The response has `Retry-After` |
| 502 | The proxy cannot connect to the upstream, the upstream's response is invalid, the upstream timed out, or no server of the upstream is usable |
| 503 | The request cannot be inspected (the inspector process is unavailable, or the wait for an inspection slot is full or timed out), the budget ran out, the request timed out, or the proxy itself cannot make a connection to the upstream |
| 500 | An inconsistency occurred inside the proxy (a line `internal fault` also appears in the log) |

A response that the proxy creates itself has an empty body and `Content-Length: 0` (204 and 304 have no `Content-Length`, and 429 also has `Retry-After`). The 200 for an ACME challenge has that file as its body.

Every response that the proxy returns (including upstream responses, blocks, refusals of the header section, and redirects) has exactly one `X-Request-ID` header that carries the request ID. If the upstream response has a header with the same name, the proxy replaces it. The request ID is the same as the `id` in the log of that request, so if someone whose request was refused tells you the ID, you can find the request in the log.

## Access Control and Rate Limits

The top-level `access`, `rate_limit`, `host_policies`, and `geo` of the configuration file define the policies that refuse requests before a route is looked up. `access` and `rate_limit` are the global settings (the global access control and the global rate limit), and `host_policies` holds the host policies, which apply to each host instead of the global settings. All of them are optional, and a policy that is omitted is not applied. In a configuration with `managed`, `access`, `rate_limit`, and `host_policies` are written in the version, not in the configuration file (see "Managed Store and Versions" above). The values are read at start and at a configuration reload (see "SIGHUP (Configuration Reload)" above). No policy applies to the admin route (`admin.route`).

### Order of Request Checks

A request is checked in the following order. The first check that refuses it decides the response.

| Order | Check | Response | `reason` in the log |
|---|---|---|---|
| 1 | Header section checks (see "Header Checks" above) | 400, 414, 431, and so on | A fixed phrase for each kind of header section violation |
| 2 | ACME challenge (on a normal listener and a redirect listener, when there is a certificate that has `acme`) | 200 with the challenge file as the body, or 404 | `acme challenge` |
| 3 | Admin route (in a configuration with `managed`, when `Host` is `admin.route.host`). Whether a TLS connection used the certificate of the admin route in the handshake, whether the connection is not plain, and whether `admin.route.access` allows it | 421, 404, 403 | `admin host on another certificate`, `admin host over plain http`, `denied by route access` |
| 4 | The access control that applies to the request (the `access` of the host policy whose hosts match the `Host`, or the global `access` if there is none) | 403 | `denied by access` |
| 5 | The rate limit that applies to the request (likewise, the `rate_limit` of the host policy or the global one) | 429 (`Retry-After: 1`) | `too many requests` |
| 6 | Whether the `Host` of a TLS connection is among the hosts of the certificate used in the handshake | 421 | `host not covered by the certificate` |
| 7 | Route (the default upstream if there is none) | 404 | `no route matches` |
| 8 | The `access` of the route | 403 | `denied by route access` |
| 9 | `Content-Length` and the `max_body` of the route | 413 | `body over the limit of the route` |
| 10 | Body type (see "Body Types" above) | 415 | `body type not supported` |

Check 10 is done before the body is read for a body with `Content-Length`, and after the body is read for a chunked body. After that, the proxy inspects and forwards the request. The redirect listener responds with a redirect or 404 after check 5 and does not read the body.

- A request that check 3 applies to skips checks 4 to 9 and is forwarded to the admin process (it is still inspected by the WAF, and the body limit is `proxy.max_body`). The 421 in check 3 happens when an HTTP/2 client sends a request for the host of the admin screens on a connection made for another site's certificate (such as `*.example.com`). The client reconnects with the correct SNI. The redirect listener redirects the host of the admin route to https without applying policies.
- The settings that apply in checks 4 and 5 are decided by the `Host` of the request (see "Host Policies (`host_policies`)" below).
- Checks 4 and 5 work the same way for requests that match a bypass route and on the redirect listener, and they refuse with the same response even when the inspector process is stopped. They do not apply to the monitoring listener.
- Requests are refused after their header section has been read. Connections from clients that will be refused are still accepted and go through the TLS handshake, and in the meantime they use a `max_conns` slot.
- A request refused in check 1 and a challenge responded to in check 2 are not counted by either the access control or the rate limit.
- A request refused in checks 3 to 9 gets its response before the body is read. On an HTTP/1.1 connection, when a request with a body is refused, the connection is closed after the response. If the request has no body, the connection continues. In HTTP/2, only that stream ends.
- A refused request appears in the log (`class` is `rejected`). A request refused in check 4 or 5 is counted in `tukuyomi_policy_refusals_total` of `/metrics`, whether by the global settings or by a host policy.

### Client and Country

- The global `access` and `rate_limit`, the host policies, the `access` of a route, and `admin.route.access` all look at the address decided in "Client Address" above. The country is also determined from that address.
- Even a peer that is in `trusted_proxies` is the client if it does not add an `X-Forwarded-For` line. The same applies to a peer that is not in `trusted_proxies`. If an intermediary in front of the proxy does not pass on the client address, the clients behind it cannot be told apart, the country is taken from the intermediary's address, and the rate limit counts them as one client.

### `access`

```text
{"deny_cidrs"?, "allow_cidrs"?, "deny_countries"?, "allow_countries"?}
```

This is the global access control. It has the same form as the `access` of a route and refuses requests by the same rules. The global `access` applies to requests that passed the header section checks (except ACME challenges and the admin route). However, if a host policy has its own `access`, that `access` applies to requests to the hosts of that policy instead of the global `access` (see "Host Policies (`host_policies`)" below).

| Setting key | Content |
|---|---|
| `deny_cidrs`, `allow_cidrs` | A list of networks. Up to 256. Written in the same way as `trusted_proxies` |
| `deny_countries`, `allow_countries` | A country list. Up to 256. A country is an ISO 3166-1 alpha-2 code in two uppercase letters (such as `JP`), or `UNKNOWN`. Lowercase letters and anything that is not two letters are rejected. The proxy does not check whether the two letters are in the ISO 3166 list |

- All four are optional. An omitted setting key means an empty list, and if all four are empty, nobody is refused.
- The following clients are refused.
  - Those in `deny_cidrs`
  - Those whose country is in `deny_countries`
  - If `allow_cidrs` is not empty, those that are not in it
  - If `allow_countries` is not empty, those whose country is not in it
- If you write both `allow_cidrs` and `allow_countries`, only the clients that are in both pass. There is no way to let a network through regardless of its country.
- A refused request gets 403 with an empty body and no `Retry-After`.
- A country list requires `geo`.

Example:

```json
"access": {
  "deny_cidrs": ["198.51.100.0/24"],
  "allow_countries": ["JP", "UNKNOWN"]
}
```

This example refuses clients in `198.51.100.0/24` and clients from countries other than `JP` and `UNKNOWN`.

### Rate Limits (`rate_limit`)

```text
{"rate", "burst", "keys", "exempt_cidrs"?}
```

This is the global rate limit. If a host policy has its own `rate_limit`, requests to the hosts of that policy are counted in that host policy's table instead of the global table (see "Host Policies (`host_policies`)" below).

| Setting key | Range | Meaning |
|---|---|---|
| `rate` | 1 to 100000 | The number of requests per second that one client may keep making |
| `burst` | 0 to 100000 | The burst allowance: the number of requests let through back to back after an idle period. Up to `burst + 1` requests in a row pass, and refusal starts from the next one |
| `keys` | 1024 to 1048576 | The maximum number of clients tracked (see "Table size" below) |
| `exempt_cidrs` | 0 to 256 networks | Clients that are not counted (excluded networks). Written in the same way as `trusted_proxies`. Empty if omitted |

- How counting works:
  - Requests are counted one by one (not connections; in HTTP/2, per stream).
  - A client that has been idle passes up to `burst + 1` requests without a gap. The next one is refused. After that, one more request passes for every 1/`rate` seconds of waiting.
  - 1/`rate` seconds is rounded up to nanoseconds, so a client never exceeds `rate`.
  - A refused request does not change the count of that client.
  - The first request from a new client always passes.
- The unit of a client:
  - For IPv4, each address. For IPv6, each /64 (the upper 64 bits). Changing the address within the same /64 does not increase the count.
  - An IPv4-mapped IPv6 address (`::ffff:192.0.2.1`) is counted as IPv4. The port is not looked at.
  - If a trusted peer does not add `X-Forwarded-For`, that peer becomes the client (see "Client and Country" above). In that case, `rate` and `burst` apply to all the clients behind that peer together.
- A refused request gets 429 with an empty body and `Retry-After`. The value is the time until the next request can pass, rounded up to whole seconds, with a minimum of 1. Because `rate` is at least 1, that time never exceeds 1 second, so the value is always `1`.
- Clients in `exempt_cidrs` are not counted, but the access control still applies to them first and can refuse them. Put monitoring programs there, for example.
- Table size:
  - `keys` is the maximum number of clients counted at the same time. One client takes about 100 bytes, so a `keys` of 1048576 takes about 100 MB.
  - The total of the global `keys` and the `keys` of the host policies that have their own table is at most 1048576. If it exceeds that, the configuration is rejected (`the rate limits keep count of more than 1048576 clients in all`).
  - On every request, the proxy examines up to 4 clients from the older end of the table and removes those that have no count left (those whose waiting time has passed). A client with no count left is treated in the same way as a new client, so removing it does not change the result.
  - When the table is full and the oldest client still has a count left, that client is removed to make room for a new client. A removed client starts as a new client the next time it comes and again passes up to `burst + 1` requests. In effect, the limit for that client is loosened once. A new client is never refused for lack of room.
  - The number of removed clients appears in `tukuyomi_rate_limit_evicted_total`, and the number of clients being counted appears in `tukuyomi_rate_limit_keys` (both are totals over all tables). If requests come from many addresses, real clients are removed from the table and the limit is loosened. Set `keys` well above the number of clients that come at the same time.
  - The tables are kept in the proxy's memory and start empty after a restart. At a configuration reload, the proxy decides for each table whether to carry it over. The global table continues if both the old and the new configuration have the global `rate_limit` and `keys`, `rate`, and `burst` are all the same (`exempt_cidrs` uses the new value). If any of them differs, or one of the two has no global `rate_limit`, counting starts from 0 in a new table, and the proxy writes a `reload: rate limit table started anew` line. For the tables of host policies, see "Host Policies (`host_policies`)" below.
- A refused request is counted under `rate_limit` in `tukuyomi_policy_refusals_total`. The `reason` in the log is `too many requests`.

### Host Policies (`host_policies`)

```text
[{"name", "hosts", "access"?, "rate_limit"?}, ..]
```

These are per-host settings that apply instead of the global access control and rate limit. They are optional. In a configuration file without `managed`, write them at the top level. In a configuration with `managed`, write them in the version (they are rejected if written in the configuration file).

| Setting key | Range | Meaning |
|---|---|---|
| `name` | 1 to 64 characters of letters and digits, `-`, and `_` | The name. Two entries cannot have the same name. It is used to carry over rate limit tables (below) |
| `hosts` | 1 to 64 entries | The hosts that the entry applies to. The same form as the `host` of a route, without a port (a lowercase name, or `*.` and a name) |
| `access` | The same form as the global `access` | The access control for these hosts |
| `rate_limit` | `{}`, or the same form as the global `rate_limit` with all of `rate`, `burst`, and `keys` written | The rate limit for these hosts |

- There are at most 64 entries, and at most 1024 hosts in all entries together. The same host cannot be written twice (not even in different entries). The host of the admin route (`admin.route.host`) cannot be written (a `*.` host may contain it; the admin route matches first).
- An entry with neither `access` nor `rate_limit` is rejected.
- How matching works: the proxy chooses an entry by the `Host` of the request, in the same way as for routes. Case is ignored, one trailing `.` is dropped, and the port is ignored. A named host matches before a `*.` host, and a longer `*.` host before a shorter one. The global settings apply to a request that matches no entry.
- How they combine: access control and rate limiting each take one of the following three forms (the table also shows the wording of the admin screens).

| How to write | Admin screen wording | Access control | Rate limit |
|---|---|---|---|
| Do not write the setting key | Inherit | The global `access` applies | Counted in the global table. Requests from the same client are counted together with those to other hosts |
| Write a value | Settings for this host | This `access` applies instead of the global one | Counted in the table of this host policy instead of the global one |
| `{}` | Not used | Nobody is refused | Not counted |

- With "Settings for this host" and "Not used", refusals by the global settings (including a `deny_cidrs` added in a hurry) do not apply to that host. When you change the global settings, also review the host policies that do not inherit them.
- A host policy applies only to requests that arrive with that `Host`. Requests with another `Host` (a `Host` that is an IP address, or a name that is in no entry) that reach the same upstream through the default upstream, a route without `host`, or a `*.` route get only the global settings. If you write a route for each host and leave the default upstream empty, this cannot happen.
  - A `Host` that is an IPv6 address (such as `[2001:db8::1]`) matches no entry. Write an internationalized domain name in Punycode form (a name that starts with `xn--`).
- A request whose `Host` cannot be parsed (it passes the header section checks, but, for example, the port of `www.example.com:0443` starts with `0`) is treated as if it could be for any host. It is refused unless it passes both the global `access` and the `access` of every entry that has its own `access`. For the rate limit, it is counted in the global table and then in the tables of all the entries that have their own table, in order, and counting stops at the first table that refuses it.
- The redirect listener also chooses the applicable settings in the same way. Host policies do not apply to the admin route.
- A country list requires `geo`.
- Rate limit tables:
  - The total of the global `keys` and the `keys` of the entries that have their own table is at most 1048576 (see "Rate Limits (`rate_limit`)" above).
  - Each entry has its own table, so the total across hosts has no maximum. One client can pass up to the global `rate` plus the `rate` of each entry.
  - At a configuration reload, if an entry with the same `name` has its own table both before and after, and `keys`, `rate`, and `burst` are all the same, the table is carried over (also when only `hosts` is changed). Among the entries that have their own table, an entry that was renamed, switched from "Inherit" or "Not used" to "Settings for this host", or newly added starts counting from empty, and the proxy writes a `reload: rate limit table of host policy <name> started anew` line. If you swap the names of two entries, the tables move with the names.
  - `tukuyomi_rate_limit_keys` and `tukuyomi_rate_limit_evicted_total` in `/metrics` are totals over all tables. Hosts that inherit are counted in the global table, so they are not counted twice.
- Requests that a host policy refuses have the same `reason` in the log (`denied by access`, `too many requests`) and the same labels in `/metrics` as those refused by the global settings. You can tell which host they were for from the `host` in the log.
- An earlier build that does not know the setting key `host_policies` rejects a configuration file or a version that contains it, as having an unknown setting key. Be careful when you go back to an earlier build. The records shipper also reads the configuration file, so before you write `host_policies` in the configuration file, replace the records shipper with the same build as the proxy (see "Starting the Records Shipper" below).

Example:

```json
"host_policies": [
  {"name": "app", "hosts": ["app.example.com"], "access": {"allow_cidrs": ["203.0.113.0/24"]}},
  {"name": "api", "hosts": ["api.example.com", "*.api.example.com"], "rate_limit": {"rate": 20, "burst": 40, "keys": 65536}},
  {"name": "status", "hosts": ["status.example.com"], "access": {}, "rate_limit": {}}
]
```

In this example, only clients in `203.0.113.0/24` can use `app.example.com` (the global `access` does not apply), and its rate limit is counted in the global table. The global `access` applies to `api.example.com` and `*.api.example.com`, and their rate limit is counted in this entry's table. Neither access control nor a rate limit applies to `status.example.com`.

### Country Database (`geo`)

```text
{"country_db", "sha256"}
```

Write both. When you use a country list (`deny_countries` and `allow_countries`), the proxy uses this database to find the country of the client address.

| Setting key | Content |
|---|---|
| `country_db` | The absolute path of the country database file |
| `sha256` | The SHA-256 of that file. 64 lowercase hexadecimal digits |

Example (the `sha256` value is an example; write the value that `sha256sum` prints for your file):

```json
"geo": {
  "country_db": "/etc/tukuyomi-core/country.mmdb",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

- The file is in the MaxMind DB format (version 2). The proxy neither includes a database nor downloads one. The operator prepares and places it, and is responsible for following the license terms of the database's provider.
- How the country is determined:
  - The proxy uses `country.iso_code` of the address record, or `registered_country.iso_code` if that is missing. If neither exists, or if the code is not two uppercase letters, it is `UNKNOWN`.
  - Loopback, private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), link-local, and unspecified addresses become `UNKNOWN` without a database lookup. An address that the database does not know is also `UNKNOWN`.
  - An IPv4-mapped IPv6 address is looked up as IPv4.
  - With a database that has only IPv4 addresses (`ip_version` 4 in the metadata), all IPv6 clients become `UNKNOWN`.
- Watch out for `UNKNOWN`. If you do not write `UNKNOWN` in `allow_countries`, clients with private addresses (such as monitoring on the same network) and IPv6 clients with an IPv4-only database are all refused. If you write `UNKNOWN` in `deny_countries`, they are refused.
- Loading:
  - The commands that read the whole configuration read and check the `geo` file. They are the proxy start, `config check`, a reload by SIGHUP or by `reload` on the control socket, `acme renew`, `managed import`, and `managed activate`. For all of them, the OS user of the service must be able to read the file. The commands that read only the configuration file (the `rules` commands, `managed list` and `managed remove`, the `admin` commands and the admin process, and the records shipper) check only the form of the `geo` values and do not read the file.
  - The proxy checks the following.
    - It is a regular file, not a symbolic link, and at most 256 MiB. It is read in full.
    - The SHA-256 matches `sha256`.
    - It can be read as a MaxMind DB. The metadata version is 2, the record size is 24, 28, or 32 bits, `ip_version` is 4 or 6, and the search tree is not broken. All the records that the tree points to are checked, and the file is rejected if any of them cannot be read.
    - It is a country database. `database_type` contains `Country`, or at least one record has an ISO code.
  - If there is a country list, the proxy keeps the whole checked file in memory. The commands that read the file check all of it every time, so a large file costs time and memory.
  - If there is no country list anywhere (the global `access`, the `access` of `host_policies`, the `access` of a route), the file is read and checked and then discarded without being used. A configuration that has a country list but no `geo` is rejected (`access has a list of countries while geo is left out`).
  - The proxy reads the file at start and at every reload by SIGHUP or by `reload` on the control socket. It does not read it again in between. The whole file is checked at every reload, so a large file costs time and memory at every reload.
- Replacing the database: place the new file under another name, change both `country_db` and `sha256` in one write of the configuration file, check with `config check`, and then reload the proxy (SIGHUP, `systemctl reload`). The admin process does not read the database. If you overwrite the file under the same name, `sha256` no longer matches, and until you fix it, the commands that read the whole configuration and a proxy that restarts reject the configuration, and a reload of the proxy is also refused.

## Logs

Logs are written to standard error, one JSON object per line (to the journal under systemd). If the configuration has `records`, the same lines are also written to files (except some of the first lines at start; see "Log Files (`records`)" below). If `records.ship` is also present, another process (the records shipper) sends the lines in the files to PostgreSQL or MySQL (see "Records Shipper" below). For each route, you can choose whether to let requests through or refuse them when logs cannot be kept (see "How Logs Are Kept (`keep` and the `records` of a Route)" below). The short-lived commands (`config check`, `rules`, `managed`, `acme`, `admin bootstrap`, `admin reset`) still write plain text lines for people to read.

Every log line starts with the following two fields. A field without a value is left out (it is not written as `null`).

| Field | Content |
|---|---|
| `ts` | The time the line was recorded. UTC in RFC 3339 format with milliseconds (example: `2026-10-27T03:53:27.123Z`) |
| `type` | One of `request`, `connection`, `tunnel`, `line`, `audit`, and `dropped` |

### Request Log (`request`)

One line is written for each request whose response was written to the client. This includes header section refusals, redirects, and responses to ACME challenges. The line is written when the response has been sent (or cut off), so a streamed response is logged when it ends.

```text
{"ts":"2026-10-27T03:53:27.123Z","type":"request","id":"0186af5443bddbd9-1","conn":1,"listener":0,"proto":"h1","tls":false,"client":"192.0.2.10","method":"GET","host":"example.com","path":"/q","class":"blocked","status":403,"reason":"blocked by a rule","ms":3,"mode":"block","engine":"coraza","generation":"2f3bda9b9ca7db60","rule":949110,"rules":[941100,941110],"severity":2,"score":10,"sent":0}
```

| Field | Content |
|---|---|
| `id` | The request ID. The same as the `X-Request-ID` of the response and the `X-Request-ID` sent to the upstream. It is a 16-digit random number chosen at each start and a per-request serial number, joined with `-`. In HTTP/2, there is one for each stream |
| `conn` | The connection number |
| `listener` | The number of the listener that received the request (its position in `listeners` in the configuration, from 0) |
| `proto` | `h1` or `h2` |
| `tls` | Whether the listener is a TLS listener |
| `client` | The address decided in "Client Address" above. For a response given before the header section was read, the address of the connection's peer |
| `method`, `host`, `path` | The method of the request, `Host` (`:authority` in HTTP/2), and the request target before the `?` (as received). Not present for a request that did not pass the header section checks |
| `cut` | The names of the fields that were cut at their limit (example: `["path"]`) |
| `class` | See the table below |
| `status` | The status code of the response (0 if nothing was returned) |
| `reason` | A fixed English phrase (examples: `malformed request head`, `body over the limit`, `inspection queue full`, `upstream connection failed`, `denied by access`, `too many requests`) |
| `ms` | The time taken (milliseconds) |
| `upstream`, `server` | The upstream name and the address of the last server that the proxy tried to connect to (`server` is not present if it tried none) |
| `mode`, `engine`, `generation` | The mode of the rule generation that made the decision (`block` or `detect`), its engine (`coraza` or `modsecurity`), and the first 16 digits of the generation's fingerprint. Not present for a request that was not inspected (including a request that a bypass route let through) |
| `rule` | The ID of the rule that blocked the request, or that matched in detect-only mode |
| `rules` | The IDs of the other rules that matched. Up to 16, in the order of evaluation. Rules that are not logged (`nolog`) and the rules added by the inspector process (4000001 to 4000011) are not included |
| `rules_more` | `true` when more than 16 rules matched |
| `severity` | The highest severity among the matched rules (the value of a rule's `severity`; 0 is the most severe) |
| `score` | The CRS inbound anomaly score (`tx.blocking_inbound_anomaly_score`). Not present when it is 0 or when the rule set has no CRS |
| `body` | The length of the body. `Content-Length` if there is one, otherwise the number of bytes read so far (for a gzip body, the gzip length). Not present for a request without a body, for a request refused by a route, and for a request whose body could not be read to the end of its first part |
| `inspected` | When only the first part of the body was inspected and the rest was streamed, the number of bytes inspected. Not present for a body streamed on a bypass route |
| `sent` | The number of response body bytes sent to the client |

`class` is one of the following.

| `class` | Case |
|---|---|
| `forwarded` | The response of the upstream was returned |
| `blocked` | A rule blocked the request |
| `rejected` | The header section or the body was refused. This also includes the 403 and 429 of the global `access` and `rate_limit` and of the host policies, the 403, 404, and 421 that a route refused, the 421, 404, and 403 that the admin route refused, and the 404 of a redirect listener |
| `redirected` | The request was redirected to https |
| `answered` | The proxy responded to an ACME challenge |
| `failed` | The proxy could not respond for a reason on its own side (busy, unable to inspect, an upstream failure) |
| `closed` | Nothing was returned |

The `reason` of `forwarded` is one of the following.

- `forwarded`: allowed by the inspection
- `detected by a rule`: matched a rule in detect-only mode
- `bypassed by a route`: the request matched a bypass route
- `closed while the response was sent`: the connection was cut before the response was completely sent

In the fields that come from the request (`method`, `host`, `path`), bytes outside 0x21 to 0x7e, `"`, and `\` are turned into `%XX` (uppercase hexadecimal), and the fields are then cut at 32 bytes for `method`, 255 for `host`, and 1024 for `path`. They are not cut in the middle of a `%XX`. A `%` that was received is kept as it is, so a received `%80` and the byte 0x80 both become `%80`.

The query, the body, headers other than `Host` (`User-Agent`, `Cookie`, and so on), the values and variable names that matched a rule, and the `msg` of a rule are not recorded. On a site that puts a secret value in the path, that value ends up in the log.

### Other Log Lines

| `type` | Fields | Case |
|---|---|---|
| `connection` | `conn`, `listener`, `client`, `class`, `status`, `reason`, `ms`, `streams` | A connection that ended without a response being written (closed before a request, the header section of the second or a later request was refused, the TLS handshake failed, and so on), and the end of an HTTP/2 connection (`streams` is the number of streams received) |
| `tunnel` | `id` (the ID of the request that opened the tunnel), `conn`, `client`, `upstream`, `server`, `end`, `ms`, `to_upstream`, `from_upstream` | A WebSocket tunnel ended (this is also written if it ended before it started to work). `end` is one of `closed` (both directions ended), `idle`, `total`, `error`, and `stop` (cut off when the proxy stopped). The byte counts are the amounts read in each direction after the handshake |
| `line` | `line` | A message from the table below. Up to 512 bytes, and a longer message is cut. Control characters become spaces |
| `audit` | (see the [admin reference](admin-reference.md)) | The audit log of the admin process. Only the admin process writes it. It does not go into the proxy's log file |
| `dropped` | `count` | The number of logs that could not be written and were discarded (those discarded since the previous `dropped` log) |

The `line` messages are as follows.

| Message | Case |
|---|---|
| `start: ...` | The startup steps (`start: managed version <version>`; for each engine that starts, `start: rules generation <fingerprint>`, `start: rules engine <name>`, `start: rules mode block` (or `detect`), and `start: rules routes <count>` (the default engine first); for each upstream that points to an engine whose chosen generation is detect-only, `start: upstream <name>: engine <engine>, mode detect`; `start: rules store refused: <reason>`, `start: rules generation refused: <reason>`, `start: tls certificate not issued yet (<place>)`, `start: the kernel is ready`, `start: listening`, `start: record file refused: <reason>`, `start: control socket refused: <reason>`, and so on) |
| `reload: ...` | Receipt of SIGHUP, SIGUSR1, SIGUSR2, and a `reload` request on the control socket (`reload: SIGHUP`, `reload: control reload <version>`, and so on). The stages and the result of a configuration reload (`reload: configuration replaced <sha256>`, `reload: configuration replaced <sha256> managed <version>` in a configuration with `managed`, `reload: configuration refused: <reason>`, `reload: tls certificate not issued yet (<place>)`, `reload: rate limit table started anew`, `reload: rate limit table of host policy <name> started anew`, `reload: upstream <name>: engine <engine>, mode detect` for each upstream that points to an engine whose chosen generation is detect-only, and so on; see "SIGHUP (Configuration Reload)" above). A switch (SIGUSR1 and the control socket; for each engine, `reload: starting generation <fingerprint>`, `reload: rules engine <name>`, `reload: rules mode block` (or `detect`), and `reload: rules routes <count>` when it starts, `reload: generation <fingerprint> is ready, switched` when it is ready, `reload: generation <fingerprint> retired, engine <engine>, clean true` (or `false`) when the previous generation was stopped, `reload: generation <fingerprint> is already running` for a generation that is already running, `reload: generation <fingerprint> failed to start: <reason>` when it failed to start, `reload: a switch is in progress, ignored` when a switch is in progress, and `reload: rules store refused: <reason>` when it was refused), and the result of a certificate replacement |
| `control: switch ...`, `control: reload ...` | The responses to the switch and reload requests on the control socket (`control: reload <version>: <result> (<reason>)` and so on; see "Control Socket" above) |
| `driver: inspector incarnation changed, engine <engine>, inc <count>, restarts <count>` | The inspector process restarted |
| `driver: stop, engine <engine>, records <count>, held <count>, waiting <count>` | One line for each running engine, written when a stop begins (see "Stopping" above) |
| `conn <number>: internal fault: <reason>` | An inconsistency inside the proxy |
| `notify: <notice> not sent ...` | A notification to systemd could not be sent |
| `stop: ...` | The reason for the stop and the result of the last stop |

- `<sha256>` is the SHA-256 of the configuration file, `<version>` is a managed configuration version (both are 64 hexadecimal digits), and `<fingerprint>` is the fingerprint of a rule generation. `<place>` is `listener <number>, certificate <number>` in a configuration without `managed`, and `admin route` or `site <name>` in a configuration with `managed`.

### When Logs Cannot Be Written

- Logs are put in a queue of 1024 entries, and only one thread writes them. Request handling and stopping do not wait for writes.
- When the queue is full, the log is discarded and counted, and when writing becomes possible again, one `dropped` log is written. This happens when whatever reads standard error stops reading.
- A write failure (such as to `/dev/full`) loses that log and is counted separately.
- Both counts appear in `/metrics` (`tukuyomi_records_dropped_total`, `tukuyomi_record_write_errors_total`). While standard error is blocked, they cannot be reported in logs.
- One line is less than 4 KiB and is not cut (the field limits keep it under this size).
- When the log file (`records`) cannot be written, only that line is missing from the file; it still appears on standard error. The count appears in `tukuyomi_record_file_errors_total` (see "Log Files (`records`)" below).
- All of the above is the default handling (`best_effort`), which lets requests through even when logs cannot be kept. You can also set a route to refuse requests when logs cannot be kept (see "How Logs Are Kept (`keep` and the `records` of a Route)" below).

### Log Files (`records`)

When you write `records` in the configuration, the lines written to standard error are also written to files in a directory. If it is omitted, logs go only to standard error. The first lines at start, before the log files are opened (such as the `start: configuration accepted` and `start: rules …` lines), go only to standard error. The admin process searches the logs by reading these files.

```text
{"dir", "file_bytes", "files", "keep"?, "sync_ms"?, "ship"?}
```

`dir`, `file_bytes`, and `files` are required.

| Setting key | Range | Meaning |
|---|---|---|
| `dir` | An absolute path, up to 3840 bytes | The directory where the files are placed. The proxy does not create it, so create it first. It must be a directory, not a symbolic link, owned by the proxy's OS user, with no permissions for the group and other users |
| `file_bytes` | 1 MiB to 1 GiB | The size of one file. A line that would make the file in use exceed this is written to the next file |
| `files` | 2 to 64 | The number of files to keep (including the one in use). 3 or more when `ship` is present and `keep` or the `records` of a route has `required` |
| `keep` | `best_effort`, `required` | How logs are kept for the routes that have no `records` of their own and for the default upstream (see "How Logs Are Kept (`keep` and the `records` of a Route)" below). `best_effort` if omitted |
| `sync_ms` | 1 to 60000 | The longest time before written lines are synced to disk (`fsync`). If omitted, the proxy does not sync and leaves it to the OS (see "Lines that go into the file" below) |
| `ship` | `{"db_driver", "db_dsn_file", "batch", "interval_ms", "retention_days"}` | The records shipper settings (see "Records Shipper" below). The proxy does not run the records shipper; it only watches how far it is behind |

- The disk used is at most `file_bytes × files`. One line is less than 4 KiB, so one file never exceeds `file_bytes`.
- Names and rotation:
  - The file in use is `records.log`. Older files continue as `records.1.log`, `records.2.log`, and so on, and `records.<files - 1>.log` is the oldest file.
  - When adding a line would exceed `file_bytes`, the proxy first rotates to the next file. It renames `records.log` to `records.rotating`, renames `records.N.log` to `records.N+1.log` (N from `files - 2` down to 1), makes `records.rotating` into `records.1.log`, and opens a new `records.log`. The oldest file is replaced and disappears.
  - If a rename fails partway, `records.rotating` is restored. If the process stops during a rotation and `records.rotating` is left, it is replaced at the next rotation.
  - No file is cut in the middle of a line.
  - If you restart with a smaller `files`, the older files from `records.<files>.log` on are deleted at start and at every rotation (up to `records.63.log`), if they are regular files owned by the proxy's OS user.
- How files are opened:
  - `records.log` is created with 0600 if it does not exist, and opened for appending. A symbolic link, a FIFO, a directory, and a file owned by another OS user are rejected. A file with permissions for the group or other users is changed to 0600 before writing.
  - If the last line of a file does not end with a newline (for example, after a crash during a write), a newline is written first, so that the next line does not join the partial line.
  - If the file cannot be opened at start, the proxy writes a `start: record file refused: <reason>` line and stops without starting the inspector processes (exit 1).
- Lines that go into the file:
  - Each line is written in the same form as on standard error, with one `write` per line, after it is written to standard error.
  - Lines that appeared before the file was opened (the `start:` messages from the configuration check through the rule generations) are not included.
  - Without `sync_ms`, there is no sync to disk (`fsync`). If the power goes off, lines that the OS has not yet written to disk are lost.
  - With `sync_ms`, the file is synced once the oldest unsynced line has waited `sync_ms`, even if no later line comes. Before a rotation, the file to be renamed is also synced. If the power goes off, the lines after the last sync are lost. A sync failure is handled in the same way as a write failure (see "When the file cannot be written" below).
- When something else moves the file: the path of `records.log` is checked at most once per second (also before a rotation). If there is no file at the path, or if it is a different file from the one that is open, the open file is closed. That line does not go into the file and is counted in `tukuyomi_record_file_errors_total`. The next line creates and opens a new `records.log`.
- When the file cannot be written:
  - If a write, an `open`, or a rename fails, that line does not go into the file, the file is closed, and the failure is counted in `tukuyomi_record_file_errors_total`. The line still appears on standard error. Request handling does not wait.
  - Lines that arrive while the file is closed also do not go into the file and are counted in the same way. The first line that arrives at least 1 second after the failure reopens the file. Even if the disk stays broken, the proxy retries at most once per second.
  - A line that was partly written is cut back to the size before the write.
  - When a sync (`sync_ms`) fails, the file is also closed and the failure is counted in the same counter.
  - The directory is checked before it is reopened and before a rotation, in the same way as at start.
- If there is a records shipper (`ship`), it places `ship.state` (how far it has sent) in the same directory, and `ship.state.new` only while it rewrites it. The proxy only reads `ship.state` and deletes neither.

### How Logs Are Kept (`keep` and the `records` of a Route)

For each route, you can choose what to do when logs cannot be kept and which logs to write. If a route has no `records`, the global `records.keep` applies, and if there is no `records.keep`, the value is `best_effort`.

| Value | When logs cannot be kept | Logs written |
|---|---|---|
| `best_effort` | Discards the log and counts it, and lets the request through (see "When Logs Cannot Be Written" above) | All |
| `required` | Refuses new requests on that route with 503 | All |
| `security` | The same as `best_effort` | Only requests that a rule decided (blocks, and requests that matched in detect-only mode), requests that could not be inspected (including a 503 for a request that could not be passed to the inspector process), requests refused by the global `access` and `rate_limit` and by host policies, and requests cut after being accepted and before the response (below). Requests that were let through normally are not logged |

A route with `required` accepts a request only when all three of the following hold.

1. The last write to the log file (and the sync) succeeded, and the thread that writes logs is running.
2. If there is a records shipper (`ship`), the number of bytes that the records shipper has not sent yet is less than the size of `files − 2` files (`file_bytes × (files − 2)`). This refuses requests before unsent logs are lost to rotation. The proxy also refuses requests when it cannot tell how far the records shipper is behind (`ship.state` cannot be read, has the wrong format, was written more than 90 seconds ago, or points to a file that is none of the log files). When `files` is less than 3, it does not refuse because of the delay.
3. There is a free slot in the log queue. At most 512 of the queue's 1024 places serve as slots. If more than 512 requests on `required` routes are accepted at the same time, the requests beyond that get 503.

- A refused request gets 503 and is counted in `tukuyomi_records_refused_total`. The log of a refused request (`reason` is `records cannot be kept`) is written on a best-effort basis. When the request was refused because the records shipper is behind, however, that log is only counted, not written, so that logs of refused requests do not use up the margin left before unsent logs are lost to rotation.
- An accepted request takes a slot before its body is read and holds it until its log is put in the queue. The log of that request is not discarded even if the queue is full.
- If a write fails after a request has been accepted, the proxy counts the failure and refuses later `required` requests. It retries the write 1 second after the failure, and returns to accepting requests when the write succeeds.
- The proxy estimates how far the records shipper is behind. It reads `ship.state` once per second, and adds the bytes written since that read to the number of bytes after that position (the rest of the file it points to and the newer files). When the estimate falls below the threshold, the proxy returns to accepting requests.
- Logs are written after the response has been sent, so `required` does not guarantee that the log exists before the response reaches the client. The following two logs can be missing.
  - The log of a request that had already been accepted when writes started to fail
  - Logs after the last sync when the power goes off (without `sync_ms`, it is left to the OS)
- `required` needs `records`. When you use both `ship` and `required`, make `files` 3 or more (see "Relations Between Values" above).

The following requests are decided before the route is chosen, or responded to without reading the body. They are logged on a best-effort basis, regardless of the route's `records` and of `records.keep`. None of them sends anything to the upstream.

- The 403 and 429 of the global `access` and `rate_limit` and of the host policies
- The 421 for a request on a TLS connection whose certificate does not cover the `Host`
- The 404 for a request that matches no route when there is no default upstream
- Requests refused by the header section checks, redirects to https, and responses to ACME challenges
- The 403 of the `access` of a route and the 413 of the `max_body` of a route
- Connection logs (`connection`) and tunnel logs (`tunnel`)

A request that was cut after being accepted and before the response (on HTTP/1.1 the client closed the connection, on HTTP/2 the stream was reset) and a request whose client disconnected in the middle of the body are logged on every route, because they may have reached the upstream.

### Users Who Can Read the Logs

The logs contain the client address and the path. Users who can read the journal (root, and on Ubuntu the users in the groups `adm` and `systemd-journal`) can read them. Keep the OS users in these groups to a minimum. The journald settings decide the retention period and the size limit (see "systemd" in the [build and deployment guide](../build/binary-deployment.md)). The log file (`records`) is 0600 in a 0700 directory, so only the proxy's OS user and root can read it. The admin process reads this file as the same OS user and shows it to the users of the admin process (see the [admin reference](admin-reference.md)). When you use the records shipper, the same logs also go into a DB table. Keep the DB users who can read that table to a minimum as well.

## Records Shipper

The records shipper (`tukuyomi-records-ship`) is a separate process that reads the proxy's log files and inserts the lines in order into a PostgreSQL or MySQL table. The proxy does not run the records shipper and does not connect to the DB. The DB client library and the DB password exist only in the records shipper's executable and process. For the build and the unit, see the [build and deployment guide](../build/binary-deployment.md). It has been tested with PostgreSQL 16 and 18 and MySQL 8.0.

### Starting the Records Shipper

```text
tukuyomi-records-ship <config>
```

- `<config>` is the same configuration file as the proxy's, written as an absolute path. It is read with the same checks as the proxy, and `records.ship` is required. If it is missing, the records shipper writes a `records-ship: configuration refused: there is no records.ship object` line and exits.
- It reads only the configuration file, not the versions in the managed store or the country database. It rejects a configuration file with unknown setting keys, so before you write a new setting key (`managed`, `host_policies`, `kernel.default_engine`, the `engine` of an upstream, and so on) in the configuration, replace the records shipper with the same build as the proxy (see "Records Shipper Unit" in the [build and deployment guide](../build/binary-deployment.md)).
- Run it as the same OS user as the proxy. It does not run as root (it does not start if any of its four user IDs is 0). Because it writes `ship.state` in the log directory, it also checks that the directory belongs to this OS user, is not a symbolic link, and has no permissions for the group and other users.
- The file system of the log directory must return the creation time of files (the btime of `statx`). The records shipper identifies log files by their inode and creation time together (a file system reuses the inode number of a deleted file right away). With a file system that does not return it, the records shipper does not start, and the proxy treats the delay as "unknown" and refuses `required` requests.
- At start, it handles the configuration, the log directory, the connection string file (below), signal handling, and `READY=1` (if there is `NOTIFY_SOCKET`), in this order. It connects to the DB in its first round of work. If the DB cannot be reached, the records shipper waits and retries, just as when the DB stops while it is running.

| exit | Case |
|---|---|
| 0 | Stopped by SIGTERM, SIGINT, or SIGHUP. It finishes the round in progress, then stops, and sends `STOPPING=1` |
| 1 | The connection string cannot be read or was rejected. The DB refused the login (see "Records Shipper Errors" below). Any other failure |
| 2 | An argument error, or the configuration was rejected |

- A stop signal is handled only after the DB call in progress finishes. One call takes at most 30 seconds (the connection at most 10 seconds), and one round has several calls, so stopping can take up to 1 to 2 minutes. Even if it is stopped with SIGKILL, the next start continues from the position left in the DB, because the lines and the position go into the DB in the same transaction.

### `records.ship`

```text
{"db_driver", "db_dsn_file", "batch", "interval_ms", "retention_days"}
```

Write all five.

| Setting key | Range | Meaning |
|---|---|---|
| `db_driver` | `pgsql`, `mysql` | The kind of DB to send to |
| `db_dsn_file` | An absolute path, up to 3840 bytes | The connection string file (below). The proxy does not open this file |
| `batch` | 1 to 10000 | The maximum number of lines in one transaction |
| `interval_ms` | 100 to 60000 | The time to wait until the next round when there were no lines to send. It is also the initial wait after a failure |
| `retention_days` | 0 to 3650 | The number of days to keep lines in the DB. 0 means never delete |

```json
"records": {
  "dir": "/var/lib/tukuyomi-core/records",
  "file_bytes": 16777216,
  "files": 8,
  "sync_ms": 1000,
  "ship": {
    "db_driver": "pgsql",
    "db_dsn_file": "/etc/tukuyomi-core/records-db.dsn",
    "batch": 500,
    "interval_ms": 1000,
    "retention_days": 90
  }
}
```

### Connection String (`db_dsn_file`)

The connection string contains a password, so do not write it in the configuration file. Put it in a separate file.

- It must be a regular file, owned by the OS user of the records shipper, with no permissions for the group and other users (0600). It is at most 16 KiB of UTF-8 text. The rejection message contains neither the name nor the contents of the file.
- PostgreSQL: the form `host=db.example.com port=5432 user=tukuyomi_ship password=<password> dbname=records`, or a `postgresql://` URL (as accepted by `tokio-postgres`). The tables are created in the first schema in the connection's `search_path`.
  - For PostgreSQL on the same host, you can connect through a Unix domain socket with peer authentication (a role with the same name as the OS user), and no password is needed. Example: `host=/var/run/postgresql user=tukuyomi dbname=tukuyomi_records sslmode=disable`.
- MySQL: a URL of the form `mysql://<user>:<password>@<host>:<port>/<db-name>` (as accepted by `mysql_async` 0.37). The DB name is required, and the tables are created in that DB. Percent-encode values in the URL that contain symbols.

TLS works as follows.

| | PostgreSQL | MySQL |
|---|---|---|
| When not written | TLS. Verifies the certificate and the host name | TLS. Verifies the certificate and the host name |
| Accepted settings | `sslmode=require`, `verify-ca`, `verify-full`. All of them verify the certificate and the host name (`require` too) | `require_ssl=true`, `verify_ca=true`, `verify_identity=true` |
| Rejected settings | `sslmode=prefer`, `allow` (they fall back to plaintext if the peer refuses TLS) | `verify_ca=false`, `verify_identity=false` (they turn off verification) |
| Plaintext | Only when you write `sslmode=disable` (for loopback and Unix domain sockets) | Only when you write `require_ssl=false`. A Unix domain socket (`socket`) can be used only in this case |

- Certificates are verified against the system's certificate authorities. The records shipper reads the file that the environment variable `SSL_CERT_FILE` points to or, if that is not set, the bundle at each distribution's usual location (Debian and Ubuntu, Fedora and Red Hat, openSUSE). You cannot specify a CA file in the connection string; pass your own CA's certificate with `SSL_CERT_FILE`.
- The records shipper does not connect to a server that does not offer TLS.
- With MySQL, the records shipper does not switch to the Unix domain socket that the server reports. It connects with the address in the connection string as it is.

### Log Table

When the records shipper connects to the DB, it looks for the tables and creates only those that do not exist.

| Table | Content |
|---|---|
| `tukuyomi_records` | One row for each log line. `id` (serial number), `ts`, `type`, `request_id`, `client`, `method`, `host`, `path`, `class`, `status`, `reason`, `ms`, `upstream`, `mode`, `engine`, `generation`, `rule`, `rules` (a string), `score`, `body`, `sent`, `raw` (the line itself), `line_hash` (the SHA-256 of the line. UNIQUE) |
| `tukuyomi_records_state` | How far each log directory has been sent (`source`, the path of `records.dir`) (`inode`, `born`, `offset`, `lost_lines`, `updated`) |
| `tukuyomi_records_schema` | The schema version (currently 1) |

- The indexes are on `ts`, `(type, ts)`, `request_id`, and `rule`.
- If all the tables exist and the version table has a row, nothing is created, so the records shipper's DB user does not need the privilege to create tables. If you do not want to grant that privilege, run the records shipper once as a user that has it, let it create the tables, and then switch the records shipper to the other user. When you create the tables by hand, create them exactly as the records shipper does (the `CREATE TABLE` in `records-ship/src/store/pgsql.rs` and `records-ship/src/store/mysql.rs`), and also insert a row with 1 into the version table. Without a version row, the records shipper tries to create the tables and needs the privilege to do so.
- If `tukuyomi_records_schema` has a version newer than this records shipper, the records shipper does not send logs to that DB (`the schema of the database is newer than this program`).
- Run only one records shipper per log directory. The position is kept for each `records.dir` path, so when proxies on different hosts send to the same tables, give them different `records.dir` paths, or use a different schema or DB.
- PostgreSQL: it takes an advisory lock while it creates the tables.
- MySQL: the tables are created as InnoDB, with the `utf8mb4` character set, the `utf8mb4_bin` collation, and the `DYNAMIC` row format, and times are `DATETIME(3)` in UTC. For each connection, the records shipper sets `sql_mode` to a strict setting (including `STRICT_ALL_TABLES`) and the time zone to UTC. It takes `GET_LOCK` while it creates the tables. Set the server's `max_allowed_packet` to 2 MiB or more (one `INSERT` holds up to 100 rows). Keep the `records.dir` path to at most 512 characters. If it is longer, the records shipper writes the line `a value does not fit the database` and stops.

### How Shipping Works

- In one round, the records shipper reads up to `batch` lines from the log file and, in one transaction, inserts them and advances the position table. After the commit, it writes `ship.state`. Even if the records shipper crashes, the next round continues from the position in the DB.
- After a round that filled `batch` lines, it starts the next round immediately, and after a round with no lines to send, it waits `interval_ms`. After a failure, it doubles the wait each time, starting from `interval_ms`, up to 1 minute, and resets it after a successful round.
- While it cannot connect to the DB, and while there are no lines to send, it still rewrites `ship.state` at least once per second. The proxy uses this to tell that the records shipper is running.
- It tracks the log files by inode and creation time, not by name. Even if a file is renamed by a rotation, it reads on from where it left off. If the last line of the file in use has no newline, the proxy may still be writing it, so it is left for the next round.
- It sends the lines of every `type`. For a line that is a JSON object with a `type` it knows, it puts the fields into the columns with the same names (columns whose field is missing or has a different type are left empty). Other lines are inserted with `type` set to `unknown`. The line itself is always kept in `raw`.
- The column lengths follow the limits of what the proxy writes, and long values are cut (`method` 32, `host` 255, `path` 1024, `request_id` 128 bytes). For a line that is not UTF-8, invalid bytes become U+FFFD in `raw` (`line_hash` is the hash of the original bytes).
- `line_hash` is UNIQUE, so a line that was sent twice ends up as one row. Lines with identical bytes also end up as one row.
- If `retention_days` is not 0, once per minute it deletes up to 1000 lines older than that (if it deleted 1000 lines, it keeps deleting). Age is based on the `ts` of the log (the proxy's clock).

### Logs That Cannot Be Shipped

- Lines in a log file that rotation removed before the records shipper read them are lost.
  - If it was the file that the records shipper had open, the records shipper counts the lost lines, adds them to `lost_lines` in the position table, and writes the line `records-ship: a record file was removed before it was shipped, <count> lines lost`.
  - Lines in a file that disappeared before the records shipper opened it (for example, when the proxy rotated more than `files` times while the DB was unreachable for a long time) cannot be counted. The records shipper writes only a line that contains `lines may be lost`. This line may also appear when nothing was lost.
- A `required` route of the proxy refuses requests before this happens (see "How Logs Are Kept (`keep` and the `records` of a Route)" above). A `best_effort` or `security` route does not.
- Do not truncate the log files (for example, with logrotate's `copytruncate`). The records shipper treats a truncated file as the same file and may not send its first lines. The proxy rotates the files itself.

### Records Shipper Errors

- The records shipper writes its log to standard error as JSON, one line per entry, like the proxy (`type` is `line`, and the message starts with `records-ship:`). The messages do not contain the connection string, logs, or text from the server's error messages. A DB error is reported as a fixed message with the SQLSTATE that the server returned (example: `records-ship: the database refused or failed a request (SQLSTATE 42000)`).
- When the DB refuses the login (a PostgreSQL SQLSTATE that starts with 28, or MySQL 1045), waiting will not help, so the records shipper writes the line `records-ship: stop: the login is refused, which waiting does not mend` and exits (exit 1).
- For other refusals, the records shipper retries after the wait described above and writes a line each time. These include a DB that does not exist, missing privileges on the DB, and, for MySQL, a host that is not allowed to connect (1130) and a locked account (3118).

## Monitoring

When you write `status` in the configuration, the proxy responds to the following three requests on that loopback address. The responses are not authenticated.

| Request | Response |
|---|---|
| `GET /healthz` | 200 `ok`. It shows only that the proxy can respond |
| `GET /readyz` | 200 `ready` if the proxy is ready. Otherwise 503 and a word for the reason: `starting` (before the listeners are bound), `inspector down` (the inspector process of a started engine is not running, including during a restart), `stopping` (after a stop has begun) |
| `GET /metrics` | 200 and the metrics in the table below (Prometheus text format, `text/plain; version=0.0.4`) |

- The proxy is ready when the inspector processes of all the engines that have started are running, all the listeners are bound, and a stop has not begun. During a generation switch, the old generation responds, so the proxy stays ready.
- `HEAD` returns the same status code without a body. Other methods get 405, other request targets (including those with a query) get 404, and a request that is not HTTP/1.1 and a header section that does not fit in 4 KiB get 400.
- It serves one request on each connection and closes the connection after responding. At most 8 connections are served at the same time, counted separately from the `max_conns` for forwarding. A connection beyond that is closed immediately after it is accepted. It waits at most 2 seconds for the header section and at most 2 seconds to write the response.
- Monitoring requests are neither inspected nor forwarded, and are not recorded in the logs. The global `access` and `rate_limit` and the host policies do not apply to them either.
- The monitoring listener is bound before the inspector processes and is closed after step 3 of the stop. Until then, `/healthz` returns 200.

### Metrics (`/metrics`)

The metric values are kept in the proxy's memory and start again from 0 after a restart. Label values are only fixed words or names from the configuration (values that come from requests are not used as labels).

| Name | Type | Labels | Content |
|---|---|---|---|
| `tukuyomi_requests_total` | `counter` | `class` | The number of requests. Requests whose logs are not written are also counted (`class` has the same 7 values as in the log) |
| `tukuyomi_waf_rule_hits_total` | `counter` | `decision` (`block`, `detect`) | Requests that a rule blocked, and requests that matched a rule in detect-only mode |
| `tukuyomi_uninspectable_total` | `counter` | `reason` | Requests that could not be inspected (`invalid`, `queue_full`, `unavailable`, `wait_deadline`, `verdict_deadline`, `inspector_lost`, `protocol`, `inspector_error`, `not_created`, `cancelled`) |
| `tukuyomi_policy_refusals_total` | `counter` | `policy` (`access`, `rate_limit`) | Requests refused by the access control and the rate limit (the 403 of the access control and the 429 of the rate limit, for the global settings and the host policies). A 403 from the `access` of a route or from `admin.route.access` is not counted |
| `tukuyomi_rate_limit_keys` | `gauge` | | The number of clients that the rate limit is counting now. The total over the global table and all the tables of host policies (the part of `keys` that is in use). 0 if there is no rate limit |
| `tukuyomi_rate_limit_evicted_total` | `counter` | | The number of clients that were removed from a table to make room although their count was still left. The total over all tables, and it does not decrease even when a configuration reload replaces the tables. 0 if there is no rate limit |
| `tukuyomi_connections_accepted_total` | `counter` | | Accepted connections |
| `tukuyomi_connections_open` | `gauge` | | Open connections |
| `tukuyomi_connection_permit_waits_total` | `counter` | | The number of times a connection waited for a connection slot when it was accepted (a guide to how often `max_conns` was reached) |
| `tukuyomi_tls_handshake_failures_total` | `counter` | | Failures and timeouts of the TLS handshake |
| `tukuyomi_body_buffer_bytes` | `gauge` | | The bytes of the budget in use for buffering bodies and so on (the part of `max_buffered_bytes` that is in use) |
| `tukuyomi_inspections_waiting` | `gauge` | | Requests waiting for an inspection slot (the part of the `wait_queue` of each engine that is in use, totaled over all engines) |
| `tukuyomi_inspector_up` | `gauge` | | 1 if the inspection kernels of all the engines that have started are ready, 0 otherwise |
| `tukuyomi_inspector_restarts_total` | `counter` | | Restarts of inspector processes (total over all engines) |
| `tukuyomi_inspector_engine_up` | `gauge` | `engine` (`coraza`, `modsecurity`) | 1 if the inspection kernel of the engine is ready, 0 otherwise. One for each engine that has started |
| `tukuyomi_inspector_engine_restarts_total` | `counter` | `engine` (`coraza`, `modsecurity`) | Restarts of the inspector process of the engine. One for each engine that has started |
| `tukuyomi_rules_generation_info` | `gauge` | `generation` (the first 16 digits of the fingerprint), `mode`, `engine` | The generation that is receiving requests. The value is always 1. One for each engine that has started |
| `tukuyomi_rules_switches_total` | `counter` | `result` (`switched`, `refused`, `failed`) | Generation switches by SIGUSR1 and by the control socket |
| `tukuyomi_certificate_reloads_total` | `counter` | `result` (`replaced`, `refused`) | Certificate reloads by SIGUSR2 |
| `tukuyomi_config_reloads_total` | `counter` | `result` (`replaced`, `refused`) | Configuration reloads by SIGHUP and by `reload` on the control socket. A SIGHUP that was received during a reload and ignored, and a `reload` request that did not start a reload (the responses `busy`, `unmanaged`, and `error`), are not counted |
| `tukuyomi_upstream_failures_total` | `counter` | `group` | Failures of upstream servers. Reset to 0 at a configuration reload |
| `tukuyomi_records_dropped_total` | `counter` | | Logs that were discarded (see "When Logs Cannot Be Written" above) |
| `tukuyomi_record_write_errors_total` | `counter` | | Logs that failed to be written |
| `tukuyomi_record_file_errors_total` | `counter` | | Logs that could not be written to the log file, and failed syncs (see "Log Files (`records`)" above) |
| `tukuyomi_records_refused_total` | `counter` | | Requests that a `required` route refused with 503 because logs could not be kept (see "How Logs Are Kept (`keep` and the `records` of a Route)" above) |
| `tukuyomi_records_healthy` | `gauge` | | 1 if the last write to the log file succeeded and the thread that writes logs is running, 0 otherwise |
| `tukuyomi_records_admitting` | `gauge` | | 1 if requests to `required` routes are accepted now, 0 if they are refused (the three conditions in "How Logs Are Kept (`keep` and the `records` of a Route)" above). It is also exposed when there is no `required` route |
| `tukuyomi_records_unshipped_bytes` | `gauge` | | The bytes of the log files that the records shipper has not sent yet. Exposed only when `records.ship` is present. While the proxy cannot tell how far the records shipper is behind, it has no value |
| `tukuyomi_start_time_seconds` | `gauge` | | The start time (Unix time in seconds) |

### Notifications to systemd

If the environment has `NOTIFY_SOCKET`, the proxy sends `READY=1` to that socket once after all the listeners are bound, and `STOPPING=1` once when a stop begins.

- `NOTIFY_SOCKET` is an absolute path or a name that starts with `@` (a name in the Linux abstract namespace). For any other value, the proxy writes one `start:` line and runs without sending notifications.
- When a notification cannot be sent, the proxy only writes one `notify:` line and otherwise behaves as usual. It sends without waiting, so the proxy does not get stuck even if the receiver does not read.
- The environment of the inspector processes is empty, so the inspector processes do not send notifications.
- If you make the unit `Type=notify`, `systemctl start` waits until the inspection kernels are ready and the listeners are bound (see "systemd" in the [build and deployment guide](../build/binary-deployment.md)).

## ACME

`acme renew` issues and renews certificates only with HTTP-01 challenges (RFC 8555).

### Requirements

- The CA fetches the challenge over plaintext HTTP from port 80 of the certificate's host, so you need a normal listener or a redirect listener on port 80.
  - The proxy does not check port numbers.
- A normal listener and a redirect listener respond to the following requests before the admin route, the policies (the global settings and the host policies), routes, the `access` of a route, inspection, forwarding, and redirects. A TLS listener does not respond to them.
  - The method is `GET` or `HEAD`.
  - The request target is `/.well-known/acme-challenge/<token>` with nothing after it (no query and no escapes). The token is 1 to 128 characters of letters and digits, `-`, and `_`.
  - The `Host` is the host of a certificate that has `acme` (case, the port, and a trailing `.` are ignored). With `managed`, it is the host of the admin route that has `acme`, or a host of an ACME site of the running version (see "ACME Sites" above).
- A request that is not in the form above is not treated as a challenge, and goes to routes and inspection like other requests.
- The response is either 200 with the file `<token>` in `challenge_dir` as its body (a regular file of up to 1 KiB), or 404. Symbolic links are not followed.
- `admin.route.access` does not apply to challenges (because the CA can connect from any address).
- In `ca_file`, put only the root certificates that issued the server certificate of the CA's API. It can hold at most 100 certificates, so you cannot use the OS root certificate bundle as it is.

### First Issue

1. In the configuration, write `acme` and a certificate that has `acme`. The certificate files need not exist yet.
   - In a configuration without `managed`, put `acme` on a certificate of a listener. In a configuration with `managed`, put it on the certificate of the admin route (`admin.route.certificate`) and on a site of a version (see "ACME Sites" above).
   - The proxy writes a `start: tls certificate not issued yet (<place>)` line and starts, leaving that certificate out of the handshake.
   - To test first, set `directory_url` to the CA's test ACME directory (staging, for Let's Encrypt).
2. Start the proxy.
3. Run `acme renew` as the OS user of the service.

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy acme renew /etc/tukuyomi-core/config.json
   ```

   Lines like `2.1 renewed` are written (with `managed`, lines like `admin route renewed` and `site www renewed`).
4. Send SIGUSR2 (`systemctl kill -s SIGUSR2 --kill-whom=main tukuyomi-core.service`), and the proxy starts to use the certificate.
5. When it works with the test CA, switch to the production CA.
   - The certificate from the test CA has not expired, so `acme renew` leaves it as it is (`valid`). Delete that certificate's files: `cert_file` and `key_file` for listeners and the admin route, and `chain` and `key` in `acme/<hosts-sha256>/` in the managed store for an ACME site.
   - Change `directory_url` to that of the production CA. If the server certificate of the production CA's API comes from a different root certificate, also change `ca_file`.
   - Run `acme renew` again, and then send SIGUSR2. If you send SIGUSR2 between deleting the files and the end of `acme renew` (the same applies to a configuration reload, which also reads certificates), that certificate drops out of the handshake. If you keep to this order, the proxy keeps using the certificate it has already loaded in the meantime.
   - Most setting keys of `acme`, such as `directory_url`, `ca_file`, and `contact_email`, are read only by the command, so the proxy does not need a restart. `challenge_dir` and the hosts of a certificate that has `acme` are also read by the proxy, so when you change them, reload the proxy's configuration (SIGHUP, `systemctl reload`; the hosts of an ACME site switch when a version is applied).
6. Install the daily timer (see "Certificate Renewal Timer" in the [build and deployment guide](../build/binary-deployment.md)).

### Notes

- Do not run two `acme renew` commands at the same time with the same configuration. Nothing prevents concurrent runs.
- Unless you send SIGUSR2 after the command, the new certificate is not used.
- The key and the certificate are each written to a separate file and synced, and then they replace the old files, the key first and then the certificate.
  - If the command stops between the two replacements, a key that does not match the certificate is left behind. The running proxy refuses that pair at SIGUSR2 and keeps using the current one, and the next run recreates them. If you start the proxy in the meantime, however, it refuses that pair and does not start (exit 1).
  - If the time between the two replacements overlaps with a configuration reload (SIGHUP, `reload` on the control socket), `managed activate`, `config check`, or start, the certificate check can be refused (`tls refused`). In that case, run it again. For how applying from the admin screens and the admin API handles this, see "Control Socket" in the [admin reference](admin-reference.md).
- The OS user of the service must be able to write to the directory where `cert_file`, `key_file`, and `challenge_dir` are placed, and to the managed store (see "OS User and Directories" in the [build and deployment guide](../build/binary-deployment.md)).
  - The key is written with 0600 and the certificate with 0644 (minus the umask).
- After you apply a version that changes the hosts of an ACME site, and after you go back to an earlier version, run `acme renew` immediately (see "ACME Sites" above).

## Version Updates

Until 1.0, only updates from the previous release are supported. To skip releases in between, update one release at a time, in order. To go back to the previous version, restore the backup taken before the update (see "Going Back to the Previous Version" below). For how to write the unit, see "systemd" in the [build and deployment guide](../build/binary-deployment.md).

### Backup Before an Update

Before an update, back up the following:

- The configuration file
- The rules store (`rules.store.dir`)
- The managed store (`managed.dir`, when you use the managed configuration)
- The admin store (`admin.store.dir`, when you use the admin process)

While you take the backup, keep the admin process, the proxy, the records shipper, and the certificate renewal timer stopped. Keep the owners and permissions as they are (the rules store and the other stores are checked for them). The backup also holds the admin store's password hashes and API tokens, the managed store's private keys, and so on, so put it in a directory that only root can read. The following commands back up the example directories and units from the [build and deployment guide](../build/binary-deployment.md). Leave out of the command any directory that you do not use.

```bash
sudo systemctl stop tukuyomi-core-admin.service tukuyomi-core.service tukuyomi-core-records-ship.service tukuyomi-core-acme.timer
sudo install -d -m 0700 /var/backups/tukuyomi-core
sudo tar -C / -cpf /var/backups/tukuyomi-core/before-update.tar etc/tukuyomi-core/config.json var/lib/tukuyomi-core/store var/lib/tukuyomi-core/managed var/lib/tukuyomi-core/admin
```

The log directory (`records.dir`), the certificates and keys, and the work directory (`kernel.tmp_root`) are not backed up.

### Updating from 0.1.0

- Take the backup described in "Backup Before an Update" above, and then replace the executables.
- Once the executables are replaced, the 0.1.0 configuration file, rules store, and managed store are read as they are (if you had chosen a ModSecurity generation in 0.1.0, `kernel.default_engine` is required, as described below). If you do not write the new setting keys (`kernel.default_engine`, the `engine` of an upstream), the proxy runs with only one engine, as in 0.1.0.
- If you had chosen a Coraza generation in 0.1.0, you do not need to write `kernel.default_engine`. The `current` written by 0.1.0 is read as Coraza's chosen generation. `config check` writes `accepted`, and at start only one `start: rules engine coraza` line appears. `current` is not rewritten and no `current.*` is added.
- If you had chosen a ModSecurity generation in 0.1.0, write `modsecurity` in `kernel.default_engine`.
  - If you do not, `config check` and start write the line `rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine` and reject the configuration (exit 1). The rules store does not change.
  - With `modsecurity` written, the configuration file passes `config check`, and at start only one `start: rules engine modsecurity` line appears. `current` is not rewritten and no `current.*` is added. The ModSecurity inspector process has been required in `kernel.engines` of the configuration since 0.1.0.
- Use the same build for the admin process, the proxy, and the records shipper.
  - The updated admin process does not choose generations or roll back for a proxy of an earlier version (409). For details, see "Choosing and Rolling Back" and "Admin Screens" in the [admin reference](admin-reference.md).
  - The records shipper rejects unknown setting keys in the configuration file. Before you write `kernel.default_engine` or the `engine` of an upstream, replace the records shipper with the same build. The 0.1.0 proxy also rejects a configuration file that has `kernel.default_engine`, with `configuration has an unknown key` (exit 2).
  - Replace all the executables with those of the same release, and then restart the admin process, the proxy, and the records shipper in this order (the same order as step 8 of "Moving to the Managed Configuration"). If you restart the admin process first, then while the replacement is in progress, the updated admin process only refuses generation choices and rollbacks for the earlier proxy with 409, and the rules store and the switch history do not change.

### Going Back to the Previous Version

Restore the backup taken before the update, and start the executables of the previous version. The steps are the same for every version.

1. Stop the admin process, the proxy, the records shipper, and the certificate renewal timer.
2. Move the current configuration file and the directories you backed up aside to other names (keep them; do not delete them).
3. Restore the backup.
4. Put back the executables of the previous version, and check that the previous version's `config check` writes `accepted`.
5. Start the admin process, the proxy, and the records shipper in this order, and start the certificate renewal timer.

For the backup in the example in "Backup Before an Update" above, steps 2 and 3 are as follows.

```bash
sudo mv /etc/tukuyomi-core/config.json /etc/tukuyomi-core/config.json.after-update
sudo mv /var/lib/tukuyomi-core/store /var/lib/tukuyomi-core/store.after-update
sudo mv /var/lib/tukuyomi-core/managed /var/lib/tukuyomi-core/managed.after-update
sudo mv /var/lib/tukuyomi-core/admin /var/lib/tukuyomi-core/admin.after-update
sudo tar -C / -xpf /var/backups/tukuyomi-core/before-update.tar
```

- What you changed after the update is lost: the generations you imported or chose, the managed configuration versions and applies, the users, API tokens, and sessions you made, and the audit log lines in the admin store. The audit log lines were also written to standard error (the journal).
- The log directory is not restored. Logs written after the update remain.
- The ACME site certificates in `acme/` in the managed store go back to those at the time of the backup. The next `acme renew` renews them depending on how much validity they have left (see "ACME" above).
