[English](admin-reference.md) | [日本語](admin-reference.ja.md)

# Admin Reference

This document is a reference for the admin process, the setting key `admin`, the admin API, and the admin screens, as they are currently implemented. For the proxy's setting keys and commands, see the [operator reference](operator-reference.md). For deployment and example systemd units, see the [build and deployment guide](../build/binary-deployment.md).

The paths and names in this document (`/etc/tukuyomi-core/config.json`, the OS user `tukuyomi`, `admin.example.com`, `192.0.2.0/24`, and so on) are examples.

## Components

The admin process runs separately from the proxy, as the `admin` command of the same executable, `tukuyomi-proxy`. It responds to requests both for the admin screens, which you open in a browser, and for the admin API, which programs use.

| Component | Content |
|---|---|
| Admin process | `tukuyomi-proxy admin <config>`. It serves the admin screens and the admin API on a loopback listener, without TLS |
| Admin screens | Screens built into the executable (Japanese and English). The admin process serves them |
| Admin store | `admin.store.dir` in the configuration. The directory that holds the users, API tokens, audit log, switch history, and configuration history |
| Control socket | `admin.control` in the configuration. A Unix domain socket that the proxy creates. The admin process uses it to ask for the proxy's state, to request a generation switch for each engine, and to request a configuration reload with a managed configuration version (for the proxy side, see "Control Socket" in the [operator reference](operator-reference.md)) |
| Log files | `records.dir` in the configuration. The proxy puts copies of its logs there. The admin process reads them (see "Log Files (`records`)" in the [operator reference](operator-reference.md)) |
| Managed store | `managed.dir` in the configuration (only for a configuration that has `managed`). The directory that holds the managed configuration versions and the files they use, such as certificates. The admin process saves and removes versions. The proxy only reads them (see "Managed Store and Versions" in the [operator reference](operator-reference.md)) |

- The admin process and the proxy read the same configuration file. The admin process reads values such as `admin` only once, at start, and does not read them again. The exceptions, which read the configuration file again each time, are `GET /api/config` (which returns the values in the configuration file) and checking or changing the managed configuration (see "Managed Configuration Operations" below). The proxy reloads its configuration on SIGHUP, but `admin` is a setting key that cannot be changed while the proxy is running (see "SIGHUP (Configuration Reload)" in the [operator reference](operator-reference.md)).
  - Of the setting keys in `admin`, the proxy uses `listen` and `control`, and also `route` in a configuration that has `managed`. Only the proxy uses `route`, not the admin process. The proxy also validates the ranges of the other setting keys, but does only that, so that both processes accept the same file or both reject it.
  - After you change a setting key in `admin`, restart the admin process. The proxy refuses to reload a configuration with a different `admin`, so restart the proxy too. For what the proxy does when `admin.route` is changed, see "`admin`" and "SIGHUP (Configuration Reload)" in the [operator reference](operator-reference.md).
- The admin process keeps working while the proxy is stopped. You can still read generations and logs, import, manage users, and read, check, and remove managed configuration versions. Generation switches, rollbacks, and applying the managed configuration are requests to the proxy, so they are refused if the proxy cannot be reached. In that case, the managed configuration's "Save and apply" does not save the version either (see "Generation Operations" and "Managed Configuration Operations" below).
- If the configuration has no `admin`, the admin process does not start (exit 2), and the proxy does not create the control socket.

## Admin Process

### `admin`

```text
tukuyomi-proxy admin <config>
```

- Pass the configuration file as an absolute path (the same rule as for "Commands" in the [operator reference](operator-reference.md)).
- At start, it does the following, in order.
  1. It runs the checks before start (not running as root, SIGCHLD, and file descriptors), which are the same as for the proxy (see "Checks Before Start" in the [build and deployment guide](../build/binary-deployment.md)).
  2. It reads the configuration file.
  3. It opens the admin store and takes the lock on `process.lock`.
  4. It opens the audit log.
  5. It binds the listener.
- After it binds the listener, it writes an `admin: listening` line and, if `NOTIFY_SOCKET` is in the environment, sends `READY=1`.
- Only one admin process can run on an admin store. While one admin process holds `process.lock`, no other admin process can start on the same store (exit 1). This keeps two processes from both accepting the same verification code in the same time window, or the same recovery code.
- Run it as the same OS user as the proxy. It uses the rules store, the admin store, the log file directory, and the managed store (`managed.dir`) only if each is a directory owned by that OS user, with no permissions for the group or other users. The proxy makes the same check on the control socket's directory when it creates the socket. An import trial starts an inspector process, so the admin process also uses the same `kernel` value as the proxy (the inspector process's executable and work directory).
- The exit codes are as follows.

| Exit code | Meaning |
|---|---|
| 0 | Stopped by a signal |
| 1 | Any other exit: started as root, a failed check before start, an admin store that cannot be used (including one that another admin process is using), an audit log that cannot be opened, an `admin.listen` that cannot be bound |
| 2 | An argument error, a configuration file that was rejected, a configuration file without `admin` |

### `admin bootstrap`

```text
tukuyomi-proxy admin bootstrap <config> <name>
```

Creates the first user, with the role `owner`. It works only when the admin store has no users.

- It reads the password from the first line of standard input. Do not pass it as an argument. Example:

  ```bash
  read -r -s -p 'password: ' PW; echo
  printf '%s\n' "$PW" | sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy admin bootstrap /etc/tukuyomi-core/config.json alice
  unset PW
  ```

- A name is 1 to 32 bytes of lowercase letters, digits, `.`, `_`, and `-`. A password is 12 to 128 bytes of UTF-8.
- On success, it writes `created owner <name>` to standard output and exits with 0. Other lines go to standard error. Except for the audit log line (below), they start with `admin bootstrap:`.
- It writes an audit log line (`action` is `create`, `auth` is `bootstrap`, with no actor and no client address) before it creates the user. If it cannot write the line, it does not create the user. This line is written to standard error as JSON.
- It can run when the admin process is not running.

### `admin reset`

```text
tukuyomi-proxy admin reset <config> <name>
```

Resets the password of a user who is locked out (for example, the only owner, after losing both the password and two-factor authentication).

- It reads the password, checks the name and the password, and writes the standard error lines and the audit log line in the same way as `admin bootstrap`. In the audit log line, `action` is `reset`, `auth` is `reset`, and the target is the user's name.
- On success, it writes `reset password of <name>` to standard output and exits with 0.
- It does the following to the user.
  - It sets the password to the entered value and makes the user change it at the next login.
  - It disables two-factor authentication and the recovery codes.
  - It ends this user's sessions and invalidates all API tokens. If it cannot delete a token file, it writes a line about it to standard error, but the token stays invalid, and it exits with 0.
  - It releases the lockout and resets the failure count to 0.
- It does not enable a disabled user. To make a disabled user usable again, an owner enables the user with `PUT /api/users/<name>`.
- It can also run while the admin process is running. It writes the change while holding the store's lock, and only if the user has not changed since it was read. If it overlaps with another write, it is refused with `the admin store is in use by another process` or `the user was changed since it was read` (exit 1); run it again.

The exit codes and the main standard error lines of `bootstrap` and `reset` are as follows.

| Exit code | Case | Standard error line (after `admin bootstrap:` or `admin reset:`) |
|---|---|---|
| 0 | Success | (the line above, on standard output) |
| 1 | Run as root, a failed check before start | `host check refused: ...` |
| 1 | The password cannot be read | `the password is not 12 to 128 bytes`, `the password line is too long`, `the password is not UTF-8` |
| 1 | An admin store that cannot be used, an audit log that cannot be written | `admin store refused: ...`, `audit log refused: ...`, `the audit log cannot be written` |
| 1 | The user already exists (`bootstrap`), the user does not exist (`reset`) | `the store has a user already`, `the user is not in the store` |
| 2 | The configuration was rejected, there is no `admin` | `configuration refused: ...` |
| 2 | A name error | `the name is not 1 to 32 bytes of a-z, 0-9, '.', '_' and '-'` |
| 2 | An argument error | (a line that starts with `admin:`, followed by a usage line) |

### Listener

The admin process responds to HTTP/1.1 requests on the loopback address of `admin.listen`. It does not use TLS. To use it from outside, go through a TLS listener of the proxy (see "Access from Outside" below).

| Field | Value |
|---|---|
| Concurrent connections | 32. A connection over the limit is accepted and closed at once |
| One connection | It accepts one request, responds to it, and closes (`Connection: close`). It does not wait for the next request |
| Header section | Up to 8 KiB and up to 64 header fields. It must be read within 10 seconds |
| Body | Up to 64 KiB. It must be read within 30 seconds |
| Body of an import, `POST /api/managed/check` and `POST /api/managed/apply` | Up to 12 MiB. It is read only for a user who can use that API (an operator or above, with a valid session or token, and not restricted by the state). Otherwise the body is not read, and the request is refused with the 400, 401, 403, 429, or 503 from the checks (400 if both a cookie and a token are present, 429 for a client that has used up its token attempts, 503 if the store cannot be read) |
| Time to build a response | 30 seconds. For an import, choosing a generation, and a rollback, the time given in "Slow responses" below |
| Lifetime of a connection | Up to the total of the times for the header section, the body, and the response |

- A request whose `Content-Length` is over the limit gets 413 before the credentials are checked, and the body is not read. For a header section that has an error or is over the limit, the HTTP library either returns its own response or returns nothing.
- An API that reads a body returns 415 if `Content-Type` is not `application/json`. A body whose JSON has the wrong form, or that has a key that the API does not recognize, gets 400.
- `HEAD` is handled as `GET`. A path that is not in the table gets 404, and a path in the table with another method gets 405 (with `Allow`).

Slow responses: An import (including the trial), choosing a generation, and a rollback take time. For these, the time to build the response is the longer of the following two times plus 7 seconds (computed from the time setting keys in `proxy`). A request that times out gets 503 `unavailable`.

- Import: `ready_wait_ms + 3 × inspect_wait_ms + stop_inspect_ms`
- Choosing a generation and rollback: `ready_wait_ms + stop_inspect_ms + 14 seconds`

With the example values from the operator reference (`ready_wait_ms` 30000, `inspect_wait_ms` 55000, `stop_inspect_ms` 10000), the limit is about 212 seconds. An import that goes smoothly takes far less time than this.

### Stopping and systemd

- It stops on SIGTERM, SIGINT, and SIGHUP. It writes an `admin: stop: <signal>` line, sends `STOPPING=1` if `NOTIFY_SOCKET` is set, and then does the following.
  1. It ends a running import trial as a failure, and cleans up its inspector process and work directory.
  2. It closes the listener.
  3. It waits up to 10 seconds for requests in progress, and cuts off the connections that remain.
  4. It exits with 0.
- The rules for `NOTIFY_SOCKET` are the same as for the proxy (see "Notifications to systemd" in the [operator reference](operator-reference.md)). It handles only these three signals, not SIGUSR1 or SIGUSR2 (if you send one of those, the default action ends the process).
- Sessions, each user's failure count and lockout state, the two-factor authentication secret that is being set up, and the managed configuration's apply job are kept only in memory. After a restart, everyone must log in again, and the apply job is lost. API tokens, users, the audit log, the switch history, and the configuration history stay in the store.

Write the admin process's systemd unit to match the proxy's unit (see "systemd" in the [build and deployment guide](../build/binary-deployment.md)), with the following differences.

- Set `ExecStart` to `tukuyomi-proxy admin <config>`, and use the same `User` and `Group` as the proxy.
- Set `Type=notify`. The admin process sends `READY=1` after it binds the listener.
- Set `KillMode=mixed`. With the default `control-group`, SIGTERM also reaches the inspector process of an import trial, and the admin process cannot stop that inspector process in order (for the same reason as with the proxy).
- Make `TimeoutStopSec` longer than the 10 seconds that the admin process waits when it stops. An import trial may be running at that time, so also add the time to stop its inspector process (`proxy.stop_inspect_ms` and `kernel.kill_grace_ms`).
- If the port of `admin.listen` is 1024 or higher, `AmbientCapabilities` is not needed. `ReadWritePaths` includes the rules store, the admin store, `kernel.tmp_root`, the directory for the control socket, and the managed store (when there is `managed.dir`).
- Set `LogRateLimitIntervalSec=0`. Audit log lines are also written to standard error (the journal), and this keeps journald's rate limit from dropping them.
- The unit does not need to be ordered before or after the proxy's unit.

As with the proxy, logs go to standard error as one JSON object per line (see "Logs" in the [operator reference](operator-reference.md)). The admin process writes `line` entries for the messages that start with `admin:` and `audit` entries for the audit log lines. `audit` entries do not go into the log files of the proxy (`records.dir`).

## Setting Key `admin`

```json
"admin": {
  "listen": "127.0.0.1:9100",
  "control": "/var/lib/tukuyomi-core/control/proxy.sock",
  "store": {"kind": "file", "dir": "/var/lib/tukuyomi-core/admin"},
  "origin": "https://admin.example.com",
  "trusted_proxies": ["127.0.0.1/32"],
  "mfa": "required",
  "session_idle_ms": 1800000,
  "session_total_ms": 43200000,
  "crs_dir": "/var/lib/tukuyomi-core/crs-4.23.0"
},
"records": {"dir": "/var/lib/tukuyomi-core/records", "file_bytes": 16777216, "files": 8}
```

`admin` and `records` are objects at the top level of the configuration file (alongside `proxy`, `forward`, `kernel`, and so on). Both are optional. When you write `admin`, write all setting keys except `crs_dir` and `route`. `route` is required in a configuration that has `managed`, and cannot be written in one that has no `managed`. Unknown setting keys, duplicates, and type mismatches are rejected by the same rules as in "Configuration File" in the [operator reference](operator-reference.md).

| Setting key | Range | Meaning |
|---|---|---|
| `listen` | A loopback IP (`127.0.0.0/8` or `::1`) and a port (0 is not allowed) | The address of the admin process's listener. The `::ffff:127.0.0.1` form is not treated as loopback |
| `control` | An absolute path, up to 107 bytes | The control socket file |
| `store` | `{"kind": "file", "dir"}` | The admin store. At present, `kind` can only be `file`. `dir` is an absolute path of up to 3840 bytes |
| `origin` | `https://` and a host (optionally `:port`) | The origin of the URL at which you open the admin screens. It has the same form as the `host` of a route (a lowercase name), and cannot have a wildcard, a path, a query, or a trailing `/`. It is compared with the `Origin` of requests that change something, such as `POST` |
| `trusted_proxies` | 0 to 256 networks | The peers that the admin process trusts when it takes the client address from `X-Forwarded-For`. Write each in the form `address/prefix`, with the host part set to 0. They are read the same way as for the proxy (see "Client Address" in the [operator reference](operator-reference.md)) |
| `mfa` | `"optional"`, `"required"` | Whether two-factor authentication is required. `required` lets a user who has not set up two-factor authentication do only the setup (see "Login and Two-Factor Authentication" below) |
| `session_idle_ms` | 1 minute to 24 hours | How long a session lasts without being used |
| `session_total_ms` | `session_idle_ms` to 7 days | The longest a session can last |
| `crs_dir` | An absolute path, up to 3840 bytes. Optional | The CRS directory that imports can use: the one fetched with `scripts/fetch-crs.sh` (see "Fetching the CRS" in the [build and deployment guide](../build/binary-deployment.md)). If omitted, imports cannot use the CRS |
| `route` | Only in a configuration that has `managed`, where it is required | The route of the admin screens (host, certificate, `access`). Only the proxy uses it. For its form and rules, see "`admin`" in the [operator reference](operator-reference.md); for how to use it, see "Admin Route with the Managed Configuration" below |

- `listen` must not overlap any listener (`proxy.listeners`) or `status.listen`. The overlap rules are the same as between listeners: the same address and port, or the same port when one of them is `0.0.0.0` or `::`.
- An upstream server's address can be `admin.listen`, so that the admin process can be used from outside through a proxy route (see "Access from Outside" below). It cannot be the address of a listener or of `status.listen`.
- Keep the directories separate. No two of the rules store (`rules.store.dir`), `records.dir` (when present), `admin.store.dir`, the directory that holds `admin.control`, `managed.dir` (when present), and `acme.challenge_dir` (when present) can be the same directory, and none can be inside another. `admin.control` itself also cannot be inside the rules store, `records.dir`, or `admin.store.dir`.
- If you change `admin.route.host`, the URL you open in the browser changes too, so change `admin.origin` to the new host as well (see "Access from Outside" below) and restart the admin process. The admin process reads `admin.origin` only at start. For what the proxy does, see "`admin`" in the [operator reference](operator-reference.md).
- Create `admin.store.dir` and the directory that holds `admin.control` beforehand. Each must be a directory (not a symbolic link) owned by the proxy's OS user, with no permissions for the group or other users (0700). The admin process creates `users/`, `tokens/`, and `audit/` in the admin store.
- `config check` validates the setting keys in `admin` and `records` and how their values relate. It does not check whether the admin store, the control socket, or the log files can be opened.

The contents of the admin store (files are 0600, directories are 0700):

| Path | Content |
|---|---|
| `users/<name>.json` | A user. It holds the password hash, the two-factor authentication secret, and the recovery code hashes. Up to 1000 users |
| `tokens/<id>.json` | An API token. It holds only the SHA-256 of the token's secret. Up to 50 per owner |
| `audit/` | The audit log (`audit.log` and older, rotated files) |
| `activations.log` | The switch history |
| `managed.log` | The configuration history (see "Configuration History" below) |
| `lock`, `process.lock` | The write lock and the admin process lock |

### Control Socket

When the configuration has `admin`, the proxy creates the control socket `admin.control` at start. For how it is created, who can use it, and the request and response formats, see "Control Socket" in the [operator reference](operator-reference.md). On the admin process side, it works as follows.

- A state query waits 2 seconds for the connection and 2 seconds for the response. If the proxy accepts the connection and closes it without responding (because it has reached its limit of concurrent connections), the admin process asks once more after 250 ms; if the result is the same, it treats the proxy as "Proxy busy" (in `GET /api/status`, `reachable` is `true` and `proxy` is `null`).
- For a state query and for a generation switch request, each of these means "the proxy cannot be reached": there is no socket, no process accepts the connection, the response is not in the defined form, or no response comes in time.
- Generation switches are requested one engine at a time. Each request names the engine to switch (`engine`) and the generation chosen for that engine in the rules store (`expect`). The admin process does not send the request to a proxy that does not return `engines` in its state (the generation, mode, and phase of each engine running in the proxy). Such a proxy is an earlier version that does not support choosing per engine (see "Choosing and Rolling Back" below).
- After a generation switch request, the admin process waits up to `ready_wait_ms + 7 seconds`. The proxy itself waits `ready_wait_ms + 5 seconds` for the response, so the admin process waits 2 seconds longer.
- When the proxy answers a switch request with `busy`, or closes the connection without reading the request, the admin process queries the state every 250 ms and decides the result as follows.
  - If the proxy starts to use the requested generation for the requested engine, the result is `switched`. The admin process tells this from that engine's generation in the state's `engines`.
  - If two state queries in a row show that no switch is in progress and that the requested generation is not in use, the result is `failed`.
  - The result is also `failed` when `stop_inspect_ms + 7 seconds` have passed.
  - If the proxy becomes unreachable in the meantime, the result is `unconfirmed`.
- After a reload request with a managed configuration version (`reload`), the admin process waits up to the time that resolving the upstream server names may take, plus 7 seconds. For that time it uses the `forward.resolve_timeout_ms` that the proxy returns in its state, or, for an old proxy that does not return it, the value in the configuration file that the admin process has read. This is 2 seconds longer than the proxy itself waits.
- If the proxy refuses because of a certificate (`tls`), the admin process sends the request once more after 1 second. This is because a certificate read while the certificate renewal (`acme renew`) is rewriting the files is refused only at that moment.
- For a `reload` request, each of the following leaves the result unknown, because the request may have arrived and the reload may still be going on: there is no socket, no process accepts the connection, the response is not in the defined form, no response comes in time, the connection was closed without a response, or the proxy responded with `busy` (`reload under way`). The admin process then queries the proxy's state every 250 ms, for as long again as it has already waited, until the proxy is no longer reloading.
  - If the proxy is using the requested version and the number of reloads that switched the configuration (`replaced` in `config_reloads`) has grown since before the request, the result is applied.
  - Otherwise the result is `failed`.
  - If the proxy becomes unreachable in the meantime, or if, when the time is up, it is still reloading or still cannot answer a query, the result is `unconfirmed`.

For how the results are handled, see "Generation Operations" and "Managed Configuration Operations" below. For the order in which an apply proceeds and what happens when it stops halfway, see "Applying" in the [operator reference](operator-reference.md).

### Log File

`GET /api/records` reads the log files that the proxy writes (`records.dir`). For the file names, sizes, and rotation, see "Log Files (`records`)" in the [operator reference](operator-reference.md).

- If the configuration has no `records`, this API returns 404.
- The admin process reads the files as the same OS user as the proxy. It does not read them, and returns 503, if the directory has a different owner, gives permissions to the group or other users, or is not a directory (a symbolic link cannot be used).
- The log files hold client addresses and paths. The admin API lets a viewer or above read them, so decide carefully who gets the viewer role.

## Access from Outside

The admin process does not use TLS, so use it through a TLS listener of the proxy. Cookies are sent with `Secure`, so the admin screens can be used only over https. How you route requests to it depends on whether the configuration file has `managed`.

- A configuration without `managed`: write a route for an admin host in `forward.routes` (see the example below).
- A configuration with `managed`: write the admin screens' route in `admin.route` (see "Overall Structure" and "`admin`" in the [operator reference](operator-reference.md), and "Admin Route with the Managed Configuration" below).

An example for a configuration without `managed`:

```json
"forward": {
  "upstreams": {
    "app": {"servers": [{"address": "127.0.0.1:8080", "weight": 1, "max_fails": 0, "fail_timeout_ms": 10000, "backup": false}]},
    "admin": {"servers": [{"address": "127.0.0.1:9100", "weight": 1, "max_fails": 0, "fail_timeout_ms": 10000, "backup": false}]}
  },
  "routes": [
    {"host": "admin.example.com", "upstream": "admin", "access": {"allow_cidrs": ["192.0.2.0/24"]}}
  ],
  "default_upstream": "app"
}
```

(The other setting keys in `forward` are omitted, and `admin.listen` is `127.0.0.1:9100` in this example.)

- Certificate: put a certificate that has `admin.example.com` in its `hosts` on a TLS listener. A handshake for a name that the certificate does not have fails.
- Upstream: write `admin.listen` as the server's address.
- `engine`: an upstream that forwards to the admin process can also have `engine`, like the other upstreams. If you do not write it, requests are inspected by the default engine. For how to write it, see "`forward`" in the [operator reference](operator-reference.md), and for choosing an engine, see "Choosing the Inspection Engine" in the same document. A bypass route for an import (see "Bypassing Inspection for the Import Route" below) goes into the generations of the engine that inspects this upstream.
- `access`: use `allow_cidrs` to allow only the addresses of the people who use the admin screens. For how the client address is decided and what to watch for when you use `access`, see "Client Address" and "Notes on using `access`" in the [operator reference](operator-reference.md). If any route has `access`, no route can have a port in its `host`.
- The global settings (the global access control and rate limits) and the host policies also apply to requests for this host, before a route is chosen (see "Access Control and Rate Limits" in the [operator reference](operator-reference.md)). Set them to suit how many people use the admin screens and how often they send requests.
- Do not route this host through a plaintext listener. A route is chosen regardless of the listener, so if there is a plaintext listener that is not `redirect`, the password may be sent unencrypted. Make plaintext listeners `redirect`.

Write the following two in either configuration.

- `admin.trusted_proxies`: write the address from which the proxy connects to the admin process (`127.0.0.1/32` on the same host). Otherwise every client appears to have the proxy's address, so everyone shares the per-client limit on login attempts, and `client` in every audit log line is the proxy's address.
- `admin.origin`: make it exactly the same as the origin of the URL you open in the browser (do not write the port when it is 443). If it differs, requests that change something, including login, get 403.

### Admin Route with the Managed Configuration

In a configuration that has `managed`, write the admin screens' route in `admin.route` in the configuration file; the proxy creates this route itself. For the form of the setting key, the certificate and `access`, the hosts that a managed configuration version cannot contain, and the fact that the global settings and the host policies do not apply to this route, see "`admin`" in the [operator reference](operator-reference.md); for how a request is processed once it is received, see "Order of Request Checks" in the same document. For the body limit, see "Body Size" below.

Requests to the admin route are inspected with the running generation of the default engine (`kernel.default_engine` in the configuration file, or Coraza if it is not written). To edit the managed configuration in the admin screens, make `POST /api/managed/check` (check) and `POST /api/managed/apply` (the "Save and apply" operation) bypass routes. The bodies of these two requests are JSON of up to 12 MiB that can hold PEM certificate chains, private keys, and many routes, and a rule may block them if they are inspected. You can write these two paths in one `--routes` file together with the rule import path (see "Bypassing Inspection for the Import Route" below).

```json
[
  {"host": "admin.example.com", "path": "/api/generations", "action": "bypass"},
  {"host": "admin.example.com", "path": "/api/managed/check", "action": "bypass"},
  {"host": "admin.example.com", "path": "/api/managed/apply", "action": "bypass"}
]
```

- `path` does not end with `/`, so it matches only that path. The other `/api/managed` paths are inspected.
- A bypass route is part of a generation, so put the same routes into every generation of the default engine. If you choose a generation that lacks them, the bodies of `check` and `apply` are inspected from that generation on. When you change the default engine, put the same routes into a generation of the new default engine, choose that generation, and then change the default engine (for the steps, see "Choosing the Inspection Engine" in the [operator reference](operator-reference.md)).
- If a rule blocks a request to `check` or `apply` with 403 in a generation that has no bypass routes, the admin screens show "The proxy or the WAF refused the request. The WAF can block a request body that contains PEM files or many routes. Check that /api/managed/check and /api/managed/apply are excluded from inspection."

### Bypassing Inspection for the Import Route

The body of `POST /api/generations` (import) is a large JSON document that holds rule files. If it is inspected, the rules may block the import. Make this path a bypass route in the generations (see "Bypass Routes" in the [operator reference](operator-reference.md)).

```json
[
  {"host": "admin.example.com", "path": "/api/generations", "action": "bypass"}
]
```

- `path` does not end with `/`, so it matches only this path. `/api/generations/<fingerprint>` (reading and removing a generation) is inspected.
- A bypass route is part of a generation, so put the same route into every generation of the engine that inspects requests for the admin screens. That engine is the default engine in a configuration that has `managed`, and the engine of the upstream that forwards to the admin process in a configuration without `managed` (see "Access from Outside" above). If you choose a generation that lacks the route, imports are inspected from that generation on. When the inspecting engine changes (for example, when you change the default engine), move the same route into a generation of the new engine before you change the engine (see "Choosing the Inspection Engine" in the [operator reference](operator-reference.md)).
- This route takes effect only once the generation that holds it is in use, so import the first generation with this route from the command line (`rules import ... --routes <file>`). An import from the admin screens can also add it: write the host and the path in a row of the table (the body sent is JSON of the same form).

### CRS Tuning for the Admin Host

If the admin host is inspected with the CRS, the CRS's default settings block the following requests from the admin screens. Tuning that affects only the admin host lets both through, and the inspection of other hosts does not change.

- PUT and DELETE: the CRS allows only `GET`, `HEAD`, `POST`, and `OPTIONS` by default, and blocks other methods with rule 911100. The admin API uses PUT and DELETE to change passwords, to change roles and the enabled or disabled state, to disable two-factor authentication, and to remove API tokens and generations. Without the tuning, a new user cannot make the first password change, and so cannot finish logging in.
- Password fields: the CRS also inspects the values in a JSON body. Depending on the symbols it contains and their order, a correct password may be taken for SQL injection, and the login or password change is blocked (rule 942100 and others).

Put the two tunings into the generation of the engine that inspects the admin host. That engine is the default engine in a configuration that has `managed`, and the engine of the upstream that forwards to the admin process in a configuration without `managed` (see "Access from Outside" above). It has been tested with ModSecurity as the default engine and a generation that has the two tunings of this section: login, creating users and API tokens, `GET /api/status`, importing rules, and displaying the admin screens (Overview, Upstreams, Rule import) pass. PUT and DELETE have not been tested with ModSecurity, so try them before you choose the generation, as the last item of this section says.

Add the method tuning at the end of `crs-setup.conf` in the CRS directory, and then import the generation. It has no effect in the operator's rule files: they are loaded after the CRS rules (see "`rules`" in the [operator reference](operator-reference.md)), so the tuning would come after the method rule. When you use the CRS in an import from the admin screens, add it to `crs-setup.conf` in `admin.crs_dir`.

```text
SecRule REQUEST_HEADERS:Host "@rx ^admin\.example\.com(?::[0-9]{1,5})?$" \
    "id:1000100,phase:1,pass,nolog,t:none,t:lowercase,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT DELETE'"
```

Write the password field tuning in one of the operator's rule files, and pass it to the import with `--rules` ("Rule files" in the admin screens). It is a phase 1 rule, so even though it is loaded after the CRS, it takes effect before the CRS rules that inspect the body.

```text
SecRule REQUEST_HEADERS:Host "@rx ^admin\.example\.com(?::[0-9]{1,5})?$" \
    "id:1000101,phase:1,pass,nolog,t:none,t:lowercase,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:json.password,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:json.current,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:json.new"
```

- Replace `admin\.example\.com` with the host of `admin.origin`. Write `.` as `\.`.
- Only the three password fields (`password`, `current`, and `new`) are excluded from inspection. The name field, a token's name, the query, and so on are still inspected after the tuning. A name that looks like an attack is blocked, so use another name.
- Use a rule ID that does not overlap other rules (for the IDs that the inspector process uses, see "Settings and Rules Added by the Inspector" in the [operator reference](operator-reference.md)).
- Before you choose a generation that has the tuning, try PUT and DELETE to the admin host and a login with a password that has symbols. For a blocked request, search the logs for the request ID that the screen shows; its `rules` gives the rule ID.

### Body Size

- The request bodies of a rule import (`POST /api/generations`) and of the managed configuration's `POST /api/managed/check` and `POST /api/managed/apply` can be up to 12 MiB. Set `proxy.max_body` to 12 MiB (12582912) or more. The `max_body` of a route can only lower `proxy.max_body`, so to limit other routes, write a smaller `max_body` on those routes. The admin route (`admin.route`) has no `max_body`, so `proxy.max_body` is its limit.
- A long body on a bypass route is streamed without buffering, so a 12 MiB body does not use up `max_buffered_bytes` (see "Request Body Limits and Inspected Length" in the [operator reference](operator-reference.md)).
- If the request body of a check is over 12 MiB, or there are more than 192 files, the admin screens do not send it and show a message saying so. If the body is merely larger than `proxy.max_body` in the configuration file (read with `GET /api/config`), the screens send it and show "The request body is larger than proxy.max_body in the configuration file. It is refused if you connect through the proxy." together with the result of the check. For a 413 that the proxy returned because of the body limit, the screens show "The request body exceeded the proxy's limit (proxy.max_body)."

### Slow Responses and Timeouts

- An import, choosing a generation, and a rollback can take tens of seconds or more (for the time limit, see "Slow responses" under "Listener"). The proxy's time setting keys cannot be set per route. The wait for the response's header section ends when the first of `upstream_header_ms`, `response_idle_ms`, and `request_total_ms` runs out (see "`proxy`: Times" and "Relations Between Values" in the [operator reference](operator-reference.md)). For a request that streams its body (for example, an import on a bypass route), `response_idle_ms` has no effect until the header section of the response arrives.
- When the wait runs out, the proxy returns 502 to the client (503 for `request_total_ms`). The admin process carries on, and the import, choice, or rollback runs to the end; the proxy cutting the connection does not stop it.
- The admin screens treat a 502 or 504 whose body has no `result` as "Result unknown", and then, depending on the screen, read the state and the history, or the list of generations, again and show them. A response that has `result` (including a 502 with `failed`, and a 503 with `unreachable` or `unconfirmed`) is interpreted by that value. A 503 that has no `result` is taken as a refused change, so make `request_total_ms` comfortably longer than the time to receive the body plus the inspection time plus `upstream_header_ms`. When you use the API directly and get the same responses, check with `GET /api/status` and `GET /api/history` (for an import, `GET /api/generations`).
- Set the time setting keys after you measure how long imports and switches take. A longer `upstream_header_ms` also makes the proxy wait longer when another host's upstream is slow.

## Users and Roles

A user has a name, a role, and a password. A name is 1 to 32 bytes of lowercase letters, digits, `.`, `_`, and `-`. A password is 12 to 128 bytes of UTF-8 (each Japanese character takes 3 bytes). The password is stored as a PBKDF2-HMAC-SHA256 hash (600000 iterations, 16-byte salt).

| Role | What it can do |
|---|---|
| `viewer` | Can read the state, the list and contents of generations, the switch history, and the logs. For the managed configuration, can read the state, the list of versions, the apply jobs, and the configuration history. Can manage their own password, two-factor authentication, and API tokens |
| `operator` | Everything a viewer can do, plus reading the audit log, importing rules, choosing generations, rolling back, and removing generations. For the managed configuration, also reading the contents of versions, the certificate information, and the values in the configuration file, and checking, saving and applying, applying by name, rolling back, and removing |
| `owner` | Everything an operator can do, plus creating users, changing roles and the enabled or disabled state, resetting other users' passwords and two-factor authentication, and viewing and removing everyone's API tokens |

- Create the first owner with `admin bootstrap`. After that, an owner creates users with `POST /api/users`. Up to 1000 users can be created. When the number reaches 1000, creating a user is refused with 409 `the store has too many users`. Users cannot be removed, so disabled users also count toward the limit.
- There is no API to remove a user, so disable users who are no longer needed. A disabled user cannot log in, and their sessions and API tokens stop working. Even if you enable the user again, the API tokens that were deleted do not come back.
- A user created by an owner, or one whose password an owner set with `POST /api/users/<name>/password`, cannot use other APIs after the next login until they change the password to one of their own.
- The following operations by an owner on themselves, and operations that would leave no owner, are refused.
  - Lowering your own role, disabling yourself: 403
  - Resetting your own password and two-factor authentication: 403 (change them with the account API)
  - A change that would leave no enabled owner: 409
- Inside the admin process, user management operations run one at a time, in order, so two owners cannot lower each other's roles at the same time and leave no owner.
- A change of role or state (changing the role, disabling, enabling, setting the password, disabling two-factor authentication) ends that user's sessions. Lowering the role, disabling, and setting the password also invalidate the user's API tokens.
- A `PUT /api/users/<name>` that changes neither the role nor the enabled or disabled state changes nothing and returns that user with 200. It does not end sessions, and it is not written to the audit log.

## Login and Two-Factor Authentication

Login starts with `POST /api/login` (`{"name", "password"}`). `mfa` in the response shows the next step.

| `mfa` | Meaning | Next action |
|---|---|---|
| `off` | The session can be used | Use the API. If `must_change` is `true`, change the password |
| `verify` | A two-factor verification code is needed | `POST /api/login/mfa` |
| `setup` | `admin.mfa` is `required` and two-factor authentication is not set up | Set up two-factor authentication |

Which APIs a session can use depends on its state. An API that does not fit the state is refused with 403 and the fixed `error` shown below.

| State | Case | Usable APIs | `error` when refused |
|---|---|---|---|
| Waiting for a verification code | The password was correct, and the user has set up two-factor authentication. This state ends after 5 minutes | `POST /api/login/mfa`, `POST /api/logout` | `second factor required` |
| Waiting for a password change | A user created by an owner, or a user whose password was set by an owner or by `admin reset` | `PUT /api/account/password`, `GET /api/session`, `POST /api/logout` | `password change required` |
| Waiting for two-factor setup | A user for whom `admin.mfa` is `required` and two-factor authentication is not set up | `POST /api/account/mfa/setup`, `POST /api/account/mfa/confirm`, `GET /api/session`, `POST /api/logout` | `second factor setup required` |
| Normal | None of the above | All APIs that the role allows | |

- A session that is waiting for both a password change and two-factor setup can use the APIs of both states.
- `GET /api/session` returns the state (`state`: `active`, `must_change`, `mfa_setup`), the remaining time, and the number of remaining recovery codes. For a session that is waiting for a verification code, it returns 403.

Two-factor authentication (MFA):

- It uses time-based one-time passwords (RFC 6238) with HMAC-SHA1, 6 digits, and 30-second time windows. It also accepts the codes of the windows just before and just after the current one. It remembers the window of the code that was used, and rejects codes from that window and earlier windows.
- Setup:
  1. `POST /api/account/mfa/setup` (`{"password"}`) returns the secret (20 random bytes) as a base32 string (`secret`) and as an `otpauth://` address (`uri`). The secret is kept in the session's memory for only 10 minutes.
  2. `POST /api/account/mfa/confirm` (`{"code"}`) verifies the code from the authenticator app, enables two-factor authentication, and returns the recovery codes. This user's other sessions end, and a new session and a CSRF token are returned.
- Refusals: for a user who has already set up two-factor authentication, both starting and confirming the setup are refused with 409 `mfa is set already`. Confirming is also refused with 409 `mfa setup was not started or has run out` if the setup was not started or 10 minutes have passed, and a wrong code gets 403 `the code is wrong`.
- There are 10 recovery codes. Each code is 16 characters (uppercase `A` to `Z` and `2` to `7`) and can be used once. They are returned only once, at setup, and only their SHA-256 is kept in the store. To get new ones before you run out, disable two-factor authentication and set it up again. When `admin.mfa` is `required`, you cannot disable it yourself, so ask an owner to disable it with `DELETE /api/users/<name>/mfa` (an owner asks another owner, or uses `admin reset`).
- To verify a code at login, send either `{"code"}` (6 digits) or `{"recovery"}` (a recovery code, sent in uppercase) to `POST /api/login/mfa`. If it is correct, the session that was waiting for the code ends, and a new session (a new ID and a new CSRF token) is returned.
- Disabling: `DELETE /api/account/mfa` (`{"password", "code"}`; `code` is a verification code or a recovery code). When `admin.mfa` is `required`, it is refused with 403 `mfa is required`. An owner can disable other users' two-factor authentication with `DELETE /api/users/<name>/mfa`.
- With `required`, a user who has not set up two-factor authentication cannot use API tokens.
- The two-factor authentication secret is stored as is in the user's file, because calculating the verification code needs the secret itself. Protect it by making the store directory 0700.

## Lockout and Attempt Limits

| Target | Rule |
|---|---|
| Per user | After 5 failures in a row, the user is locked out for 15 minutes. An attempt during the lockout also counts as a failure and restarts the 15 minutes. A success resets the failure count |
| Per client | Up to 30 attempts per minute. An attempt over the limit is refused with 429 `too many tries` before any hash is calculated, and does not count as a failure for the user |

- These count as failures for the user: a wrong password at login, a wrong verification code at login (`POST /api/login/mfa`), a wrong verification code for disabling two-factor authentication, and a wrong password in an API that verifies the password (changing the password, setting up and disabling two-factor authentication, creating a token). A login by a disabled or locked-out user also counts as a failure for that user. For a user who has set up two-factor authentication, a correct password does not reset the failure count; a correct verification code does. This keeps someone who knows the password from resetting the failure count at every login and trying verification codes without end. A wrong code when confirming the two-factor setup (`POST /api/account/mfa/confirm`) does not count as a failure for the user or as an attempt for the client, and is not written to the audit log. The response is 403 `the code is wrong`.
- These count toward the client's attempts: a login, a verification code at login, an API that verifies the password (the same ones as above), and an API token that does not match. A request with a correct API token and confirming the two-factor setup are not counted. A login counts even when it succeeds. Once a client has used up its attempts, a request from it with an API token is refused with 429 `too many tries` before the token is verified, even if the token is correct.
- The admin process tracks up to 4096 clients. When the table is full of clients that tried within the last minute, it does not accept other clients.
- A login gets the same response (401 `invalid credentials`) for a name that does not exist, a disabled user, a locked-out user, and a wrong password. The hash is calculated once even for a name that does not exist or a locked-out user, so the response time does not tell them apart either. A wrong verification code at login also gets the same 401 `invalid credentials`. In other APIs the error is 403: for the password, `the password is wrong` (`the current password is wrong` for a password change), and for the verification code, `the code is wrong`.
- The reason is written only to the audit log (`unknown user`, `disabled`, `locked`, `wrong password`, `wrong code`). A name that does not exist is not written. This keeps a password typed into the name field out of the log.
- Each user's failure count and lockout state, and each client's attempt count, are kept only in the admin process's memory, and are lost when it restarts.
- When a user is changed (`admin reset`, an owner's operation, a password change, or setting up or disabling two-factor authentication), the lockout is released and counting starts again from the next failure.

## Sessions

- When a login succeeds, a session is created and the cookie `tukuyomi_admin` is returned. The cookie value is 43 characters: 32 random bytes in base64url.

  ```text
  Set-Cookie: tukuyomi_admin=<43-characters>; Secure; HttpOnly; SameSite=Strict; Path=/
  ```

  No expiry is set (the cookie disappears when the browser is closed). At logout, a cookie with `Max-Age=0` is returned to delete it.
- The admin process identifies a session by the SHA-256 of its ID and does not keep the ID itself. The audit log's `session` holds only the first 8 digits of that SHA-256.
- Each session has a CSRF token (another 32 random bytes, 43 characters). It is returned in the response to login and by `GET /api/session`.
- A session ends in these cases:
  - It was not used for `admin.session_idle_ms` (the count restarts at every request)
  - `admin.session_total_ms` has passed since it was created
  - The user logged out
  - The user's password, role, enabled or disabled state, or two-factor authentication was changed (including by `admin reset` or an operation of another admin process). When users change their own password or two-factor authentication, a new session is returned for that request and the other sessions end
  - The user was disabled
  - The admin process was restarted
- A user can have up to 16 sessions that are waiting for a verification code, and up to 16 normal sessions. When a 17th is created, the oldest one ends and `logout` (with `reason` `too many sessions`) is written to the audit log. Repeatedly entering the wait for a verification code does not end normal sessions. The admin process keeps up to 1024 sessions in all; when that is full, no new session can be created (login gets 503).
- A request carries either a session cookie or an API token, and one that has both gets 400. A request with a session cookie and an `Authorization` header also gets 400, even when the header is not Bearer, so if you put HTTP authentication such as Basic authentication in front of the admin screens, requests after login get 400. A request that has the cookie twice is treated as having no session and gets 401.

## CSRF and Origin

Requests other than `GET` and `HEAD` (requests that change something) are checked in two ways.

- `Origin`: if the header is present, there must be only one, and it must be exactly the same as `admin.origin`. Otherwise the request gets 403 `forbidden`. A request without an `Origin` header (a request from a program) passes. This check also applies to the login request.
- `X-CSRF-Token`: a request with a session must have exactly one, with the same value as that session's CSRF token (compared in constant time). If it differs or is missing, the request gets 403 `forbidden`. A request with an API token does not need it, because it does not use a cookie.

For the order of the checks, see "Order of Admin API Checks" under "Response Format".

- The admin screens keep the CSRF token only in memory and attach it to each request that changes something. When you reopen the page, they get the token again with `GET /api/session`. For a session that is waiting for a verification code, `GET /api/session` returns 403 and no CSRF token, so reopening the page takes you back to login.
- A request that was refused because of an `Origin` mismatch or a CSRF mismatch is written to the audit log when the user is known (`reason` is `origin` or `csrf`).

## API Tokens

API tokens let programs use the admin API.

- The form is `tkc_<16-hex-digits>_<43-characters>`. The first part is the token ID, and the last part is the secret (32 random bytes in base64url). The whole token is returned only once, when it is created. Only the SHA-256 of the secret is kept in the admin store.
- Send it as `Authorization: Bearer <token>`. It cannot be sent together with a session cookie (400).
- Creating: `POST /api/account/tokens` (`{"name", "role", "days", "password"}`). A user with a session creates tokens for themselves, and needs the current password.
  - `name`: 1 to 64 printable ASCII bytes
  - `role`: the user's own role or lower. A higher role is refused with 403 `the role is above the role of the user`.
  - `days`: 1 to 365. The token expires this many days after it is created.
  - One user can have up to 50 tokens (more is refused with 409 `the user has too many tokens`). Expired tokens count toward the 50. Expired tokens are not deleted automatically, so delete them with `DELETE /api/account/tokens/<id>`.
  - The response is the token's information (`id`, `owner`, `name`, `role`, `created`, `expires`, `expired`, `last_used`; the times are epoch milliseconds), plus `token` (the whole string).
- APIs it can use: status, generations, import, choosing, rollback, removal, history, logs, the audit log, the managed configuration, and the values of the configuration file (those with "yes" in the "Token" column of "API Paths" below). It cannot be used for the account APIs or the user management APIs (403). This keeps an owner's token from being used to reset another user's password or two-factor authentication and log in as that user.
- The request has the token's role (the owner's role or lower). A CSRF token is not needed. For a request that changes something, `Origin`, if present, must be the same as `admin.origin`.
- Every time it is used, these are checked:
  - The form is correct, the store has that ID, and the SHA-256 of the secret matches
  - The owner exists, is not disabled, and has a role equal to or higher than the token's role
  - The token was created after the owner's "tokens made before this time are invalid" time
  - The expiry has not passed
  - If `admin.mfa` is `required`, the owner has set up two-factor authentication
- It becomes invalid in these cases (even if the file cannot be deleted, it no longer passes the checks above):
  - It expired, or it was removed (`DELETE /api/account/tokens/<id>`; for an owner, `DELETE /api/tokens/<id>`)
  - The owner was disabled
  - The owner's role was lowered (all of the owner's tokens become invalid)
  - The owner's password was changed (by the owner, by an owner setting it, or by `admin reset`)
- A token that does not match counts toward the client's attempts (see "Lockout and Attempt Limits" above). It is not written to the audit log. This keeps anyone who can send requests from filling the audit log.
- The last-used time (`last_used`) is written at most once every 10 minutes. If it cannot be written, the request still passes.
- An example (with the token in `$TOKEN`):

  ```bash
  curl -sS -H "Authorization: Bearer $TOKEN" https://admin.example.com/api/status
  curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"generation":"<target-fingerprint>","expect":"<current-fingerprint>"}' \
    https://admin.example.com/api/activate
  ```

## Audit Log

The admin process records logins, changes, and refused requests as audit log lines.

| Field | Content |
|---|---|
| `ts`, `type` | The same as in the logs. `type` is `audit` |
| `id` | The request ID (`X-Request-ID`). Not present in lines from the commands (`admin bootstrap`, `admin reset`) |
| `actor` | The name of the verified user. Not present if the user could not be verified. It is not taken from the request headers |
| `session` | The first 8 digits of the SHA-256 of the session ID. The ID itself is not written |
| `auth` | The authentication method when it is not a session: `token:<id>`, `bootstrap`, `reset` |
| `client` | The client address. Not present in lines from the commands |
| `action` | The operation (the table below) |
| `target` | The target of the operation (a user's name, an API token's ID, a generation's fingerprint, or the name of a managed configuration version). Not present for a login with a name that does not exist |
| `result` | `ok`, `denied` (refused), `failed` (the operation was tried and failed) |
| `reason` | A fixed word (`wrong password`, `locked`, `expect`, `store`, and so on) |
| `before`, `after` | Before and after a change: the role, the enabled or disabled state, a generation's fingerprint, or the name of a managed configuration version |

Passwords, API tokens, verification codes, recovery codes, two-factor authentication secrets, and cookies are not written.

| `action` | Case |
|---|---|
| `login` | A successful login (`ok`) and a failed one (`denied`; `reason` is `unknown user`, `wrong password`, `locked`, `disabled`). When a session cannot be created (`failed`, `no session`). When the password of a user who has set up two-factor authentication is correct, `reason` is `second factor pending` |
| `mfa` | A verification code that succeeds or fails (`wrong code`, `locked`). A success with a recovery code has `reason` `recovery code` |
| `lock` | A lockout of a user (`reason` is `too many failures`) |
| `logout` | A logout. When a session was ended because there were too many, `reason` is `too many sessions` |
| `password`, `mfa_setup`, `mfa_confirm`, `mfa_disable` | A user's own password; starting and confirming the two-factor setup; disabling two-factor authentication. A wrong password or verification code is `denied` (`wrong password`, `wrong code`, `locked`), except that no line is written for a wrong verification code in `mfa_confirm` |
| `token_create`, `token_revoke` | Creating (`after` is the role) and removing an API token |
| `user_create`, `role`, `disable`, `enable`, `user_password`, `user_mfa` | User management by an owner |
| `import`, `activate`, `rollback`, `remove` | Generation operations (see "Generation Operations" below) |
| `managed-import` | In `POST /api/managed/apply` (the "Save and apply" operation), before the version is saved (see "Save and Apply" under "Managed Configuration Operations" below) |
| `managed-apply`, `managed-activate`, `managed-rollback` | The "Save and apply", "Apply by name", and "Roll back" operations of the managed configuration (see "Managed Configuration Operations" below) |
| `managed-remove` | Removing a managed configuration version |
| `create`, `reset` | The commands `admin bootstrap` and `admin reset` |
| `action` of each API | The name of an API that was refused; a `denied` line is written (see the note below). Besides the `action` values of the generation operations and the managed configuration above, the names are `status`, `generations`, `generation` (reading one generation), `history`, `records`, `audit`, `session`, `users`, `user_update` (`PUT /api/users/<name>`), `tokens`, `managed` (`GET /api/managed`), `managed-versions`, `managed-version` (reading one version), `managed-job`, `managed-history`, `managed-check`, `managed-certificates`, and `config` (`GET /api/config`) |

- A request refused by an API's checks gets a `denied` line if the user is known. `reason` is `origin`, `csrf`, `token` (an API that cannot use an API token), `role`, `state`, `second factor pending`, `password change`, or `second factor setup`.
- A request refused before the user is known is not written: for example, a request with neither a session nor an API token, an API token that does not match, a login over the client's attempt limit, a login with a wrong `Origin`, and a path that does not exist. This keeps anyone who can send requests from pushing the old lines out.
- A generation operation line has the target generation's fingerprint in `target`. An `ok` line for `activate` and `rollback` also has the previously chosen generation in `before` and the requested generation in `after`. An `ok` line is written before the change, so it does not show success; check how the operation ended from the `failed` line that follows it and from the switch history. The `reason` of `failed` is `expect`, `store`, `refused`, `failed`, `unconfirmed`, or `history` (the history line could not be written), and for an import, `store` and `trial`. When the operation was refused before the change, the line is `denied` and `reason` is `expect`, `engine`, `version` (a proxy that does not return the state of each engine), `busy`, or `unreachable`. For a removal, the `reason` is `chosen` for a chosen generation and `rollback target` for a rollback target.
- A managed configuration line has the target version's name in `target`. An `ok` line for `managed-apply`, `managed-activate`, and `managed-rollback` is written before the apply job asks the proxy, with the version before the change in `before` and the version after it in `after`. It does not show success either, so check how the operation ended from the lines that follow and from the configuration history.
  - When the operation was refused before the change, the line is `denied`, and `reason` is `managed`, `configuration`, `expect`, `unreachable`, `busy`, `unmanaged`, `engine` (in `managed-activate` and `managed-rollback`, when the rules store has no chosen generation for the engine of one of the version's upstreams), or a word for the apply job's result (`current changed`, `no version`, `store`).
  - When the operation failed after the pre-change line was written, the line is `failed`, and `reason` is a word for the apply job's result (`refused`, `busy`, `error`, `failed`, `unconfirmed`, `not recorded`) or `history` (the configuration history line could not be written). When the apply job could not be started, the line is also `failed`, and `reason` is `time`, `stopping`, or `thread`.
  - When `managed-import` fails, `reason` is `store`, `version`, or `configuration`. For a removal, a refusal is `managed`, `configuration`, `chosen` (the selected version), or `rollback target` (the rollback target), and a failure is `store`.
  - A check and the read-only APIs are not changes, so they write no line unless they are refused up front.

How it is written:

- The audit log line is written first, and only then is the change made. If the line cannot be written (for example, the disk is full), the change is not made and the request is refused with 503 `unavailable`. The line is synced to disk and then also written to standard error.
- The exception is logout: it takes authority away, so the session ends even if the line cannot be written.
- When a change fails, a `failed` line is written afterwards (the response does not change even if it cannot be written).
- The audit log is stored in `audit/audit.log` under `admin.store.dir`, one JSON object per line. When a file goes over 16 MiB, writing moves to the next file, and 8 files are kept (`audit.log` and `audit.1.log` to `audit.7.log`). The same lines are also written to standard error (the journal).
- `GET /api/audit` (operator or above, API tokens allowed) returns the newest 200 lines, newest first, as `{"entries": [...]}`. It reads from the end of the file, and reads the older files if it needs more. It reads at most the last 1 MiB of a file; if the file is larger than that, it stops there and does not read the older files. Lines that cannot be read are skipped.

## Generation Operations

A viewer can read the list and contents of generations. An operator or above can import, choose, roll back, and remove.

### Listing and Contents

- `GET /api/status`: returns the following.
  - `current`: the fingerprint of the generation that the rules store has chosen for the default engine (`null` if there is none)
  - `reachable`: whether the proxy can be reached. A proxy that cannot respond because it has reached its limit of concurrent connections is treated as reachable
  - `proxy`: the proxy's state (`generation`, `mode`, `engine`, `phase`, `switching`, `engines`, `reloading`, `ready`) and numbers (`uptime_ms`, `requests`, `blocked`, `policy_refused`, `upstream_failures`, `config`, `managed`, `resolve_timeout_ms`, `config_reloads`). It is the proxy's response as is, or `null` if it cannot be read. `generation`, `mode`, `engine`, and `phase` are the values the proxy reports for the default engine. `engines` is an array of `{"engine", "generation", "mode", "phase"}` for each engine running in the proxy (sorted by engine name), and `ready` is whether the state is one in which `/readyz` reports the proxy as ready. A proxy of an earlier version does not send `engines`, `reloading`, or the numbers, so anything not sent is `null` (the response is not refused). `reloading` is whether a configuration reload is in progress. The numbers are as follows; for details, see "Control Socket" in the [operator reference](operator-reference.md)
    - `uptime_ms`: milliseconds since the proxy started
    - `requests`: the number of requests (all 7 `class` values in the log)
    - `blocked`: the number of requests that rules blocked
    - `policy_refused`: the number of requests that the global `access` and `rate_limit`, and the host policies, refused
    - `upstream_failures`: the failure count of the upstream servers in the running configuration. It restarts from 0 when a configuration reload switches the configuration
    - `config`: the SHA-256 of the running configuration file (64 lowercase hexadecimal digits)
    - `managed`: the name of the running managed configuration version (64 lowercase hexadecimal digits). `null` for a configuration without `managed`
    - `resolve_timeout_ms`: `forward.resolve_timeout_ms` in the running configuration
    - `config_reloads`: the number of configuration reloads by SIGHUP and by the control socket's `reload`, as `{"replaced", "refused"}` (the number that switched the configuration and the number refused)
  - `rollback_to`: the generation that would be chosen if a rollback of the default engine were requested now (`null` if there is none)
  - `default_engine`: `kernel.default_engine` when the admin process started (`coraza` or `modsecurity`; `coraza` if it is not written). If only one of the admin process and the proxy was restarted, it may differ from `engine` in `proxy`
  - `engines`: an array of `{"engine", "current", "rollback_to"}` for each engine (in the order `coraza`, `modsecurity`): the generation that the rules store has chosen for that engine, and that engine's rollback target. `current` and `rollback_to` above are this array's values for the engine named in `default_engine`
  - `crs`: `{"available", "files"}`. Whether `admin.crs_dir` exists, and the names of the CRS `.conf` files that an import can leave out
- `GET /api/generations`: `{"reachable", "generations"}`. For each generation, newest first, it returns `fingerprint`, `made` (the time it was made, in seconds since the epoch), `mode` (`block`, `detect`, or `unknown` if the manifest cannot be read), `engine` (`coraza`, `modsecurity`, or `unknown` if the manifest cannot be read), `routes` (the number of bypass routes), `current` (whether the rules store has chosen it for any engine), and `serving` (whether it is running in the proxy for any engine).
- `GET /api/generations/<fingerprint>`: in addition to the above, it returns `load` (the load order) and `files` (`path`, `size`, `sha256`). `routes` here is an array of routes (`host`, `path`, `action`), not a number. If a route has no `host`, `host` is not present. A generation that is not in the rules store gives 404.

The "Chosen" generation and the "Running" generation are different things, and each engine has one of each. A generation chosen in the rules store is not running if the proxy failed to switch to it, or if its engine is not running. The admin screens show a warning when the two differ for any engine while no switch is in progress, or when a generation is chosen but that engine is not running.

### Import

`POST /api/generations` (operator or above, API tokens allowed) creates a generation in the same steps as `rules import`: it collects the files, puts them in the rules store temporarily, runs a trial with an inspector process, and, if the trial passes, makes them a generation. It does not choose the generation.

The body is a JSON object, and all keys are optional.

| Key | Content |
|---|---|
| `rules` | The rule files. An array of `{"name", "data"}`, loaded in the order written. `name` is a name without a directory (the same rule as `--rules`), and `data` is standard base64 (with padding) |
| `data` | The data files. The form is the same as `rules` (it corresponds to `--data`) |
| `crs` | `true` uses the CRS in `admin.crs_dir`. A request cannot give a path. If there is no `admin.crs_dir`, it gives 400 |
| `crs_off` | An array of names of CRS `.conf` files not to load (it corresponds to `--crs-off`) |
| `routes` | An array of bypass routes (the same form as a `--routes` file) |
| `engine` | The name of the inspection engine (it corresponds to `--engine`). `coraza` or `modsecurity` (lowercase). If omitted, the admin process's default engine (the same value as `default_engine` in `GET /api/status`) |
| `detect_only` | `true` makes a detect-only generation |
| `accept_block` | `true` keeps the import from failing even if a trial request is blocked |

- The limits and the rules for names are the same as for `rules import` (see "`rules`" in the [operator reference](operator-reference.md)). Up to 128 files, 2 MiB per file, and 8 MiB in all. A file over 2 MiB is refused before it is decoded.
- If `engine` is not the name of an engine, or if that engine cannot be used, it is refused with 400 before the files are collected: nothing is put in the rules store temporarily, and no trial is run. The message is one of these:
  - `engine is not the name of an engine (coraza or modsecurity)`
  - `kernel.engines has no inspector for the engine of the generation` (the configuration has no inspector process for that engine)
- The trial is the same as for `rules import`: the admin process starts one inspector process and inspects three fixed requests (`GET /`, a form `POST /`, and a JSON `POST /`). The inspector process is the one for the engine named in `engine` (`kernel.inspector` for `coraza`, `kernel.engines` for `modsecurity`). It uses the values in `kernel`, and `ready_wait_ms`, `inspect_wait_ms`, `stop_inspect_ms`, and `drive_slice_ms` in `proxy`.
- Inside the admin process, imports, choices, rollbacks, and removals run one at a time, in order. If another change is in progress, the request does not wait and gets 409 `a change of the rules is under way`. If a command or another process holds the rules store's lock, it gets 409 `the rules store is in use by another command`.

The response:

| Status code | Case | Body |
|---|---|---|
| 200 | A generation was created | `{"fingerprint", "result", "trial"}`. `result` is `created`, `existing` (the same generation was already there), or `repaired` (a damaged generation with the same fingerprint was made again) |
| 400 | The input was refused (including an engine that cannot be used) | `{"error"}`. If an input file's name applies, it is added as `subject` (bytes outside 0x20 to 0x7e are written as `\xNN`, up to 128 bytes) |
| 409 | Refused by the rules store, or another change is in progress | `{"error"}` |
| 422 | The trial failed. No generation is created | `{"error": "the trial failed", "trial": {..}}` |
| 500 | The trial could not be run | `{"error"}` |
| 503 | The audit log line could not be written | `{"error": "unavailable"}` |

`trial` is `{"passed": true, "accepted": [..]}` when it passed and `{"passed": false, "failure": <message>}` when it failed. If there is output from the inspector process, `detail` (up to 512 bytes) is added, whatever the value of `passed`. Even if all trial requests passed, if the inspector process or the work directory was not cleaned up, `passed` is `false`, `failure` is `the inspector did not stop cleanly; a process or a directory may be left behind`, the response is 422, and no generation is created. In that case, check that no process or directory is left behind on the host. `accepted` lists the blocks (`{"kind": "block", "probe", "rule", "phase", "status"}`) and detections (`{"kind": "detected", "probe", "rule", "status"}`) that the trial accepted. `probe` is the name of the trial request (`GET /`, `POST / with a urlencoded body`, `POST / with a JSON body`).

### Choosing and Rolling Back

`POST /api/activate` (`{"generation", "expect"}`) and `POST /api/rollback` (`{"engine", "expect"}`; `engine` is optional) change the generation chosen in the rules store and tell the proxy to switch. They need an operator or above, and API tokens can be used. Each switch is for one engine: for `activate`, the generation's engine, and for `rollback`, the engine in `engine` (the admin process's default engine if omitted). Each engine has its own chosen generation and rollback target (see "Chosen Generation per Engine" in the [operator reference](operator-reference.md)).

- A fingerprint is 64 lowercase hexadecimal digits. If not, it gives 400 `a generation is not 64 lowercase hexadecimal digits`.
- If `engine` of `rollback` is not lowercase `coraza` or `modsecurity`, it gives 400 `engine is not the name of an engine (coraza or modsecurity)`.
- `expect` is the "Chosen generation" for that engine, as you saw it on the screen. If someone else or a command has chosen again since you saw the screen, the request is refused with 409, so that choosing again from an old screen does not overwrite that choice.
  - For `activate`, `expect` is the generation chosen for the engine of the generation in `generation`. If no generation is chosen for that engine, write `null`. If you write `null` while a generation is chosen, it is refused with 409.
  - Always write the `expect` key for `activate`; if you omit it, the request gets 400. For `rollback`, `expect` is a 64-character string.
- If no generation is chosen for that engine, you can choose one with `expect` set to `null`. The screen also lets you choose a generation of an engine that has no chosen generation. The proxy needs the default engine's first generation to start, so choose that one with the command (`rules activate`) (see "Choosing the Inspection Engine" in the [operator reference](operator-reference.md)).
- If `generation` is the generation chosen now, the rules store's chosen generation does not change, and only the proxy is told to switch ("Apply to the proxy" in the admin screens). If that engine is not running in the proxy, the engine is started ("Start the engine" in the admin screens). When you give a generation that is not chosen yet, an engine that is not running in the proxy is likewise started with that generation. `rollback` also starts the engine with the rollback target if that engine is not running in the proxy.

Steps:

1. For `activate`, the admin process checks that the generation is in the rules store (if not, 404 `no such generation`). For a rollback, it decides the rollback target (below).
2. It checks that the generation chosen for that engine in the rules store is the same as `expect` (or, if no generation is chosen, that `expect` is `null`). If not, the result is 409: nothing is changed or written to the history, and the audit log gets `denied` with `reason` `expect`.
3. It checks that the engine of the generation to switch to can be used. If not, the result is 409 with `{"error": <message>}`: nothing is changed or written to the history, and the audit log gets `denied` with `reason` `engine`. The message is the same as `kernel.engines has no inspector for the engine of the generation` in the 400 of "Import" above. A generation whose manifest cannot be read is not refused here; it is refused when the rules store chooses the generation.
4. It asks for the proxy's state.
   - The proxy cannot be reached: 503 `the proxy cannot be reached`. The rules store is not changed, and `unreachable` is written to the history (the audit log also gets `denied` with `reason` `unreachable`).
   - The proxy accepts the connection and closes it without responding (the limit of concurrent connections): 503 `the proxy is busy`. The rules store is not changed, and nothing is written to the history (the audit log gets `denied` with `reason` `busy`).
   - The state has no `engines` (an earlier version of the proxy that does not support choosing per engine): 409 `the proxy does not report its engines`. The rules store is not changed, and nothing is written to the history (the audit log gets `denied` with `reason` `version`). Use the same build for the admin process and the proxy (see "Version Updates" in the [operator reference](operator-reference.md)).
5. It writes an audit log line (if it cannot, 503 `unavailable`, and nothing is changed).
6. It chooses the generation in the rules store. The choice is made inside the lock, and `expect` is verified once more. If another process chose in the meantime, that choice is not overwritten, and the result is 409.
7. It asks the proxy to switch, and waits for the switch to end (see "Control Socket" above).
8. It writes one line to the history and returns the response.

The response (the body is `{"result", "engine", "from", "generation", "chosen"}`; a failure also has `error`):

| `result` | Status code | Meaning | `chosen` |
|---|---|---|---|
| `switched` | 200 | The proxy now uses that generation | `true` |
| `unchanged` | 200 | The proxy was already using that generation | `true` |
| `refused` | 409 | The proxy refused (`the proxy refused the switch`). This includes the case where the proxy found that `expect` did not match | `true` |
| `failed` | 502 | The proxy did not switch (`the proxy did not switch`). This includes the case where it did not switch in time | `true` |
| `unreachable` | 503 | The proxy cannot be reached. The rules store was not changed | `false` |
| `unconfirmed` | 503 | The rules store was changed, but the proxy did not report the result (`the proxy did not say how the switch ended`) | `true` |

- `chosen` shows whether that generation is now chosen in the rules store.
- Even if the switch ends in `refused`, `failed`, or `unconfirmed`, the rules store is not changed back. With `refused` and `failed`, the proxy keeps using the previous generation. With `unconfirmed`, which generation the proxy is using is not known, so check that engine's `generation` in `proxy.engines` of `GET /api/status`. When the proxy restarts, each engine starts with the generation chosen in the rules store, so if you do not want to use that generation, choose the previous one again.
- If a line could not be written to the history, `"history": "not written"` is added to the response.
- Only the six cases in the table above have `result` and `chosen`. Other failures have only `{"error": <message>}` as the body. They are: the 409 where `expect` does not match (`the chosen generation is not the one that was expected`), the 503 `the proxy is busy`, the 409 where the rollback target cannot be decided, the 409 where the engine of the generation cannot be used, the 409 for a proxy that does not return the state of each engine, and the 409 where the choice was refused by the rules store itself. Of these, a line (`refused`) is written to the history only when the rules store itself refused the choice.

The rollback target:

- It is the `from` of the newest history line that is for that engine, has the result `switched`, and has different `from` and `to`. A line without `engine` (written by an earlier version of the admin process) counts as a line for that engine only when the generations in `from` and `to` both belong to that engine (it does not count if a generation's engine cannot be read).
- It works only when the `to` of that line is the generation that the rules store has chosen now for that engine. After a failed switch, or after a generation was chosen with a command, the end of the history does not match the chosen generation, so no rollback is possible (409 `the history does not end at the chosen generation`). If there is no `switched` line, it gives 409 `there is no switch to go back from`.
- If the generation to go back to is not in the rules store, it gives 409 `the generation to go back to is not in the store`.
- A rollback is also recorded in the history, as `rollback`, so rolling back again right after returns to the original generation.

### Removal

`DELETE /api/generations/<fingerprint>` (operator or above, API tokens allowed) removes a generation from the rules store. This cannot be undone. Removing the following generations is refused with 409.

| Generation | `error` |
|---|---|
| The generation that the rules store has chosen (for any engine) | `the generation is the one the rules store chooses` |
| A generation that is a rollback target (for any engine) | `the generation is the target of a rollback` |
| A generation that is running in the proxy (for any engine) | `the generation is used by a running proxy` |

A generation that is not in the rules store gives 404. If another change is in progress, it is refused with 409 `a change of the rules is under way` (inside this admin process) or `the rules store is in use by another command` (a command or another process holds the rules store's lock). If a command chose a generation after the removal check, it gives 409 `the generation is the current one`. On success, it returns `{"removed": <fingerprint>}`.

## Managed Configuration Operations

The managed configuration is kept as versions in a managed store, separate from the configuration file, and is changed from the admin screens and the admin API. It covers the sites and certificates, the upstreams, the routes, the default upstream, the global access control and rate limits, and the host policies. For whether to use the managed configuration, the form of the managed store and versions, the commands, and the order in which a version is applied, see "Managed Configuration" in the [operator reference](operator-reference.md). This section describes the admin API operations.

- A viewer can read the state, the list of versions, the apply jobs, and the configuration history. An operator or above can read the contents of a version, the certificate information, and the values in the configuration file, and can check, save and apply, apply by name, roll back, and remove. All of these can be used with API tokens.
- Version contents and configuration file values are limited to an operator or above because a route's rewrite (`rewrite`) can hold a secret, such as a credential for the upstream.
- These APIs can be used only if the configuration file had `managed` when the admin process started. If it did not, `GET /api/managed` returns `{"managed": false}`, `GET /api/config` works as it does with `managed`, and the other APIs are refused with 409 `the configuration has no managed object`.
- The admin process uses the managed store that `managed.dir` pointed to when it started, and opens it at every request. If the store cannot be opened, the response is 500 with the managed store's message. A check or a change reads the configuration file again, and if `managed.dir` differs from its value at start, the request is refused with 409 `the managed object of the configuration names another directory than at the start`. If you add or remove `managed`, or change `managed.dir`, restart the admin process.

### State and Listing

- `GET /api/managed`: returns the following.
  - `managed`: `true`
  - `current`: the version that the managed store has selected (`null` if there is none)
  - `serving`: the running version, as reported by the proxy on the control socket (`null` if the state cannot be read, or if the proxy is running with a configuration without `managed`)
  - `reachable`: whether the proxy can be reached. A proxy that cannot answer a query because it has reached its limit of concurrent connections is treated as reachable
  - `reloading`: whether the proxy is reloading the configuration (`null` if not known)
  - `rollback_to`: the version that would be applied if a rollback were requested now (`null` if there is none; see "Applying and Rolling Back by Name" below)
  - `job`: the last apply job (`null` if there is none; see "Apply Jobs" below)

  If the configuration history cannot be read, it gives 503.
- `GET /api/managed/versions`: `{"reachable", "versions"}`. For each version, newest first, it returns `name` (the version's name: its SHA-256 as 64 lowercase hexadecimal digits), `made` (the modification time of the version's file, in seconds since the epoch), `current` (whether it is selected), and `serving` (whether it is running).
- `GET /api/managed/versions/<version>` (operator or above): in addition to the above four, it returns `version` (the version's JSON, exactly as it is in the managed store). A version specifies files only by SHA-256, and no response contains file contents. A version that is not in the managed store gives 404, and a version whose contents do not match its name gives 500.

The "Selected" version and the "Running" version are different things. They may differ after an apply stopped halfway, or after a version was selected with a command. Applying either version again makes them the same. When they differ, the admin screens show a notice and two ways to make them the same (see "Admin Screens" below).

### Certificate Information

`GET /api/managed/certificates/<version>` (operator or above) returns the state of the certificates in the managed store for each site of the version, in the version's order. The response is `{"name", "sites"}`, and each site has the following keys.

| Key | Content |
|---|---|
| `name` | The name of the site |
| `kind` | `files` (certificate chain and private key files) or `acme`. `null` if it is in neither form |
| `chain`, `key` | For a `files` site, the names (SHA-256) of the certificate chain and private key files. The contents are not returned |
| `hosts` | The hosts of an `acme` site. Only when it is in a readable form |
| `state` | The table below |
| `not_after`, `expired` | The expiry of the first certificate in the certificate chain (in seconds since the epoch), and whether it has expired by the server's clock. Only when the expiry could be read |
| `names`, `more` | The host names in the certificate (DNS names, up to 100) and the number of other names. Only when the names could also be read. `[]` means that the certificate has no DNS name |

`state` is the first of the following that matches.

| `state` | Meaning |
|---|---|
| `unreadable` | The certificate chain or private key file cannot be read (a symbolic link, not a regular file of 1 MiB or less, a `files` site whose contents do not match the name, and so on). This is also the state of a certificate in neither form |
| `missing` | For a `files` site, the certificate chain or private key file is not in the managed store |
| `waiting` | For an `acme` site, it has not been issued yet (the certificate chain or private key that `acme renew` writes is missing) |
| `unparsed` | The names or the expiry cannot be read from the first certificate in the certificate chain |
| `present` | For a `files` site, the certificate chain can be read and the private key file exists |
| `issued` | For an `acme` site, the certificate chain can be read and the private key file exists |

- The response shows the certificates on disk, not the certificates in the proxy's memory. After `acme renew`, the two differ until the proxy reads the certificates again (SIGUSR2). The version does not have to be the running one.
- `present` and `issued` show only that the files exist and that the certificate chain can be read. They do not verify what the private key contains, whether the certificate chain and the private key are a pair, or whether the certificate includes the site's hosts. The proxy may still refuse a version in which every site is `present`.
- The proxy does not check certificate expiry, and uses an expired certificate as is. The validation in `check` and `apply` does not check expiry either.
- This API does not take the right to run a change or a lock, does not ask the proxy, and does not write to the audit log.

### Configuration File Values

`GET /api/config` (operator or above) returns the current values in the configuration file. It works whether or not the configuration file has `managed`.

- It reads the configuration file again at every request, and responds only when the file passes all of the configuration file validation. If the file cannot be read or is rejected, it responds with 409 and a fixed message.
- The response is `{"sha256", "managed", ...}`. `sha256` is the SHA-256 of the file (the value that appears in `proxy.config` of `/api/status` once the proxy has read it), `managed` is whether the configuration file has `managed`, and the rest are the configuration file's setting keys, with the same names and form as in the file.
- It returns only the setting keys on a fixed list. Path values (certificates, private keys, CA files, directories, inspector processes, sockets, database files) are returned as `true` if they are written and `null` if not; the path strings themselves are not returned.
- It is limited to an operator or above because a route's rewrite can hold a secret, and because the response includes server and listener addresses.

### Check

`POST /api/managed/check` (operator or above) validates a version in the same way as `POST /api/managed/apply` and saves nothing. It lets the screen show errors next to their fields before anything is saved.

- The body is `{"version", "files", "expect"}`, in the same form as for `POST /api/managed/apply` (see "Save and Apply" below). `expect` is optional, and its form is not validated even if it is present.
- Steps (the response comes from the first stage that refuses):
  1. It takes the validation slot. If another request holds it, 503 `a check of a managed version is under way`. If `managed` was absent when the admin process started, 409 at once.
  2. It validates the form of the body, the files, and the version. A refusal is 400 (a message and a location).
  3. It reads the configuration file again. If the file has no `managed`, if `managed.dir` differs from its value at start, or if the file is rejected, 409.
  4. It opens the managed store. If the store cannot be opened, 500.
  5. It validates the version and the files against the configuration file, the files in the request, and the files in the managed store. A refusal is 400 (a message and a location). It is also 400 when the rules store has no chosen generation for the engine of one of the version's upstreams (the message is `no generation is chosen for the engine of an upstream`, and `at` is `upstreams.<name>.engine` of the first such upstream). If the rules store cannot be read, 500.
- The response is 200 `{"version", "detect"}`. `version` is the name the version would have if it were saved. `detect` lists, as `[{"upstream", "engine"}, ..]`, the upstreams inspected by an engine whose chosen generation is detect-only (in upstream order; `[]` if there are none). For those upstreams, even a request that matches a rule is not blocked.
- It does not take the right to run a change, does not ask the proxy, puts nothing in the managed store, and does not write to the audit log. It works even with a managed store that has no selected version (before the first version is created with a command).
- The validation slot: inside the admin process, only one version validation by `check` or `apply` runs at a time, because it reads the 12 MiB body and the managed store's files again and uses a lot of memory.

### Save and Apply

`POST /api/managed/apply` (operator or above) saves a version in the managed store and applies it to the running proxy. The body is a JSON object, and all three keys are required.

| Key | Content |
|---|---|
| `expect` | The selected version that you saw on the screen (64 lowercase hexadecimal digits) |
| `version` | The version to save, in the managed store's version form (files are specified by SHA-256 and have no path); how it is formatted does not matter. It is saved in one fixed format, and the SHA-256 of the saved form is the version's name |
| `files` | An array of the files to save with the version (PEM strings of the certificate chain, the private key, and the CA files) |

- `files` can hold up to 192 files, each up to 1 MiB. The same file cannot be sent twice, and every file must be one that the version specifies. A file that the version specifies but the request does not include must already be in the managed store.
- The contents of the files are not written to the response, the audit log, or the configuration history.

Steps (the response comes from the first stage that refuses):

1. It takes the validation slot. If another request holds it, 503. This is not written to the audit log.
2. It validates the body: 400 if the JSON form is wrong, if there are too many files or a file is too large, if the version's form is wrong (a repeated setting key, an unknown setting key, a missing setting key, a type mismatch), or if `expect` is not 64 lowercase hexadecimal digits. This is not written to the audit log.
3. It takes the right to run a change, reads the configuration file again, checks the managed store and `expect`, and asks for the proxy's state (the same as 1 to 4 of "Applying and Rolling Back by Name" below). If the proxy cannot accept the version, nothing is saved.
4. It validates the version against the configuration file and the files (the same validation as `managed import`; the country database is not loaded here, and the proxy loads it when it applies the version). It also checks that the rules store has a chosen generation for the engine of each of the version's upstreams (the same as step 5 of "Check"). A refusal is 400 (a message and a location), and is not written to the audit log.
5. It writes a `managed-import` line (the target is the version's name) to the audit log. If it cannot, 503, and nothing is saved.
6. It places the files and the version in the managed store, inside the store's lock. If a command holds the lock, 409 `the managed store is in use by another command`; the managed store's other refusals are also 409. If the version, read together with the files in the managed store, is refused, 400 (no location); if the configuration file is refused, 409. In every case, a failure (`store`, `version`, `configuration`) is written to the audit log.
7. It starts the apply job (step 6 of "Applying and Rolling Back by Name" below). If the apply job cannot be started, the saved version stays in the managed store, which does no harm.

The response is 202, and has `version` (the version's name), `placed` (the result of saving: `created`, `existing` if the same version was already there, or `recreated` if a damaged copy was replaced), and `job` (the apply job that was started).

### Applying and Rolling Back by Name

`POST /api/managed/activate` (`{"expect", "version"}`) applies a version in the managed store, given by name, to the running proxy, and `POST /api/managed/rollback` (`{"expect"}`) applies the rollback target version to it. They need an operator or above, and API tokens can also be used.

- `expect` and `version` are 64 lowercase hexadecimal digits. If not, it gives 400 `a version is not 64 lowercase hexadecimal digits`.
- `expect` is the selected version that you saw on the screen. If another user or a command has selected again since you saw the screen, the request is refused with 409, so that an old screen does not overwrite that selection.
- In a managed store that has no selected version, nothing can be applied because `expect` does not match. Create and select the first version with commands (`managed import` and `managed activate`) (see "First Start with the Managed Configuration" in the [operator reference](operator-reference.md)).

Steps (step 3 of "Save and Apply" above runs the same checks; the response comes from the first stage that refuses):

1. It takes the right to run a change. Inside the admin process, changes run one at a time, each until its apply job ends. If another change (including removing a version) is in progress, 409 `a change of the managed configuration is under way`; if the admin process is stopping, 503. This is not written to the audit log.
2. It reads the configuration file again. If the file has no `managed` (including when there was none when the admin process started), if `managed.dir` differs from its value at start, or if the file is rejected, 409, and a refusal (`managed`, `configuration`) is written to the audit log.
3. It checks the managed store. If the store cannot be opened, or if the file that records the selected version (`current`) cannot be read, 500. If the selected version is not `expect` (including when there is none), 409 `the chosen managed version is not the one that was expected` (a refusal, `expect`, in the audit log). For a rollback, it decides the rollback target here. If there is none, 409, and if the configuration history cannot be read, 503 (neither is written to the audit log).
4. It asks for the proxy's state on the control socket.
   - The proxy cannot be reached: 503 `the proxy cannot be reached`. An `unreachable` line is written to the configuration history (a refusal, `unreachable`, in the audit log).
   - The proxy accepts the connection and closes it without responding (the limit of concurrent connections): 503 `the proxy is busy` (a refusal, `busy`, in the audit log).
   - The running configuration has no `managed`: 409 `the configuration in force has no managed object` (a refusal, `unmanaged`, in the audit log).
5. For apply by name and rollback, it checks that the version is in the managed store. If not, apply by name gives 404, and rollback gives 409 `the version to go back to is not in the store`. If it is, it checks that the rules store has a chosen generation for the engine of each of the version's upstreams. If not, 409 `no generation is chosen for the engine of an upstream` with `at` (`upstreams.<name>.engine` of the first such upstream), and a refusal (`engine`) is written to the audit log. If the rules store cannot be read, 500. `POST /api/managed/apply` saves the version at this stage (4 to 6 of "Save and Apply" above).
6. It starts the apply job. If 5 seconds or less are left of the response time (30 seconds), or if the admin process began to stop after step 1, 503 (a failure, `time`, `stopping`, in the audit log). If a thread cannot be created, 503 (a failure, `thread`, in the audit log).

The response is 202, and has `version` (the version to apply) and `job`.

The rollback target:

- It is the `from` of the newest line in the configuration history whose result is `applied` and whose `from` and `to` differ.
- It works only when the `to` of that line is the version selected now. After an apply that did not end in `applied`, or after a version was selected with a command, the end of the history does not match the selected version, so no rollback is possible (409 `the history does not end at the chosen version`). If there is no `applied` line, it gives 409 `there is no change to go back from`.
- A rollback is also recorded in the history, as `rollback`, so rolling back again right after returns to the original version.

### Apply Jobs

A change ("Save and apply", "Apply by name", "Roll back") gets the 202 response as soon as it has passed the stages above, and the apply continues inside the admin process as an apply job (`job`), because an apply may take longer than one response can wait. You can see how it ended with `GET /api/managed/job` (viewer or above; `{"job"}`, or `null` if there is none) or with `job` of `GET /api/managed`.

- The admin process keeps only the last apply job, and only in memory, so it is lost when the admin process restarts. A running apply job ends with the admin process, and the managed store's lock is released with the process.
- An apply job cannot be cancelled. It does not stop even if the requesting user's role changes.
- An apply job holds the right to run a change until it ends. Until then, other changes and removing versions get 409.
- For the order of an apply (the managed store's lock, the reload request to the proxy, and when the selected version is moved forward) and what happens when it stops halfway, see "Applying" in the [operator reference](operator-reference.md). For how long the admin process waits on the control socket, see "Control Socket" above.

| Key | Content |
|---|---|
| `kind` | `apply` (Save and apply), `activate` (apply by name), `rollback` |
| `actor` | The name of the user who requested it |
| `from`, `to` | The version before the change (`expect`) and the version after it |
| `started`, `ended` | When it started and when it ended (in seconds since the epoch). While it is running, `ended` is `null` |
| `state` | `running` (applying) or `ended` |
| `result` | How it ended (the table below). While it is running, `null` |
| `reason` | A fixed word. The part that the proxy refused (`configuration`, `version`, `store`, `upstream`, `tls`, `fixed`, `listener`, `thread`), the reasons for `busy` (`store in use`, `proxy busy`, `reload under way`, `starting`, `too many orders`, `stopping`), the reasons for `error`, and the reasons for `not recorded` (`current changed`, `store`) |
| `detail` | The message from the proxy that refused, or from the managed store |
| `config_before`, `config_after` | The SHA-256 of the configuration file that was in use before and after the apply. Only when known |
| `history` | Whether a line was written to the configuration history. `null` for an outcome that writes no line |

| `result` | Meaning | Audit log | Configuration history |
|---|---|---|---|
| `applied` | The proxy runs the new version, and the managed store has selected it | The `ok` line written before the change | A line is written |
| `refused` | The proxy refused. Nothing was changed | A failure | A line is written |
| `busy` | The managed store or the proxy was in use. Nothing was changed | A refusal if it happened before the pre-change line was written, a failure if after | A line is written if after |
| `current changed` | The selected version was no longer `expect` | A refusal | Not written |
| `no version` | The version is not in the managed store | A refusal | Not written |
| `unmanaged` | The configuration of the running proxy has no `managed` | A refusal | Not written |
| `store` | The managed store's lock could not be taken, the file that records the selected version (`current`) is missing or cannot be read, and so on | A refusal | Not written |
| `audit` | The pre-change audit log line could not be written. Nothing was changed | − | Not written |
| `error` | The proxy did not accept the request (`unknown op` means an old proxy that does not support the control socket's `reload`) | A failure | A line is written |
| `unreachable` | The proxy could not be reached | A refusal | A line is written |
| `failed` | The proxy did not switch to the new version | A failure | A line is written |
| `unconfirmed` | The result could not be confirmed | A failure | A line is written |
| `not recorded` | The proxy switched to the new version, but the managed store did not select it (`current changed`: the selected version was changed by hand; `store`: the file that records the selected version (`current`) cannot be written) | A failure | A line is written |

- The `reason` of `refused` is `fixed` when a setting key that cannot change while running differs (`detail` is `<key> cannot change while running`), and when the engine of one of the version's upstreams is not running in the proxy (including while it is starting; `detail` is `the engine of an upstream is not ready (upstream <name>)`). First start the engine that is not running (with "Start the engine" on the Rule generations screen, or with SIGUSR1; see "Chosen Generation per Engine" in the [operator reference](operator-reference.md)), and then apply again.
- The audit log's `ok` line is written before the change (`from` and `to` go into `before` and `after`; the configuration file's SHA-256 goes into the configuration history, not the audit log). It does not show success, so check how the operation ended from the lines that follow and from the configuration history.
- If a line could not be written to the configuration history, a failure (`history`) is written to the audit log.
- If an apply job ends abnormally partway, its result is `unconfirmed`, and the admin process writes one line to its log.
- After `unconfirmed` and `not recorded`, the selected version and the running version may differ. Check `current` and `serving` in `GET /api/managed`, and if they differ, apply either version again.

### Removing Versions

`DELETE /api/managed/versions/<version>` (operator or above, API tokens allowed, no body) removes a version from the managed store. This cannot be undone. It also cleans up the files and ACME certificates that no version specifies any more (for what the cleanup removes, see "Removing Versions" in the [operator reference](operator-reference.md)).

Steps (the response comes from the first stage that refuses):

1. If the name is not 64 lowercase hexadecimal digits, 404.
2. It takes the right to run a change (an apply job also holds it). If another change is in progress, 409, and if the admin process is stopping, 503. This is not written to the audit log.
3. It reads the configuration file again. If the file has no `managed`, if `managed.dir` differs from its value at start, or if the file is rejected, 409 (a refusal, `managed`, `configuration`, in the audit log).
4. If the managed store cannot be opened, 500.
5. A version that is not listed in the managed store gives 404.
6. The selected version is not removed (409, a refusal, `chosen`, in the audit log).
7. The rollback target version is not removed (409, a refusal, `rollback target`, in the audit log). If the configuration history cannot be read, 503.
8. It writes a `managed-remove` line (the target is the version's name) to the audit log. If it cannot, 503, and nothing is removed.
9. It removes the version from the managed store. A refusal is 409 with the managed store's message (a failure, `store`, in the audit log).

| Version | `error` |
|---|---|
| The selected version | `the version is the one the managed store chooses` |
| The rollback target version | `the version is the target of a rollback` |
| A version in use (for which versions are in use, see "Removing Versions" in the [operator reference](operator-reference.md)) | `the managed version is in use` |

- On success, it returns 200 `{"removed", "cleaned"}`. `removed` is the name of the removed version, and `cleaned` is a boolean that says whether the cleanup finished. If `cleaned` is `false`, the cleanup could not finish (for example, another version could not be read). The removal still stands, and the cleanup is tried again at the next removal.
- It does not ask the proxy. A version in use is refused by the managed store.
- A removal reads the other versions one by one, so it takes longer when there are more versions. If the response does not come in time, the request gets 503, but the removal may still complete.
- It writes no line to the configuration history. Lines that name the removed version remain.

## Switch History

`GET /api/history` (viewer or above, API tokens allowed) returns the history of generation choices and rollbacks, newest first, up to 200 lines, as `{"entries": [...]}`.

| Field | Content |
|---|---|
| `ts` | The time (UTC, RFC 3339, to the millisecond) |
| `actor` | The name of the user who requested the switch |
| `from` | The generation that the rules store had chosen before the request, for the engine that the generation in `to` belongs to (the same as `to` if there was none) |
| `to` | The generation that was requested (the rollback target for a rollback) |
| `kind` | `activate`, `rollback` |
| `result` | A word for the result (see the note below) |
| `engine` | The engine of the generation in `to` (`coraza` or `modsecurity`). `null` for a line written by an earlier version of the admin process |

`result` takes the same six values as `result` in the response described in "Choosing and Rolling Back" (`switched`, `unchanged`, `refused`, `failed`, `unreachable`, `unconfirmed`), with the same meanings.

- The history is appended to `activations.log` in `admin.store.dir`, one file for all engines. Each line is synced after it is written, and then the response is returned. The file is not rotated or deleted. Only the last 1 MiB (about 4000 lines) is read back, and older lines are not used for deciding the rollback target either.
- Only switches requested through the admin screens and the admin API are recorded. Choices and switches made with the command (`rules activate`) or with SIGUSR1 are not recorded.
- A line is written to the history only when the proxy could not be reached, and for the outcomes after the audit log line was written (the rules store refusing the choice, and the proxy's response). No line is written for an input error, a generation that does not exist, a rollback target that cannot be decided, another change in progress, an old `expect`, a proxy that did not answer the state query because of its limit of concurrent connections, or an audit log line that could not be written.

## Configuration History

`GET /api/managed/history` (viewer or above, API tokens allowed) returns the history of managed configuration changes ("Save and apply", "Apply by name", "Roll back"), newest first, up to 200 lines, as `{"entries": [...]}`.

| Field | Content |
|---|---|
| `ts` | The time (UTC, RFC 3339, to the millisecond) |
| `actor` | The name of the user who requested the change |
| `kind` | `apply`, `activate`, `rollback` |
| `from` | The version that the managed store had selected at the time of the request |
| `to` | The version that was requested (the rollback target for a rollback) |
| `result` | A word for the result (see the note below) |
| `reason` | A fixed word. `null` if there is none |
| `config_before`, `config_after` | The SHA-256 of the configuration file in use before and after the apply. `null` if not known |

`result` is one of these eight: `applied`, `refused`, `busy`, `error`, `failed`, `unconfirmed`, `not recorded`, `unreachable`. The meanings are the same as in the table in "Apply Jobs" under "Managed Configuration Operations". `reason` also uses the same words as the apply job's `reason`.

- The history is appended to `managed.log` in `admin.store.dir`, one JSON object per line. Each line is synced after it is written. The file is not rotated or deleted. Only the last 1 MiB is read back, and older lines are not used for deciding the rollback target either. Lines that do not match the fixed form are left out.
- Only changes requested through the admin screens and the admin API are recorded. A choice made with the command (`managed activate`) and an apply by SIGHUP are not recorded.
- A line is written only when the proxy could not be reached (`unreachable`), and for the outcomes after the pre-change audit log line was written (see the table in "Apply Jobs"). No line is written for an input error, another change in progress, an old `expect`, a rollback target that cannot be decided, a proxy that did not answer the query because of its limit of concurrent connections, or an audit log line that could not be written.
- Messages from the proxy and the managed store are not written to the history; they appear only in the apply job's `detail`.
- If a line could not be written, the apply job's `history` is `false` and a failure (`history`) is written to the audit log.
- If `managed` was absent when the admin process started, it gives 409, and if the history cannot be read, 503.

## Reading Logs

`GET /api/records` (viewer or above, API tokens allowed) reads the files in `records.dir`, starting from the newest line, and returns the lines that match the conditions. Each line is the JSON object as it was written, and characters that came from a request (such as `path`) stay in the `%XX` form (see "Logs" in the [operator reference](operator-reference.md)). The order of the keys may change.

The conditions (the query) are as follows. Each can be given once, and a value can be written with `%XX` (up to 128 bytes after decoding).

| Condition | Form |
|---|---|
| `from`, `to` | The start and end times. RFC 3339 in UTC, ending in `Z`. Up to 9 fractional digits (cut down to milliseconds), or none |
| `type` | `request`, `connection`, `tunnel`, `line`, `audit`, `dropped` |
| `class` | The result in a request log (1 to 32 characters of lowercase letters, digits, `_`, and `-`) |
| `status` | A status code (1 to 3 digits) |
| `rule` | A rule ID: the rule that decided, or one of the other rules that matched |
| `id` | The request ID |
| `client` | An IP address |
| `generation` | The fingerprint of a generation. The first 16 digits or all 64 (the log has only the first 16 digits) |
| `engine` | The engine that inspected the request. `coraza` or `modsecurity` (lowercase only). A log without `engine` (such as a request that went through a bypass route) does not match this condition |
| `file`, `offset`, `inode` | The position to continue from. It can be used only when all three are given |

- `audit` logs are written to the admin process's standard error and to the audit log in the admin store, and do not go into the proxy's log files, so a search with `type=audit` finds nothing in these files. Read the audit log with `GET /api/audit`.
- It returns up to 500 lines at a time, and reads up to 256 MiB. When it reaches either limit and logs still remain, `next` in the response holds the position to continue from. If the read limit stops it before any matching line is found, `next` is present even though `records` is empty. Keep reading until `next` is `null`.
- The response is `{"records": [..], "next": null or {"file", "offset", "inode"}}`. `inode` is returned as a string. To continue, add the three values of `next` to the same conditions.
- The position to continue from consists of the file number, the position in the file, and the file's inode. Even if rotation changes the file numbers, the file is found by its inode. If rotation deleted the file, or the position is no longer at the end of a line, the request gets 409 `the continuation names no place in the record files any more`. In that case, read again from the start.
- It reads from the newest line and stops at the first line older than `from`. It does not return a last line that has no newline yet because it is still being written, a line without `ts`, or a line that is too long.
- Failures:
  - The configuration has no `records`: 404 `records are not configured`
  - An error in the conditions (an unknown condition, the same condition twice, a value in the wrong form, or not all three values of the position to continue from): 400. The message is one fixed English sentence
  - The log file directory fails the owner and permission check: 503. The message is the one from that check
  - The file cannot be read: 503 `unavailable`

## Admin Screens

The admin screens are served by the admin process. Open `https://admin.example.com/` (`admin.origin`) in a browser.

- The files are in `proxy/admin-ui/`, and are built into the executable. The admin process and the admin screens are always the same version. The admin process does not read any files of the host.
- The only paths that it serves are `GET /` (the page) and `GET /ui/<ui-version>/<name>` (a style sheet, an icon, and 34 scripts, 36 files in all). A script's name is its path under `proxy/admin-ui/js/` (`js/app.js` is `/ui/<ui-version>/app.js`, and `js/waf/waf.js` is `/ui/<ui-version>/waf/waf.js`). No session is needed (the files contain no secret).
- `<ui-version>` in the path is 16 lowercase hexadecimal digits derived from the names and contents of the 36 files (the first 16 digits of the SHA-256 of a list of each file's name and SHA-256). It is computed once, at the first request for the page or a file, and the page is served with `/ui/` in it replaced by `/ui/<ui-version>/`. As long as the files' contents do not change, `<ui-version>` does not change either.
- `/ui/<name>` without `<ui-version>`, a path with a different `<ui-version>`, and a name that is not one of the 36 all fall through to the API table and get 404. A method other than `GET` and `HEAD` on the page or on the files under `<ui-version>` gets 405 (`Allow: GET, HEAD`).
- The response headers for the page and the files:

| Header | Value |
|---|---|
| `Cache-Control` | The page is `no-store`. The files under `<ui-version>` are `public, max-age=31536000, immutable` |
| `X-Content-Type-Options` | `nosniff` |
| `Content-Security-Policy` | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'` |
| `Referrer-Policy` | `same-origin` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Permissions-Policy` | `accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()` |

- The page is loaded every time, and refers to the files by the current `<ui-version>` path. The files under `<ui-version>` never change, so the browser uses its cache for up to a year. When you restart the admin process with an executable whose screen files have changed, `<ui-version>` changes, and only then does the browser load the files from the new path.
- The screens' scripts cannot create markup from a string (Trusted Types). The screens can do nothing except load their own scripts, styles, and icons, and call their own API.
- `Referrer-Policy` is `no-referrer` for API responses, and `same-origin` for the screens' files.

Language and storage:

- The languages are Japanese and English. The screens use the saved language if there is one, otherwise the browser language (Japanese if it starts with `ja`, English if it starts with `en`), and English if it is neither. You can switch the language in the bar at the top of the screen.
- The theme (Auto, Light, Dark) and how times are shown (Local or UTC) can also be chosen in the bar at the top of the screen. The screens save only these three things in browser storage (`localStorage`): the language, the theme, and how times are shown. The password, verification code, recovery codes, API token, CSRF token, two-factor authentication secret, and managed configuration draft (see "Drafts" below) are all kept only in the screen's memory. Those that are returned only once (the recovery codes, an API token, a secret that is being set up) are also discarded when you leave the screen, except that if the response confirming the two-factor setup arrives after you have left the screen, its recovery codes are kept until the next screen shows them. All of these are discarded at logout and when the session ends. They are not put in the URL or the history either.
- When you switch the language, the theme, or how times are shown, the screen is not redrawn; only the text is replaced. The text you entered, the files you selected, and the filters stay as they are.
- The two-factor authentication QR code is drawn within the screen (nothing is sent outside).

Which screens you can use depends on the role. The menu arranges the screens in 7 groups (the "Menu" column of the table below), and shows only the screens that the role can use.

| Menu | Screen | Role | Content |
|---|---|---|---|
| (no name) | Overview | viewer or above | It shows the proxy's numbers (five: "Requests", "Blocked", "Refused by policy", "Upstream failures", and "Config reloads", with the time since start shown under "Requests"; for what they mean, see `GET /api/status` under "Listing and Contents" above), the proxy's state (whether all engines are ready, and whether a generation switch is in progress), the state of each engine's generations, and the SHA-256 of the current configuration file. Each engine's panel shows the engine name (with the badge "Default" for the default engine), the inspection kernel's phase, the chosen generation, the running generation, the mode, the rollback target, and a message about what the two generations are doing. For an engine that has a chosen generation but is not running in the proxy, it shows the badge "Not running" and a message that says to start the engine on the Rule generations screen ("This engine has a chosen generation but is not running in the proxy. Press 'Start the engine' on the Rule generations screen."). An engine that has neither a chosen generation nor a running generation, and is not the default engine, is not shown. When no switch is in progress but the two generations differ for any engine, or when a generation is chosen but that engine is not running, a warning is shown in the bar at the top of the screen. While a switch is in progress, the Overview screen shows only a message saying so. When the managed configuration is used, the "Managed configuration" panel shows the selected version and the running version, and "Matching" or "Different" for the two ("Applying" while an apply job is running), and the link "Open the Configuration versions screen" |
| WAF | Rule generations | viewer or above | It shows the list of generations and each generation's details (files, load order, bypass routes). An operator or above can choose, switch the proxy, start the engine, and remove, for each engine of the generation. The buttons are "Switch to this generation" ("Switch" in a row of the list) for choosing, "Apply to the proxy" for switching when the proxy has not caught up with the chosen generation, and "Start the engine" for starting an engine that has a chosen generation but is not running in the proxy. When a generation's manifest cannot be read, so its engine is not known, the buttons for choosing and starting are not shown. The chosen generation, the running generation, and the rollback target of any engine cannot be removed |
| WAF | Rule import | operator or above | Select files in the browser and import them, specifying the inspection engine (Coraza or ModSecurity; the initial value is the default engine, and Coraza if it is not known), whether to use the CRS and which files not to use, the bypass routes, and detect only. Write the bypass routes one per line, as a host (optional) and a path. The description says "Requests to the admin screens are inspected by the default engine when the configuration file has managed, and by the engine of the upstream that forwards to the admin process when it does not. If an import request is blocked by inspection, put a bypass route in a generation of that engine." The action is always `bypass`, and `routes` in the body sent is JSON of the same form as a `--routes` file. A line with only a host is shown as an error, and an empty line is not sent. The browser also checks the limits. If the trial is blocked, you can use "Accept the block and import" after a confirmation. The new generation is not chosen |
| WAF | Switch history | viewer or above | It shows the switch history (newest first, up to 200; the screen says so too; the "Engine" column shows "—" for old lines that have no `engine`) and each engine's rollback target. An operator or above can roll back ("Roll back") for each engine that has a rollback target |
| Logs | Access log | viewer or above | It searches the logs by conditions. The "Engine" condition (Any, Coraza, ModSecurity) narrows the logs to those that engine inspected. Text that came from a request is shown as it is, in the `%XX` form. For a log that has a request ID, pressing the row's content (the method, host, and path, and so on) opens its details. The request ID appears in the `title` attribute of the content, and in "All fields" and "JSON" in the details. A log without a request ID (such as a connection log or a `line` log of the proxy) opens with "Open" on the row. An opened log first shows the main points (the `class`, `status`, and `reason` of the result, the rule, `score`, the time, the client, the method, host, and path, the generation, and the engine), with "All fields" and "JSON" collapsed below them. In "All fields", if you select "Also show the URL-decoded text", the decoded text is also shown |
| Logs | Audit log | operator or above | It shows the newest 200 lines (newest first; the screen says so too). When the request ID is in the form that the proxy and the admin process generate, you can open the Access log screen from that ID |
| Proxy | Sites | operator or above | It lists and edits the sites in the managed configuration draft (name, hosts, certificate; the certificate is either certificate chain and private key files, or ACME). The list and the editing panel show the expiry, the state, and the host names of the certificate in the managed store (see "Certificate Information" above) |
| Proxy | Upstreams | operator or above | It edits the draft's default upstream, and lists and edits the upstreams (engine, servers, TLS, and CA file). The engine is one of "Default engine (Coraza)" (the parentheses hold the default engine's name), "Coraza", and "ModSecurity". The help for the choices points to "ModSecurity Generations" in the [operator reference](operator-reference.md). The list's "Engine" column shows the engine that inspects ("(default engine)" is added for an upstream that follows the default engine). Before saving, a notice is shown when the chosen engine has no chosen generation, is not running in the proxy, or is starting, or when the ModSecurity inspector process is not in `kernel.engines` in the configuration file |
| Proxy | Routes | operator or above | It lists and edits the draft's routes (host, path or a regular expression for it, priority, upstream; and, in the collapsed part, access control, streaming responses, and rewrite; see "Routes screen" below). It loads up to 1024 routes |
| Policy | Access control and rate limits | operator or above | It lists and edits the draft's global access control and rate limits, and its host policies (see "Host policy screen" below) |
| Configuration | Configuration versions | viewer or above | It shows the selected version and the running version, the proxy's state, the state of the apply, and the list of versions (see "Managed configuration screens" below). An operator or above can show the contents of a version (JSON and certificates), apply by name, remove, and make a draft. The selected version, the running version, and the rollback target cannot be removed |
| Configuration | Configuration history | viewer or above | It shows the configuration history (newest first, up to 200; the screen says so too) and the rollback target. A line where the configuration file differs before and after the apply shows "Changed". An operator or above can roll back ("Roll back to the previous version") |
| Configuration | Configuration file | operator or above | It shows the current values in the configuration file (see "Configuration File Values" above). The values cannot be changed here. Paths are not shown: it shows true if a path is written, and "—" if not. It shows a comparison with the running proxy ("Matching" or "Different (waiting for reload)") |
| Admin | Account | viewer or above | Changing the password, setting up and disabling two-factor authentication, and creating and removing API tokens |
| Admin | Users | owner | Listing and creating users, changing roles, disabling and enabling users, resetting passwords and two-factor authentication, and listing and removing everyone's API tokens |

- When the Overview cannot get the numbers from the proxy, it shows "—" and a short word in place of the numbers, so that they are not mistaken for 0. The reason is shown only once, in the proxy panel, and is one of these: the proxy cannot be reached (`reachable` is `false`), the proxy is busy (`proxy` is `null`), or that proxy does not return the numbers (a proxy of an earlier version, where the value is `null`). The SHA-256 of the configuration file is treated the same way.
- The per-engine display shows these notices.
  - When the default engine differs between the admin process and the proxy (when only one of them was restarted), the "Default" badge is not shown, and "The admin process and the proxy have different default engines. Restart both to make them the same." is shown on the Overview, Rule import, and Upstreams screens.
  - For a proxy of an earlier version (one that does not return `engines`), "This proxy does not report the state of its engines. Use the same build for the admin process and the proxy." is shown on the Overview, Rule generations, and Switch history screens, and the buttons for choosing a generation, applying to the proxy, starting an engine, and rolling back are not shown (see "Version Updates" in the [operator reference](operator-reference.md)).
- Choosing, rolling back, and removing a generation show a confirmation first. The confirmation puts the generation "Now" and the generation "After the switch" ("After the rollback" for a rollback, "After deletion" for a removal) side by side in a table of the fingerprint (first 12 digits), the mode, the engine, and the number of bypass routes, with the values that change in bold. For choosing, "Now" is the chosen generation and "After the switch" is the generation to choose, and if the proxy is using a generation different from the chosen one, that generation is also shown. For a rollback, "After the rollback" is the rollback target, and for a removal, "After deletion" is "Gone" for every item. An unknown value is shown as "—". The confirmation for an engine that is not running in the proxy (including the first choice when the engine has no chosen generation, starting with the chosen generation, and a rollback) also says that the engine will be started, and adds "This engine also starts when the proxy is restarted. If it fails while it runs, the whole proxy stops. When you no longer use it, clear its choice with the rules deactivate command." (see "Chosen Generation per Engine" in the [operator reference](operator-reference.md)). An import is sent without a confirmation; a confirmation is shown only when you accept the trial's block and import again. While one of these is running, no other change can be started.
- When the result is not known (a 502 or 504 whose body has no `result`, or a dropped connection), the screen reads again and shows: for a choice or a rollback, the state and the history of the engine that the switch was for; for an import, the newest three generations in the list; for a removal, the list of generations. When a managed configuration change was sent and it is not known whether the change started, the screen reads the state again and shows it as "Result unknown".
- The screens never refresh by themselves on a timer. The exception is the managed configuration's apply job: until it ends, the screen reads `GET /api/managed/job` 1 second after the previous response to check the state. If it cannot read a response 3 times in a row, or when the longest time an apply job may take has passed, it stops checking and says so. While it checks, every request counts as using the session, so the session does not end through `admin.session_idle_ms` (it does end through `admin.session_total_ms`). When you use the screens through the proxy and logs are not kept with `security`, each check adds one line to the proxy's log. When you change something from a screen, the related displays are read again. To get the latest data, use "Reload" (the Rule import screen does not have it).
- In a list table, pressing the name of a sortable column sorts by that column (each press switches between ascending and descending, and rows with no value come last). Typing words in the field above the table narrows it to the rows whose visible cell text contains all the words (words are separated by spaces, and case is ignored; the column of operation buttons is not searched). Rows are split into pages of 50, and you move between them with "Previous" and "Next". Sorting and narrowing apply only to the rows that the screen has loaded. Some small tables, such as a generation's bypass route table, have no field for narrowing.
- The Access log screen shows one `GET /api/records` response (up to 500 lines) in pages of 50 lines. If the response has a continuation (`next`), "Next" on the last page loads the older logs that follow. "Previous" on the first page goes back to the newer ones that were loaded before. The position to continue from is not put in the URL, so if you open the URL again, it loads from the start.
- The part of the URL after `#` identifies the screen. It is `#/<screen>` (`overview`, `generations`, `import`, `history`, `records`, `audit`, `sites`, `upstreams`, `routes`, `policy`, `managed`, `managed-history`, `config`, `account`, `users`); in addition, a generation's details are `#/generations/<fingerprint>`, a version's contents are `#/managed/<version>`, a single log is `#/records/<id>`, and a log search is `#/records?<key>=<value>` (the condition names are the same as for `GET /api/records`, except for the position to continue from). Every move is added to the browser history, so the browser's back and forward buttons work. Opening the URL again shows the same screen.
- The values in the URL are checked for form before they are used. A value in the wrong form, a condition that the screen does not recognize, and extra parts are not used and are removed from the URL, and "Removed the invalid parts of the address." is shown. An unknown screen, or a screen that the role cannot use, opens the Overview. For a single log that is not among the loaded rows, the screen searches for it by that request ID, and if it is not found, says so.
- Times are shown in one form at a time. By default they are local times (in the form `2026-11-04 16:33:56 (JST)`; the parentheses hold the short name of the time zone that the browser returns, such as `JST` or `GMT+8`), and "Time" in the bar at the top of the screen switches them to UTC (`(UTC)`). In a table, the time zone name appears once, in the column name (`Time (JST)` and so on), not in the cells. Only a time in a different time zone from the column name (because of summer time, for example) also has the time zone in its cell. The other form of each time appears in its `title` attribute (the text shown when you hold the pointer over it). The log search's `from` and `to` are always written in RFC 3339 in UTC (ending in `Z`), whichever form is selected.
- After login, while the session is waiting for a password change or for two-factor setup, only that screen is shown.
- The screens call the admin API with the browser's `fetch`, and replace the message in an API response (`error`) with a message in the selected language.
- For a failure whose response has no `error` message (a 403 for a request that a proxy in front blocked by a rule, a 502 where the proxy could not connect to the admin process, and so on), the screen shows the request ID from the response's `X-Request-ID` after the failure message. Searching the Access log screen for that ID finds the rule that blocked the request and so on (see "CRS Tuning for the Admin Host" above). The ID is shown only when it is in the form that the proxy and the admin process generate.

Managed configuration screens:

- When the admin process was started without the managed configuration, the Configuration versions screen and the editing screens show what the managed configuration can do and an outline of the steps to start using it. The steps follow "Moving to the Managed Configuration" in the [operator reference](operator-reference.md).
- The Configuration versions screen shows the selected version, the running version, and the state of the proxy ("Reachable", "Unreachable", "Proxy busy", "Not using the managed configuration", "Reloading"). When the two versions differ, it shows a notice and, to an operator or above, two operations: "Apply the selected version again" and "Select the running version". The former switches the proxy to the selected version, and the latter applies the running version by name and makes it the selected version.
- When the configuration file differs from what the running proxy has read (`sha256` of `GET /api/config` differs from `proxy.config` of `/api/status`), the screen says so. If you apply from this screen, the configuration file's changes are also applied. If the configuration file has an error, the apply is refused.
- Apply by name ("Apply this version"), rollback, the operation that makes the two versions the same, and removal ("Remove this version") show a confirmation first. The confirmation puts the version "Now" and the version "After applying" ("After removal" for a removal) side by side in a table showing the number of sites, the number of upstreams, the number of upstreams for each engine ("Coraza upstreams" and "ModSecurity upstreams"; when the default engine is not known, one row "Upstreams that name an engine"), the number of routes, the default upstream, the global access control, the global rate limit, and the number of host policies, and for an apply it also shows "Applying resets the upstreams' failure counts. A server that is marked as failed stays marked if it has the same address in the same upstream, with the same failure limit, fail timeout, and TLS." For apply by name, rollback, and the operation that makes the two versions the same, if an engine is running a detect-only generation and the version after the apply has an upstream for that engine, the badge "Currently detect-only" is added to the "After applying" value.
- When you send a change, "Applying" is shown until the apply job ends, and then the screen shows the result ("Applied", "Refused", "Busy", and so on), what happened, and what to do next. When the proxy refused the apply with `fixed`, it shows "A setting key that cannot change while the proxy runs was changed, or an upstream's engine is not running in the proxy." and the next step ("If the engine is not running, start it on the Rule generations screen, then apply again. Otherwise, restore that setting key in the configuration file, or restart the proxy."). When the `at` of a 409 from apply by name or rollback is `upstreams.<name>.engine`, the upstream's name is added before the refusal message, as in "Upstream app:".
- The contents of a version (`#/managed/<version>`) can be opened only by an operator or above. The contents may include secrets, so they are kept in the screen's memory only while they are open. For a version that is not the selected one, "Create a draft from this version" creates a draft from it.

Drafts:

- The four screens (Sites, Upstreams, Routes, and Access control and rate limits) share one draft of the managed configuration. The draft is made from the selected version (it can also be made from another version, on that version's contents screen). A change made here has no effect until you press "Save and apply".
- The draft exists only in this page's memory. It is not put in browser storage, the URL, or the history. It is lost when you log out, when the session ends after a period with no activity, and when you close the tab. If you try to leave the page with a draft that has changes, the browser shows a confirmation.
- While you type into the draft, `GET /api/session` is sent at most once every 30 seconds to extend the session (typing counts as using the session).
- The bar at the top of the screen shows the base version and "Changed" or "No changes". "Changed" appears only when the version that would be made from the draft differs from the base version. A draft that you edited and then changed back shows "No changes". A draft with an input format error shows "Changed".
- "Check" in the bar sends `POST /api/managed/check` and, if it is refused, shows the error in its field (see `at` in "Response Format" below). "Save and apply" runs the check, shows a confirmation, and then sends `POST /api/managed/apply`. A draft with "No changes" cannot be saved (the check says "This is the same as the base version: nothing has changed.").
- The "Save and apply" confirmation lists the changes to save (adding, removing, and changing upstreams, the default upstream, access control, rate limits, host policies, sites, and routes) by name, without their values (because a rewrite can hold a secret). A change of an upstream's engine (only for upstreams that are in both versions) is listed as "Upstream engine", and adding or removing only the engine setting while the inspecting engine stays the same is listed as "Upstream engine setting". When some upstreams are inspected by an engine whose chosen generation is detect-only, it shows "Upstreams inspected by an engine whose generation is detect-only: {n} ({names}). Requests that match a rule are not blocked." (`{n}` is the number and `{names}` are the names. Up to 20 names are shown, and the rest are shown as a count such as "3 more"). When a site needs a new ACME certificate (`{n}` is the number of such sites), it shows "Sites that need a new certificate: {n}. Their hosts cannot be reached over TLS until acme renew issues the certificate (at most a little over a day if you leave this to the renewal timer)."
- When the draft's base version is no longer the selected one (because another user or a command changed it first), the draft cannot be saved as it is.
- The certificate chain, private key, and CA PEM files are read in the browser, checked to be UTF-8 text of 1 MiB or less, and specified by the SHA-256 of the text that is sent. File contents are not shown. The SHA-256 is calculated with the browser's cryptography functions, so a file can be selected only over a secure connection (https or localhost). The bytes that were read are overwritten with 0 as soon as they have been used, but the text inside the browser is not, and stays in memory until nothing refers to it.

Routes screen:

- The "Path" column of the list shows the route's path, or its regular expression. A route whose path is a regular expression has the mark "Regex", and a route that has a `priority` has the mark "Priority {n}" (`{n}` is the value). A route without `priority` has no such mark, and a route with `"priority": 0` shows "Priority 0". The field above the list also looks in the text of these marks.
- In the editing panel, "Path" is one line of text. When "Treat the path as a regular expression" is selected, the text is written as the route's `path_regex` and `path` is not written. When it is not selected, the text is written as `path` and `path_regex` is not written. The text stays when you switch the choice, and the help under "Path" changes with it.
- "Priority" is optional. If it is empty, `priority` is not written (0 is not written for it). Enter an integer from -1000 to 1000. The screen checks only that it is an integer of up to 4 digits; a value out of range is refused by the check, and the refusal is shown at "Priority".
- For the syntax of the regular expression, how it is matched against the path, the limits, how a route is chosen by `priority`, and how `access` applies, see `routes` under "`forward`" in the [operator reference](operator-reference.md).
- A route whose path is a regular expression cannot have access control that refuses anyone, or a path to rewrite to (an access control that refuses no one is the same as none, and can be saved). The screen does not hide or turn off those fields: the check refuses the draft and shows the refusal in the part of the access control or at "Path to rewrite to". When you change the choice of the regular expression, the refusals shown at "Path", in the part of the access control, and at "Path to rewrite to" are removed.
- A refusal of the check about a route's `path_regex` is shown at "Path", and one about `priority` at "Priority".
- The "Save and apply" confirmation names a route by its host and its path. A regular expression is written with `~` before it (for example, `app.example.com ~ ^/api/`). A path and a regular expression with the same text are different routes. A change of only the priority is listed as a change of that route.

Host policy screen:

- From top to bottom, the Access control and rate limits screen has the notice "The global settings and the per-host settings do not apply to the admin route.", the global access control and rate limits panel, the list of host policies with "Add a per-host setting", and the editing panel for the open host policy.
- For a host policy's setting keys, how hosts are compared, and how policies are layered, see "Host Policies (`host_policies`)" in the [operator reference](operator-reference.md).
- In the editing panel, write a name and the hosts (one per line), and, for access control and for rate limits, choose one of these three. What you entered stays in the draft when you switch between them.
  - "Inherit": the global settings also apply to this host. The rate limit is counted with the same counter as the global one.
  - "Settings for this host": the values in this panel apply in place of the global settings. The global access control is not inherited. The rate limit is counted with this host's own counter.
  - "Not used": it does not apply to this host. For access control, even a global refusal does not apply to this host.
- In a draft that changes the global access control or the global rate limit, the global settings panel and the "Save and apply" confirmation show "Per-host settings that do not inherit the global access control: {n} ({names}). This change does not apply to them." (`{n}` is the number and `{names}` are the names. The same form for rate limits). This is because global changes (including an urgent denial) do not take effect for hosts with "Settings for this host" or "Not used".
- The list shows "A per-host setting applies only to requests whose Host header is one of its hosts. Only the global settings apply to requests for other hosts that reach the same upstream through the default upstream, a route whose host starts with *., or a route without a host. We recommend writing a route for each host and setting the default upstream to 'None'."
- If you write a country list while the configuration file has no `geo`, the check's `at` points to that host policy's access control. If you write the same host as the admin route, the check's `at` points to that row.

## API Paths

The "Token" column shows whether an API token can be used. The "State" column shows the session states in which the API can be used ("Normal" means that the state does not restrict the API; for the states, see "Login and Two-Factor Authentication" above).

| Method | Path | Minimum role | Token | State | Content |
|---|---|---|---|---|---|
| POST | `/api/login` | (none) | no | | Login. `{"name", "password"}` |
| POST | `/api/login/mfa` | viewer | no | Waiting for a verification code | Verify the two-factor code. `{"code"}` or `{"recovery"}` |
| POST | `/api/logout` | viewer | no | Any state | Logout |
| GET | `/api/session` | viewer | no | Not waiting for a verification code | Session information |
| PUT | `/api/account/password` | viewer | no | Normal, waiting for a password change | Change the password. `{"current", "new"}` |
| POST | `/api/account/mfa/setup` | viewer | no | Normal, waiting for two-factor setup | Start the two-factor setup. `{"password"}` |
| POST | `/api/account/mfa/confirm` | viewer | no | Normal, waiting for two-factor setup | Confirm the setup. `{"code"}` |
| DELETE | `/api/account/mfa` | viewer | no | Normal, waiting for two-factor setup | Disable two-factor authentication. `{"password", "code"}` |
| GET | `/api/account/tokens` | viewer | no | Normal | List of your own API tokens |
| POST | `/api/account/tokens` | viewer | no | Normal | Create an API token |
| DELETE | `/api/account/tokens/<id>` | viewer | no | Normal | Remove your own API token. Another user's API token gives 404 |
| GET | `/api/status` | viewer | yes | Normal | State of the proxy and the generations |
| GET | `/api/generations` | viewer | yes | Normal | List of generations |
| GET | `/api/generations/<fingerprint>` | viewer | yes | Normal | Details of a generation |
| POST | `/api/generations` | operator | yes | Normal | Import |
| DELETE | `/api/generations/<fingerprint>` | operator | yes | Normal | Remove a generation |
| POST | `/api/activate` | operator | yes | Normal | Choose a generation and switch the proxy |
| POST | `/api/rollback` | operator | yes | Normal | Roll back to the previous generation. `{"engine", "expect"}` (`engine` is optional) |
| GET | `/api/history` | viewer | yes | Normal | Switch history |
| GET | `/api/managed` | viewer | yes | Normal | State of the managed configuration |
| GET | `/api/managed/versions` | viewer | yes | Normal | List of managed configuration versions |
| GET | `/api/managed/versions/<version>` | operator | yes | Normal | Contents of a version |
| DELETE | `/api/managed/versions/<version>` | operator | yes | Normal | Remove a version |
| GET | `/api/managed/certificates/<version>` | operator | yes | Normal | Certificate information of the sites in a version |
| POST | `/api/managed/check` | operator | yes | Normal | Check a version. `{"version", "files", "expect"}` (`expect` is optional) |
| POST | `/api/managed/apply` | operator | yes | Normal | Save a version and apply it. `{"expect", "version", "files"}` |
| POST | `/api/managed/activate` | operator | yes | Normal | Apply by name. `{"expect", "version"}` |
| POST | `/api/managed/rollback` | operator | yes | Normal | Roll back to the previous version. `{"expect"}` |
| GET | `/api/managed/job` | viewer | yes | Normal | The last apply job |
| GET | `/api/managed/history` | viewer | yes | Normal | Configuration history |
| GET | `/api/config` | operator | yes | Normal | Values in the configuration file |
| GET | `/api/records` | viewer | yes | Normal | Reading logs |
| GET | `/api/audit` | operator | yes | Normal | The newest 200 lines of the audit log |
| GET | `/api/users` | owner | no | Normal | List of users |
| POST | `/api/users` | owner | no | Normal | Create a user. `{"name", "role", "password"}` |
| PUT | `/api/users/<name>` | owner | no | Normal | Change the role or the enabled or disabled state. Either `{"role"}` or `{"disabled"}`, only one of them |
| POST | `/api/users/<name>/password` | owner | no | Normal | Set another user's password. `{"password"}` |
| DELETE | `/api/users/<name>/mfa` | owner | no | Normal | Disable another user's two-factor authentication |
| GET | `/api/tokens` | owner | no | Normal | List of everyone's API tokens |
| DELETE | `/api/tokens/<id>` | owner | no | Normal | Remove anyone's API token |

- An API marked "Normal" cannot be used by a session that is waiting for a password change or waiting for two-factor setup.
- The main response bodies (times are epoch milliseconds for users and API tokens; epoch seconds for `made` of a generation, `made` of a managed configuration version, `started` and `ended` of an apply job, and `not_after` of a certificate; and RFC 3339 for `ts` of the histories and the audit log):
  - `POST /api/login`, `POST /api/login/mfa`: `{"name", "role", "csrf", "mfa", "must_change"}` and a cookie
  - `GET /api/session`: `{"name", "role", "csrf", "mfa", "recovery_left", "must_change", "state", "idle_expires_in_ms", "total_expires_in_ms"}`. `mfa` is whether two-factor authentication is set up
  - `PUT /api/account/password`, `DELETE /api/account/mfa`: `{"csrf"}` and a new cookie. The other sessions end. A password change removes all API tokens
  - `POST /api/account/mfa/setup`: `{"secret", "uri"}`. `POST /api/account/mfa/confirm`: `{"csrf", "recovery"}` and a new cookie
  - `GET /api/users`: `{"users": [..]}` (`name`, `role`, `disabled`, `mfa`, `must_change`, `created`, `changed`). `POST /api/users` and `PUT /api/users/<name>` return that user
  - `GET /api/account/tokens`, `GET /api/tokens`: `{"tokens": [..]}` (newest first; the secret is not included)
  - `POST /api/managed/check`: 200 `{"version", "detect"}`. `POST /api/managed/apply`: 202 `{"version", "placed", "job"}`. `POST /api/managed/activate`, `POST /api/managed/rollback`: 202 `{"version", "job"}`. `DELETE /api/managed/versions/<version>`: 200 `{"removed", "cleaned"}` (see "Managed Configuration Operations" above)

## Response Format

### Responses

- Every response is JSON and has these headers (the admin screens' files are different; see "Admin Screens" above): `Content-Type: application/json`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `X-Request-ID` (the request ID).
- The request ID is the `X-Request-ID` of the request when the request comes from a peer in `admin.trusted_proxies` and that value is in the form that the proxy generates (16 lowercase hexadecimal digits, `-`, and 1 to 16 digits). Otherwise the admin process generates an ID of the same form. For a request that went through the proxy, `id` in the proxy's log and `id` in the audit log are the same.
- A failure response is `{"error": "<sentence>"}`. The message is one fixed English sentence for each kind of error, and does not contain any value from the request (only an input file's name is added, as a separate item: `subject` in the 400 of an import). The 422 of an import also has `trial`, and the failures of choosing a generation and of rollback also have the items in the table above. The admin screens replace this message with a message in the selected language.
- The 400 of `POST /api/managed/check` and `POST /api/managed/apply` is `{"error", "at"}`. `at` is the location in the body of the value that was refused, or `null` if there is no location. The 409 that `POST /api/managed/activate` and `POST /api/managed/rollback` give because no generation is chosen for an upstream's engine is also `{"error", "at"}`.
  - A location is written as the path of setting keys in the request body. `files` is for when there are too many files, and `files[k]` is for a file that is too large, that appears twice, or that the version does not specify. A location in the version takes forms such as `sites[1].hosts[0]`, `upstreams.app.servers[2].address`, `upstreams.app.engine`, `sites[0].certificate.key`, and `host_policies[1].rate_limit.keys`.
  - Array indexes count from 0.
  - A body whose JSON has the wrong form, and an `expect` that is not 64 lowercase hexadecimal digits, have no location (`null`). A 400 from a check in "Order of Admin API Checks" below has no `at` key.
  - The message is a fixed sentence that does not contain the location. A refusal of the configuration file (409) also has only a message and no location.
- The apply job's `detail` (the message from the proxy that refused) does not put the location in `at`; it writes it inside the message. There, listeners and upstream servers count from 1 (`listener 1 cannot be bound`, `(upstream app, server 1)`, and so on), and a site is given by its name (`site app`). This way of counting differs from the check's `at`.

### Status Codes

| Status code | Case | Main `error` |
|---|---|---|
| 400 | The body is not a JSON object, it has a key that the API does not recognize, there are both a cookie and an API token, an input error | `bad request`, a message for each API. `/api/managed/check` and `/api/managed/apply` also have `at` |
| 401 | There is neither a session nor an API token, the session has ended, the user was changed, an invalid API token. A login error | `unauthorized`, `invalid credentials` |
| 403 | Refused by `Origin`, CSRF, the role, the state, or an API that cannot use an API token. A wrong password or verification code. Other refusals | `forbidden`, `second factor required`, `password change required`, `second factor setup required`, `the password is wrong`, `the current password is wrong`, `the code is wrong`, `mfa is required` |
| 404 | A path that is not in the table, a generation, a managed configuration version, a user, or an API token that does not exist, a configuration without `records` | `not found`, `no such generation`, `records are not configured` |
| 405 | The path does not have that method. `Allow` is added (it includes `HEAD` if there is `GET`) | `method not allowed` |
| 408 | The body does not arrive within 30 seconds | `request timeout` |
| 409 | It overlaps another change, it does not fit the state, a limit on a count, the engine of the generation cannot be used, a proxy that does not return the state of each engine, no generation is chosen for an upstream's engine, there is no managed configuration, the configuration file is rejected | `conflict`, `the name is taken`, `the store has too many users`, `the user has too many tokens`, `the last enabled owner stays`, `the user was changed since it was read`, a generation operation message (`the chosen generation is not the one that was expected`, `the proxy does not report its engines`, and so on), `the configuration has no managed object`, `a change of the managed configuration is under way`, a managed configuration operation message (`no generation is chosen for the engine of an upstream`, and so on) |
| 413 | The body is over the limit | `payload too large` |
| 415 | An API that reads a body gets a `Content-Type` that is not `application/json` | `unsupported media type` |
| 422 | An import trial failed | `the trial failed` |
| 429 | The client has used up its attempts | `too many tries` |
| 500 | An inconsistency inside the admin process. The rules store or the managed store cannot be read. The record of a chosen generation is broken, or the records of an engine disagree | `internal error`, the messages from the rules store and the managed store (including `the current generation record is broken` and `the current generation records of the engine disagree`) |
| 502 | The proxy did not switch | `the proxy did not switch` |
| 503 | The store or an audit log line cannot be read or written, a timeout, the proxy cannot be reached, managed configuration checks overlap | `unavailable`, `the proxy cannot be reached`, `the proxy is busy`, `the proxy did not say how the switch ended`, `a check of a managed version is under way` |

The admin API cannot repair a 500 with `the current generation record is broken` or `the current generation records of the engine disagree`. `GET /api/generations` and `GET /api/status` answer 500 as well, so the admin screens cannot list or switch generations. Choose a generation for that engine again with `rules activate` (see "Chosen Generation per Engine" in the [operator reference](operator-reference.md)).

A managed configuration change ("Save and apply", "Apply by name", "Roll back") gets the 202 response when it is accepted. Read how it ended from the apply job (see "Managed Configuration Operations" above).

### Order of Admin API Checks

The response comes from the first check that fails.

1. The path (404 if it is not in the table) and the method (405 if the path does not have it)
2. For an API that has a minimum role, the credentials (a session cookie or `Authorization: Bearer`). If both are present, 400; if neither is present or they do not match, 401; for a client that has used up its API token attempts, 429
3. For a request that changes something, `Origin` (403) and, for a session, `X-CSRF-Token` (403)
4. An API token for an API that cannot use an API token (403)
5. The state of the session (403; a fixed message)
6. The role (403)

A request refused at steps 3 to 6 is written to the audit log, because the user is known by then. After these checks, an API that reads a body validates `Content-Type` (415) and the form of the JSON (400).
