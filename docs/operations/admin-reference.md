[English](admin-reference.md) | [日本語](admin-reference.ja.md)

# Admin Reference

This document is a reference for the admin process, the setting key `admin`, the admin API, and the admin screens of the current implementation. For the setting keys and commands of the proxy, see the [operator reference](operator-reference.md). For the deployment and examples of systemd units, see the [build and deployment guide](../build/binary-deployment.md).

The paths and names in this document (`/etc/tukuyomi-core/config.json`, the OS user `tukuyomi`, `admin.example.com`, `192.0.2.0/24`, and so on) are examples.

## Components

The admin process runs as the `admin` command of the same executable as `tukuyomi-proxy`, separately from the proxy. It responds to requests for the admin screens that you open in a browser and for the admin API that programs use.

| Component | Content |
|---|---|
| Admin process | `tukuyomi-proxy admin <config>`. It responds to requests for the admin screens and the admin API on a loopback listener without TLS |
| Admin screens | Screens built into the executable (Japanese and English). The admin process serves them |
| Admin store | `admin.store.dir` in the configuration. The directory that holds the users, API tokens, audit log, switch history, and configuration history |
| Control socket | `admin.control` in the configuration. A Unix domain socket that the proxy creates. The admin process uses it to ask for the state of the proxy, to request a generation switch for each engine, and to request a configuration reload with a version of the managed configuration (for the proxy side, see "Control Socket" in the [operator reference](operator-reference.md)) |
| Log files | `records.dir` in the configuration. The proxy puts copies of its logs there. The admin process reads them (see "Log Files (`records`)" in the [operator reference](operator-reference.md)) |
| Managed store | `managed.dir` in the configuration (only for a configuration that has `managed`). The directory that holds the versions of the managed configuration and the files that the versions use, such as certificates. The admin process saves and removes versions. The proxy only reads them (see "Managed Store and Versions" in the [operator reference](operator-reference.md)) |

- The admin process and the proxy read the same configuration file. The admin process reads values such as `admin` only once, at start, and does not read them again. However, `GET /api/config`, which reads out the values of the configuration file, and the check and the changes of the managed configuration read the configuration file again each time (see "Managed Configuration Operations" below). The proxy reloads on SIGHUP, but `admin` is a setting key that cannot change while running (see "SIGHUP (Configuration Reload)" in the [operator reference](operator-reference.md)).
  - The setting keys of `admin` that the proxy uses are `listen` and `control`, and, in a configuration that has `managed`, also `route`. Only the proxy uses `route`, not the admin process. For the other setting keys, the proxy also only validates the ranges, so that both processes accept the same file or both reject it.
  - After you change a setting key of `admin`, restart the admin process. The proxy refuses to reload a configuration whose `admin` differs, so restart the proxy too. For what the proxy does when `admin.route` is changed, see "`admin`" and "SIGHUP (Configuration Reload)" in the [operator reference](operator-reference.md).
- The admin process works while the proxy is stopped. While the proxy is stopped, you can still read generations and logs, import, manage users, and read, check, and remove versions of the managed configuration. A generation switch and a rollback, which the admin process asks the proxy to do, and applying the managed configuration are refused if the proxy cannot be reached. In that case, the "Save and apply" operation of the managed configuration does not save the version either (see "Generation Operations" and "Managed Configuration Operations" below).
- If the configuration has no `admin`, the admin process does not start (exit 2), and the proxy does not create the control socket.

## Admin Process

### `admin`

```text
tukuyomi-proxy admin <config>
```

- Pass the configuration file as an absolute path (the same rule as for "Commands" in the [operator reference](operator-reference.md)).
- Start proceeds in the following order.
  1. It runs the checks before start (not running as root, SIGCHLD, file descriptors. These are the same as for the proxy; see "Checks Before Start" in the [build and deployment guide](../build/binary-deployment.md)).
  2. It reads the configuration file.
  3. It opens the admin store and takes the lock on `process.lock`.
  4. It opens the audit log.
  5. It binds the listener.
- After it binds the listener, it writes an `admin: listening` line and, if `NOTIFY_SOCKET` is in the environment, sends `READY=1`.
- Only one admin process can run on one admin store. While one admin process holds `process.lock`, no other admin process can start on the same store (exit 1). This prevents two processes from each accepting the same verification code of the same time window, or the same recovery code, once.
- Run it as the same OS user as the proxy. It uses each of the rules store, the admin store, the directory for the log files, and the managed store (`managed.dir`) only if it is a directory that is owned by that OS user and has no permissions for the group and other users. The directory for the control socket gets the same check when the proxy creates the socket. A trial of an import starts an inspector process, so the admin process also uses the same `kernel` value of the configuration as the proxy (the executable and work directory of the inspector process).
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

Creates the first user (with the role `owner`). It can create the user only when the admin store has no user.

- It reads the password from the first line of standard input. Do not pass it as an argument. Example:

  ```bash
  read -r -s -p 'password: ' PW; echo
  printf '%s\n' "$PW" | sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy admin bootstrap /etc/tukuyomi-core/config.json alice
  unset PW
  ```

- A name is 1 to 32 bytes of lowercase letters, digits, `.`, `_`, and `-`. A password is 12 to 128 bytes of UTF-8.
- On success, it writes `created owner <name>` to standard output and exits with 0. Other lines go to standard error. Except for the line of the audit log (below), they start with `admin bootstrap:`.
- It writes an audit log line (`action` is `create`, `auth` is `bootstrap`, with no actor and no client address) before it creates the user. If it cannot write the line, it does not create the user. This line is written to standard error as JSON.
- It can run when the admin process is not running.

### `admin reset`

```text
tukuyomi-proxy admin reset <config> <name>
```

Sets the password again for a user who is locked out (for example, the only owner who has lost both the password and two-factor authentication).

- How the password is read, the rules for the name and the password, the lines on standard error, and how the audit log line is written are the same as for `admin bootstrap`. In the audit log line, `action` is `reset`, `auth` is `reset`, and the target is the name of the user.
- On success, it writes `reset password of <name>` to standard output and exits with 0.
- It does the following to the user.
  - It sets the password to the entered value and makes the user change it at the next login.
  - It disables two-factor authentication and the recovery codes.
  - It ends the sessions of this user and invalidates all API tokens. If it cannot delete a token file, it writes a line about it to standard error, but the token stays invalid, and it exits with 0.
  - It releases the lockout and counts failures again from 0.
- A user who is disabled is not enabled again. To make a disabled user usable, an owner enables the user with `PUT /api/users/<name>`.
- It can also run while the admin process is running. The change is written inside the lock of the store, and only if the user that was read has not changed. If it overlaps with another write, it is refused with `the admin store is in use by another process` or `the user was changed since it was read` (exit 1). In that case, run it again.

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

The admin process responds to HTTP/1.1 requests on the loopback address of `admin.listen`. It does not use TLS (to use it from outside, go through a TLS listener of the proxy; see "Access from Outside" below).

| Field | Value |
|---|---|
| Concurrent connections | 32. A connection over the limit is accepted and closed at once |
| One connection | It accepts one request, responds to it, and closes (`Connection: close`). It does not wait for the next request |
| Header section | Up to 8 KiB and up to 64 header fields. It must be read within 10 seconds |
| Body | Up to 64 KiB. It must be read within 30 seconds |
| Body of an import, `POST /api/managed/check` and `POST /api/managed/apply` | Up to 12 MiB. It is read only for a user who can use that API (an operator or above, with a valid session or token, and not restricted by the state). Otherwise it is not read, and the request is refused with the 400, 401, 403, 429, or 503 of the checks (400 if both a cookie and a token are present, 429 for a client that has used up its token attempts, 503 if the store cannot be read) |
| Time to build a response | 30 seconds. For an import, choosing a generation and a rollback, the time given in "Slow responses" below |
| Lifetime of a connection | Up to the total of the times for the header section, the body, and the response |

- A request whose `Content-Length` is over the limit gets 413 before the credentials are checked, without reading the body. For a header section that has an error or is over the limit, the HTTP library either returns its own response or returns nothing.
- An API that reads a body returns 415 if `Content-Type` is not `application/json`. A body whose JSON has the wrong form, or that has a key that the API does not recognize, gets 400.
- `HEAD` is handled as `GET`. A path that is not in the table gets 404, and another method on a path that is in the table gets 405 (with `Allow`).

Slow responses: An import (including the trial), choosing a generation, and a rollback take time. The time to build the response is the longer of the following two times plus 7 seconds (it uses the time setting keys of `proxy`). A request that times out gets 503 `unavailable`.

- Import: `ready_wait_ms + 3 × inspect_wait_ms + stop_inspect_ms`
- Choosing a generation and rollback: `ready_wait_ms + stop_inspect_ms + 14 seconds`

With the values in the example of the operator reference (`ready_wait_ms` 30000, `inspect_wait_ms` 55000, `stop_inspect_ms` 10000), the limit is about 212 seconds. An import that completes without trouble takes far less time than this.

### Stopping and systemd

- It stops on SIGTERM, SIGINT, and SIGHUP. It writes an `admin: stop: <signal>` line and, if `NOTIFY_SOCKET` is set, sends `STOPPING=1`.
  1. It ends the trial of a running import as a failure (it cleans up the inspector process and the work directory).
  2. It closes the listener.
  3. It waits up to 10 seconds for requests in progress, and cuts off the connections that remain.
  4. It exits with 0.
- The rules for `NOTIFY_SOCKET` are the same as for the proxy (see "Notifications to systemd" in the [operator reference](operator-reference.md)). It handles only these three signals, not SIGUSR1 or SIGUSR2 (if you send one of them, the process ends with the default action).
- Sessions, the failure count and lockout state of each user, the secret of two-factor authentication that is being set up, and the apply job of the managed configuration are only in memory. So after a restart everyone must log in again, and the apply job is not kept. API tokens, users, the audit log, the switch history, and the configuration history stay in the store.

Write the systemd unit to match the unit of the proxy (see "systemd" in the [build and deployment guide](../build/binary-deployment.md)). The differences for the admin process are as follows.

- Set `ExecStart` to `tukuyomi-proxy admin <config>`, and use the same `User` and `Group` as the proxy.
- Set `Type=notify`. The admin process sends `READY=1` after it binds the listener.
- Set `KillMode=mixed`. With the default `control-group`, SIGTERM also reaches the inspector process of the trial of an import, and the admin process cannot stop the inspector process in order (the reason is the same as for the proxy).
- Make `TimeoutStopSec` longer than the 10 seconds that the admin process waits at stop. To allow for a trial of an import that is running, also add the time to stop its inspector process (`proxy.stop_inspect_ms` and `kernel.kill_grace_ms`).
- If the port of `admin.listen` is 1024 or higher, `AmbientCapabilities` is not needed. `ReadWritePaths` includes the rules store, the admin store, `kernel.tmp_root`, the directory for the control socket, and the managed store (when there is `managed.dir`).
- Set `LogRateLimitIntervalSec=0`. Audit log lines are also written to standard error (the journal), so this keeps them from being lost to the rate limit of journald.
- The unit does not need an ordering with the unit of the proxy.

As with the proxy, logs go to standard error as one JSON object per line (see "Logs" in the [operator reference](operator-reference.md)). The admin process writes `line` entries for the sentences that start with `admin:` and `audit` entries for the audit log lines. `audit` entries do not go into the log files of the proxy (`records.dir`).

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

`admin` and `records` are objects at the top level of the configuration file (alongside `proxy`, `forward`, `kernel`, and so on). Both can be omitted. When you write `admin`, write all setting keys except `crs_dir` and `route`. `route` is required in a configuration that has `managed`, and cannot be written in one that has no `managed`. The rules that reject unknown setting keys, duplicates, and type mismatches are the same as for "Configuration File" in the [operator reference](operator-reference.md).

| Setting key | Range | Meaning |
|---|---|---|
| `listen` | A loopback IP (`127.0.0.0/8` or `::1`) and a port (0 is not allowed) | The address of the listener of the admin process. The `::ffff:127.0.0.1` form is not treated as loopback |
| `control` | An absolute path, up to 107 bytes | The control socket file |
| `store` | `{"kind": "file", "dir"}` | The admin store. `kind` is only `file` at present. `dir` is an absolute path of up to 3840 bytes |
| `origin` | `https://` and a host (optionally `:port`) | The origin of the URL that opens the admin screens. It has the same form as the `host` of a route (a lowercase name), and cannot have a wildcard, a path, a query, or a trailing `/`. It is compared with the `Origin` of changing requests such as `POST` |
| `trusted_proxies` | 0 to 256 networks | The peers that are trusted when the client address of the admin process is decided from `X-Forwarded-For`. Write them in the form `address/prefix` with the host part 0. They are read the same way as for the proxy (see "Client Address" in the [operator reference](operator-reference.md)) |
| `mfa` | `"optional"`, `"required"` | Whether two-factor authentication is required. `required` lets a user who has not set up two-factor authentication do only the setup (see "Login and Two-Factor Authentication" below) |
| `session_idle_ms` | 1 minute to 24 hours | How long a session lasts without being used |
| `session_total_ms` | `session_idle_ms` to 7 days | The upper limit of how long a session lasts |
| `crs_dir` | An absolute path, up to 3840 bytes. It can be omitted | The CRS directory that imports can use. It is the one fetched with `scripts/fetch-crs.sh` (see "Fetching the CRS" in [build and deployment guide](../build/binary-deployment.md)). If omitted, imports cannot use the CRS |
| `route` | Only in a configuration that has `managed`. Then it is required | The route of the admin screens (host, certificate, `access`). Only the proxy uses it. For its form and rules, see "`admin`" in the [operator reference](operator-reference.md); for how to use it, see "Admin Route with the Managed Configuration" below |

- `listen` must not overlap any listener (`proxy.listeners`) or `status.listen`. The rules for overlap are the same as among listeners: the same address and port, or the same port where one of them is `0.0.0.0` or `::`.
- The address of a server of an upstream can be `admin.listen` (it cannot be that of a listener or of `status.listen`). This is so that the admin process can be used from outside through a route of the proxy (see "Access from Outside" below).
- Keep the directories apart. The rules store (`rules.store.dir`), `records.dir` (when present), `admin.store.dir`, the directory that holds `admin.control`, `managed.dir` (when present), and `acme.challenge_dir` (when present) cannot be the same directory or inside one another. `admin.control` itself also cannot be inside the rules store, `records.dir`, or `admin.store.dir`.
- If you change `admin.route.host`, the URL that you open in the browser changes too, so change `admin.origin` to the new host as well (see "Access from Outside" below) and restart the admin process. The admin process reads `admin.origin` only at start. For what the proxy does, see "`admin`" in the [operator reference](operator-reference.md).
- Create `admin.store.dir` and the directory that holds `admin.control` beforehand. Each must be a directory that is owned by the OS user of the proxy, has no permissions for the group and other users (0700), and is not a symbolic link. The admin process creates `users/`, `tokens/`, and `audit/` in the admin store.
- `config check` validates the setting keys of `admin` and `records` and the relations between their values. It does not check whether the admin store, the control socket, and the log files can be opened.

The contents of the admin store (files are 0600, directories are 0700):

| Path | Content |
|---|---|
| `users/<name>.json` | A user. It holds the password hash, the secret of two-factor authentication, and the hashes of the recovery codes. Up to 1000 users |
| `tokens/<id>.json` | An API token. It holds only the SHA-256 of the secret of the token. Up to 50 per owner |
| `audit/` | The audit log (`audit.log` and the older files that were rotated) |
| `activations.log` | The switch history |
| `managed.log` | The configuration history (see "Configuration History" below) |
| `lock`, `process.lock` | The lock for writing and the lock of the admin process |

### Control Socket

When the configuration has `admin`, the proxy creates the control socket `admin.control` at start. For how it is created, who can use it, and the forms of requests and responses, see "Control Socket" in the [operator reference](operator-reference.md). The admin process handles it as follows.

- Asking for the state: it waits 2 seconds to connect and 2 seconds for the response. If the proxy accepts the connection and closes it without responding (it has reached the limit of concurrent connections), it asks again once after 250 ms, and if the result is the same, it treats the proxy as "Proxy busy" (in `GET /api/status`, `reachable` is `true` and `proxy` is `null`).
- For a request for the state and a request for a generation switch, all of these mean "the proxy cannot be reached": there is no socket, no process accepts the connection, the response is not in the defined form, or no response comes in time.
- A request for a generation switch is made for each engine. The request names the engine to switch (`engine`) and the generation that the rules store has chosen for that engine (`expect`). The admin process does not make the request to a proxy that does not return `engines` in its state (the generation, mode, and phase of each engine that runs in the proxy; such a proxy is an earlier version that does not support the choice per engine) (see "Choosing and Rolling Back" below).
- A request for a generation switch waits up to `ready_wait_ms + 7 seconds`. The time that the proxy itself waits for the response is `ready_wait_ms + 5 seconds`, so the wait of the admin process is 2 seconds longer.
- When the proxy responds to a switch request with `busy`, or closes the connection without reading the request, the admin process asks for the state every 250 ms.
  - If the proxy starts to use the requested generation for the requested engine, the result is `switched`. Whether it started to use it is read from the generation of that engine in `engines` of the state.
  - If, twice in a row, the state is not in the middle of a switch and does not show the requested generation, the result is `failed`.
  - The result is also `failed` when `stop_inspect_ms + 7 seconds` have passed.
  - If the proxy cannot be reached on the way, the result is `unconfirmed`.
- A request for a reload with a version of the managed configuration (`reload`) waits up to the time that resolving the names of the servers of the upstreams may take, plus 7 seconds. That time is `forward.resolve_timeout_ms` that the proxy returns in its state; for an old proxy that does not return it, it is the value in the configuration file that the admin process has read. This is 2 seconds longer than the time that the proxy itself waits.
- If the proxy refuses with a certificate (`tls`), the admin process makes the request again once after 1 second. This is because a certificate that was read at the moment when the certificate renewal (`acme renew`) was rewriting the files is refused only for that moment.
- For a `reload` request, all of these are treated as a result that is not known: there is no socket, no process accepts the connection, the response is not in the defined form, no response comes in time, the connection was closed without a response, or the proxy responded with `busy` (`reload under way`). This is because the request may have arrived and the reload may be continuing. The admin process asks for the state of the proxy every 250 ms for as long as it waited, and waits until the proxy is no longer reloading.
  - If the proxy is using the requested version and the number of reloads that switched the configuration (`replaced` of `config_reloads`) is larger than before the request, the result is applied.
  - Otherwise the result is `failed`.
  - If the proxy cannot be reached on the way, if it is still reloading at the end of the time, or if it still cannot respond to a query, the result is `unconfirmed`.

For how the results are handled, see "Generation Operations" and "Managed Configuration Operations" below. For the order of applying and what happens when an apply stops halfway, see "Applying" in the [operator reference](operator-reference.md).

### Log File

`GET /api/records` reads the log files that the proxy writes (`records.dir`). For the file names, sizes, and rotation, see "Log Files (`records`)" in the [operator reference](operator-reference.md).

- If the configuration has no `records`, this API gives 404.
- The admin process reads the files as the same OS user as the proxy. It does not read them (503) if the owner of the directory is different, if the group or other users have permissions, or if it is not a directory (a symbolic link cannot be used).
- The log files hold client addresses and paths. The admin API lets a viewer or above read them, so decide carefully which users you give the role viewer.

## Access from Outside

The admin process does not use TLS, so use it through a TLS listener of the proxy. Cookies are sent with `Secure`, so the admin screens can be used only over https. How you route to it depends on whether the configuration file has `managed`.

- A configuration without `managed`: write a route for an admin host in `forward.routes` (see the example below).
- A configuration with `managed`: write the route of the admin screens in `admin.route` (see "Overall Structure" and "`admin`" in the [operator reference](operator-reference.md), and "Admin Route with the Managed Configuration" below).

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

(The other setting keys of `forward` are omitted. This is an example where `admin.listen` is `127.0.0.1:9100`.)

- Certificate: put a certificate that has `admin.example.com` in its `hosts` on a TLS listener. A handshake for a name that it does not have fails.
- Upstream: write `admin.listen` as the address of the server.
- `engine`: an upstream that forwards to the admin process can also have `engine`, like the other upstreams. If you do not write it, requests are inspected by the default engine. For how to write it, see "`forward`" in the [operator reference](operator-reference.md), and for choosing an engine, see "Choosing the Inspection Engine" in the same document. A bypass route for an import (see "Bypassing Inspection for the Import Route" below) goes into the generations for the upstream engine of this upstream.
- `access`: with `allow_cidrs`, allow only the addresses of the users of the admin screens. For how the client address is decided and for what to be careful about when you use `access`, see "Client Address" and "Notes on using `access`" in the [operator reference](operator-reference.md). If any route has `access`, no route can have a port in its `host`.
- The global settings (the global access control and rate limits) and the host policies also apply to requests for this host, before a route is chosen (see "Access Control and Rate Limits" in the [operator reference](operator-reference.md)). Decide them to fit the number and speed of the users of the admin screens.
- Do not route this host through a plaintext listener. A route is chosen regardless of the listener, so if there is a plaintext listener that is not `redirect`, the password may flow unencrypted. Make plaintext listeners `redirect`.

Write the following two in either configuration.

- `admin.trusted_proxies`: write the address that the proxy connects to the admin process from (`127.0.0.1/32` if it is the same host). If you do not, every client has the address of the proxy, so the limit on login attempts (per client) is shared by everyone, and `client` in the audit log is the address of the proxy for every line.
- `admin.origin`: make it exactly the same as the origin of the URL that you open in the browser (do not write the port when it is 443). If it differs, changes, including login, get 403.

### Admin Route with the Managed Configuration

In a configuration that has `managed`, write the route of the admin screens in `admin.route` of the configuration file, and the proxy creates this route itself. For the form of the setting key, the certificate and `access`, the fact that the global settings and the host policies do not apply, and the hosts that cannot be written in a version of the managed configuration, see "`admin`" in the [operator reference](operator-reference.md); for the processing from the time a request is received, see "Order of Request Checks" in the same document. For the body limit, see "Body Size" below.

Requests to the admin route are inspected with the running generation of the default engine (`kernel.default_engine` of the configuration file; Coraza if it is not written). To edit the managed configuration in the admin screens, make `POST /api/managed/check` (check) and `POST /api/managed/apply` (the "Save and apply" operation) bypass routes. The bodies of these two requests are JSON of up to 12 MiB, with PEM certificate chains and private keys and many routes. If they are inspected, a rule may block them. You can write them in one `--routes` file together with the path of the rule import (see "Bypassing Inspection for the Import Route" below).

```json
[
  {"host": "admin.example.com", "path": "/api/generations", "action": "bypass"},
  {"host": "admin.example.com", "path": "/api/managed/check", "action": "bypass"},
  {"host": "admin.example.com", "path": "/api/managed/apply", "action": "bypass"}
]
```

- `path` does not end with `/`, so it matches only that path. The other `/api/managed` paths are inspected.
- A bypass route is part of a generation. Keep putting the same routes into every generation of the default engine. If you choose a generation in which they were forgotten, the bodies of `check` and `apply` are inspected from that generation on. When you change the default engine, put the same routes into a generation of the new default engine and choose it, and then change the default engine (for the steps, see "Choosing the Inspection Engine" in the [operator reference](operator-reference.md)).
- If a rule blocks a request to `check` or `apply` with 403 in a generation that has no bypass routes, the admin screens show "The proxy or the WAF refused the request. A body with PEM files or many routes can be blocked by the WAF. Check that /api/managed/check and /api/managed/apply are left out of the inspection."

### Bypassing Inspection for the Import Route

The body of `POST /api/generations` (import) is a large JSON that holds rule files. If it is inspected, the inspection of the rules may block the import. Make this path a bypass route of generations (see "Bypass Routes" in the [operator reference](operator-reference.md)).

```json
[
  {"host": "admin.example.com", "path": "/api/generations", "action": "bypass"}
]
```

- `path` does not end with `/`, so it matches only this path. `/api/generations/<fingerprint>` (reading and removing a generation) is inspected.
- A bypass route is part of a generation. Keep putting the same route into every generation of the engine that inspects the requests of the admin screens. The engine that inspects is the default engine in a configuration that has `managed`, and the engine of the upstream that forwards to the admin process in a configuration without `managed` (see "Access from Outside" above). If you choose a generation in which it was forgotten, imports are inspected from that generation on. When the engine that inspects changes (for example, when you change the default engine), move the same route into a generation of the new engine and then change the engine (see "Choosing the Inspection Engine" in the [operator reference](operator-reference.md)).
- This route takes effect only after the generation that holds it is in use. For the generation that first holds this route, import with the command (`rules import ... --routes <file>`). In an import from the admin screens, you can also add it by writing the host and the path in a row of the table (the body that is sent is JSON of the same form).

### CRS Tuning for the Admin Host

If the admin host is inspected with the CRS, the default settings of the CRS block the following requests of the admin screens. Both are let through with tuning that affects only the admin host. After the tuning, the inspection of other hosts does not change.

- PUT and DELETE: the CRS allows only `GET`, `HEAD`, `POST`, and `OPTIONS` by default, and blocks other methods with rule 911100. The admin API uses PUT and DELETE to change passwords, to change roles and the enabled or disabled state, to disable two-factor authentication, and to remove API tokens and generations. Without the tuning, a new user cannot make the first password change and cannot finish logging in.
- Password fields: the CRS also inspects the values of a JSON body. Depending on the sequence of symbols, a correct password may be judged to be SQL injection, and login or a password change is blocked (rule 942100 and others).

The two tunings go into the generation of the engine that inspects the admin host. The engine that inspects is the default engine in a configuration that has `managed`, and the engine of the upstream that forwards to the admin process in a configuration without `managed` (see "Access from Outside" above). With ModSecurity as the default engine and a generation that has the two tunings of this section, it has been confirmed that login, creating users and API tokens, `GET /api/status`, importing rules, and displaying the admin screens (Overview, Upstreams, Rule import) pass. PUT and DELETE have not been confirmed with ModSecurity. As the last item of this section says, try them before you choose the generation.

For the method tuning, add it at the end of `crs-setup.conf` in the CRS directory, and then import the generation. The rule files of the operator are loaded after the CRS rules (see "`rules`" in the [operator reference](operator-reference.md)), so if you write it there, it comes after the method rule and has no effect. When you use the CRS in an import from the admin screens, add it to `crs-setup.conf` in `admin.crs_dir`.

```text
SecRule REQUEST_HEADERS:Host "@rx ^admin\.example\.com(?::[0-9]{1,5})?$" \
    "id:1000100,phase:1,pass,nolog,t:none,t:lowercase,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT DELETE'"
```

Write the tuning of the password fields in a rule file of the operator, and pass it to the import with `--rules` (in the admin screens, "Rule files"). It is a phase 1 rule, so even if it is loaded after the CRS, it takes effect before the CRS rules that inspect the body.

```text
SecRule REQUEST_HEADERS:Host "@rx ^admin\.example\.com(?::[0-9]{1,5})?$" \
    "id:1000101,phase:1,pass,nolog,t:none,t:lowercase,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:json.password,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:json.current,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:json.new"
```

- Replace `admin\.example\.com` with the host of `admin.origin`. Write `.` as `\.`.
- Only the three password fields (`password`, `current`, and `new`) are excluded from the inspection. The name field, the name of a token, the query, and so on are still inspected after the tuning. A name that looks like an attack is blocked, so use another name.
- Use a rule ID that does not overlap other rules (for the IDs that the inspector process uses, see "Settings and Rules Added by the Inspector" in the [operator reference](operator-reference.md)).
- Before you choose a generation that has the tuning, try PUT and DELETE to the admin host and a login with a password that has symbols. For a request that was blocked, search the logs with the request ID that the screen shows, and `rules` gives the rule ID.

### Body Size

- The request body of a rule import (`POST /api/generations`) and of `POST /api/managed/check` and `POST /api/managed/apply` of the managed configuration is up to 12 MiB. Set `proxy.max_body` to 12 MiB (12582912) or more. The `max_body` of a route can only lower `proxy.max_body`, so to limit other routes, write a smaller `max_body` on those routes. The admin route (`admin.route`) has no `max_body`, so `proxy.max_body` is its limit.
- A long body of a bypass route is streamed without buffering, so a 12 MiB body does not use up `max_buffered_bytes` (see "Request Body Limits and Inspected Length" in the [operator reference](operator-reference.md)).
- If the request body of a check is over 12 MiB, or there are more than 192 files, the admin screens do not send it and show a message to that effect. If the body is only larger than `proxy.max_body` of the configuration file (read with `GET /api/config`), the screens send it and show "The body to send is larger than proxy.max_body of the configuration file. It is refused when you connect through the proxy." together with the result of the check. For a 413 that the proxy gave because of the body limit, the screens show "The body is over the limit of the proxy (proxy.max_body)."

### Slow Responses and Timeouts

- An import, choosing a generation, and a rollback can take tens of seconds or more (for the time limit, see "Slow responses" under "Listener"). The time setting keys of the proxy cannot be changed for each route. The wait for the header section of the response ends at whichever of `upstream_header_ms`, `response_idle_ms`, and `request_total_ms` runs out first (see "`proxy`: Times" and "Relations Between Values" in the [operator reference](operator-reference.md)). For a request that streams its body (for example, an import on a bypass route), `response_idle_ms` has no effect until the header section of the response arrives.
- When the wait runs out, the proxy returns 502 to the client (503 for `request_total_ms`). The admin process continues, and the import, choosing, and rollback run to the end. They are not stopped by the proxy cutting the connection.
- The admin screens treat a 502 or 504 whose body has no `result` as "Result unknown", and, for each screen, read again and show the state and the history, or the list of generations. A response that has `result` (including a 502 with `failed`, and a 503 with `unreachable` or `unconfirmed`) is read by that value. A 503 that has no `result` is read as a change that was refused, so make `request_total_ms` sufficiently longer than the time to receive the body plus the time of the inspection plus `upstream_header_ms`. When you use the API directly, for the same responses, check with `GET /api/status` and `GET /api/history` (for an import, `GET /api/generations`).
- Decide the time setting keys after you measure the time that imports and switches need. If you make `upstream_header_ms` longer, the proxy also waits longer when the upstream of another host is slow.

## Users and Roles

A user has a name, a role, and a password. A name is 1 to 32 bytes of lowercase letters, digits, `.`, `_`, and `-`. A password is 12 to 128 bytes of UTF-8 (a Japanese character is 3 bytes). The password is stored as a PBKDF2-HMAC-SHA256 hash (600000 iterations, 16-byte salt).

| Role | What it can do |
|---|---|
| `viewer` | Can read the state, the list and contents of generations, the switch history, and the logs. Can read the state of the managed configuration, the list of versions, the apply jobs, and the configuration history. Can manage their own password, two-factor authentication, and API tokens |
| `operator` | Everything a viewer can do. In addition, can read the audit log. Can import rules, choose generations, roll back, and remove generations. Can read the contents of the versions of the managed configuration, the certificate information, and the values of the configuration file, and can check, save and apply, apply by name, roll back, and remove |
| `owner` | Everything an operator can do. In addition, can create users, change roles and the enabled or disabled state, reset the passwords and two-factor authentication of other users, and view and remove the API tokens of everyone |

- Create the first owner with `admin bootstrap`. Later users are created by an owner with `POST /api/users`. Up to 1000 users can be created. When the number reaches 1000, creating a user is refused with 409 `the store has too many users`. Users cannot be removed, so disabled users also count toward the limit.
- There is no API to remove a user. Disable a user that is no longer used. A disabled user cannot log in, and their sessions and API tokens stop working. Even if you enable the user again, the API tokens that were deleted do not come back.
- A user that an owner created, and a user whose password an owner set with `POST /api/users/<name>/password`, cannot use other APIs at the next login until they change the password to their own.
- An owner's operations on themselves, and operations that would leave no owner, are refused.
  - Lowering your own role, disabling yourself: 403
  - Resetting your own password and two-factor authentication: 403 (change them with the account API)
  - A change that would leave no enabled owner: 409
- User management proceeds one operation at a time, in order, inside the admin process. It cannot happen that two owners lower each other at the same time and leave no owner.
- A change of role or state (changing the role, disabling, enabling, setting the password, disabling two-factor authentication) ends the sessions of that user. Lowering the role, disabling, and setting the password also invalidate the API tokens.
- A `PUT /api/users/<name>` that changes neither the role nor the enabled or disabled state changes nothing and returns that user with 200. It does not end sessions, and it is not written to the audit log.

## Login and Two-Factor Authentication

Login starts with `POST /api/login` (`{"name", "password"}`). `mfa` in the response shows the next step.

| `mfa` | Meaning | Next action |
|---|---|---|
| `off` | The session can be used | Use the API. If `must_change` is `true`, change the password |
| `verify` | A verification code of two-factor authentication is needed | `POST /api/login/mfa` |
| `setup` | `admin.mfa` is `required` and two-factor authentication is not set up | Set up two-factor authentication |

Which APIs a session can use depends on its state. An API that does not fit the state is refused with 403 and the following fixed sentence.

| State | Case | Usable APIs | `error` when refused |
|---|---|---|---|
| Waiting for a verification code | The password was right and the user has set up two-factor authentication. It ends in 5 minutes | `POST /api/login/mfa`, `POST /api/logout` | `second factor required` |
| Waiting for a password change | A user created by an owner, or a user whose password was set by an owner or by `admin reset` | `PUT /api/account/password`, `GET /api/session`, `POST /api/logout` | `password change required` |
| Waiting for two-factor setup | A user for whom `admin.mfa` is `required` and two-factor authentication is not set up | `POST /api/account/mfa/setup`, `POST /api/account/mfa/confirm`, `GET /api/session`, `POST /api/logout` | `second factor setup required` |
| Normal | None of the above | All APIs that the role allows | |

- When waiting for a password change and waiting for two-factor setup overlap, the APIs of both can be used.
- `GET /api/session` returns the state (`state`: `active`, `must_change`, `mfa_setup`), the remaining time, and the number of remaining recovery codes. For a session that is waiting for a verification code, it gives 403.

Two-factor authentication (MFA):

- It is a time-based one-time password (RFC 6238), made with HMAC-SHA1 with 6 digits, in time windows of 30 seconds. It also accepts the code of the window before and the window after the current one. It keeps the window that was used, and rejects the code of that window and of the windows before it.
- Setup:
  1. `POST /api/account/mfa/setup` (`{"password"}`) returns the secret (20 random bytes) as a base32 string (`secret`) and as an `otpauth://` address (`uri`). The secret is kept in the memory of the session for only 10 minutes.
  2. `POST /api/account/mfa/confirm` (`{"code"}`) verifies the code of the authenticator app, enables two-factor authentication, and returns the recovery codes. The other sessions of this user end, and a new session and a CSRF token are returned.
- Refusing the start and the confirmation of the setup: a user who has already set up two-factor authentication is refused for both with 409 `mfa is set already`. The confirmation is also refused with 409 `mfa setup was not started or has run out` if the setup was not started or 10 minutes have passed. If the code is wrong, it gives 403 `the code is wrong`.
- There are 10 recovery codes. A code is 16 characters (uppercase `A` to `Z` and `2` to `7`) and can be used once. They are returned only once, at setup, and only their SHA-256 is kept in the store. To make new ones before you use them up, disable two-factor authentication and set it up again. When `admin.mfa` is `required`, you cannot disable it yourself. Ask an owner to disable it with `DELETE /api/users/<name>/mfa` (for an owner's own, ask another owner to disable it, or use `admin reset`).
- To verify a code at login, send either `{"code"}` (6 digits) or `{"recovery"}` (a recovery code, sent in uppercase) to `POST /api/login/mfa`. If it is right, the session that was waiting for the code ends, and a new session (a new ID and a new CSRF token) is returned.
- Disabling: `DELETE /api/account/mfa` (`{"password", "code"}`; `code` is a verification code or a recovery code). When `admin.mfa` is `required`, it is refused with 403 `mfa is required`. An owner can disable the two-factor authentication of other users with `DELETE /api/users/<name>/mfa`.
- With `required`, the API tokens of a user who has not set up two-factor authentication cannot be used.
- The secret of two-factor authentication is kept as it is in the file of the user (because the secret itself is needed to calculate the verification code). Protect it by making the directory of the store 0700.

## Lockout and Attempt Limits

| Target | Rule |
|---|---|
| Per user | After 5 failures in a row, the user is locked out for 15 minutes. An attempt during the lockout also counts as a failure and restarts the 15 minutes. A success resets the failure count |
| Per client | Up to 30 attempts per minute. An attempt over the limit is refused with 429 `too many tries` before any hash is calculated, and does not count as a failure of the user |

- These count as a failure of the user: a wrong password at login, a wrong verification code at login (`POST /api/login/mfa`), a wrong verification code for disabling two-factor authentication, and a wrong password in an API that verifies the password (changing the password, setting up and disabling two-factor authentication, creating a token). A login of a disabled user or of a locked-out user also counts as a failure of that user. For a user who has set up two-factor authentication, a right password does not reset the failure count. It is reset when the verification code is right. This keeps someone who knows the password from resetting the failure count at every login and trying verification codes without end. A wrong code at the confirmation of the two-factor setup (`POST /api/account/mfa/confirm`) is not counted as a failure of the user or as an attempt of the client, and is not written to the audit log. The response is 403 `the code is wrong`.
- These count toward the attempt count of the client: a login, a verification code at login, an API that verifies the password (the same as above), and an API token that does not match. A request with a correct API token and the confirmation of the two-factor setup are not counted. A login is counted even if it succeeds. A request with an API token from a client that has used up its count is refused with 429 `too many tries` before the token is verified, even if the token is right.
- It tracks up to 4096 clients. When the table is full of clients that tried within the last minute, it does not accept other clients.
- A login gives the same response (401 `invalid credentials`) for a name that does not exist, a disabled user, a locked-out user, and a wrong password. It calculates the hash once even for a name that does not exist or a user who is locked out, so the time it takes does not tell them apart either. A wrong verification code at login also gets the same 401 `invalid credentials`. In other APIs the error is 403: for the password, `the password is wrong` (`the current password is wrong` for a password change), and for the verification code, `the code is wrong`.
- The reason is written only to the audit log (`unknown user`, `disabled`, `locked`, `wrong password`, `wrong code`). A name that does not exist is not written. This keeps a password that was typed into the name field out of the log.
- The failure count and lockout state of each user and the attempt count of each client are only in the memory of the admin process. They disappear when it restarts.
- When a user is changed (`admin reset`, an owner's operation, a password change, or setting up or disabling two-factor authentication), the lockout is released and counting starts again from the next failure.

## Sessions

- When a login succeeds, a session is created and the cookie `tukuyomi_admin` is returned. The value of the cookie is 43 characters: 32 random bytes in base64url.

  ```text
  Set-Cookie: tukuyomi_admin=<43-characters>; Secure; HttpOnly; SameSite=Strict; Path=/
  ```

  No expiry is set (the cookie disappears when the browser is closed). At logout, a cookie with `Max-Age=0` is returned to delete it.
- The admin process keeps a session by the SHA-256 of its ID, and does not hold the ID itself. `session` in the audit log gets only the first 8 digits of that SHA-256.
- Each session has a CSRF token (another 32 random bytes, 43 characters). It is returned in the response to login and by `GET /api/session`.
- A session ends in these cases:
  - It was not used for `admin.session_idle_ms` (counted again at every request)
  - `admin.session_total_ms` has passed since it was created
  - The user logged out
  - The password, role, enabled or disabled state, or two-factor authentication of the user was changed (including `admin reset` and an operation of another admin process). When users change their own password or two-factor authentication, a new session is returned for that request and the other sessions end
  - The user was disabled
  - The admin process was restarted
- A user can have up to 16 sessions that are waiting for a verification code, and up to 16 normal sessions. When a 17th is created, the oldest one ends and `logout` (with `reason` `too many sessions`) is written to the audit log. Repeating the wait for a verification code does not end normal sessions. The admin process keeps up to 1024 sessions in all, and when it is full, a new session cannot be created (login gets 503).
- A request has either the cookie of a session or an API token. If it has both, it gets 400. Even when the `Authorization` header is not Bearer, it gets 400 if it comes with the session cookie, so if you put HTTP authentication such as Basic authentication in front of the admin screens, requests after login get 400. A request that has the cookie twice is treated as having no session and gets 401.

## CSRF and Origin

A request other than `GET` and `HEAD` (a change) has these two checks.

- `Origin`: if the header is present, it must be exactly the same as `admin.origin`, and there must be only one. If not, it gets 403 `forbidden`. A request without an `Origin` header (a request from a program) passes. It also applies to the login request.
- `X-CSRF-Token`: for a session request, it must have exactly one value that is the same as the CSRF token of that session (compared in constant time). If it differs or is missing, it gets 403 `forbidden`. It is not needed for a request with an API token (because it does not use a cookie).

For the order of the checks, see "Order of Admin API Checks" under "Response Format".

- The admin screens keep the CSRF token only in memory and attach it to each changing request. When you reopen the page, they receive the token again with `GET /api/session`. For a session that is waiting for a verification code, `GET /api/session` gives 403 and no CSRF token can be received, so if you reopen the page, you start again from login.
- A request that was refused because of an `Origin` mismatch or a CSRF mismatch is written to the audit log when the user is known (`reason` is `origin` or `csrf`).

## API Tokens

Tokens for programs to use the admin API.

- The form is `tkc_<16-hex-digits>_<43-characters>`. The first part is the ID of the token, and the last part is the secret (32 random bytes in base64url). The whole token is returned only once, when it is created. Only the SHA-256 of the secret is kept in the admin store.
- Send it as `Authorization: Bearer <token>`. It cannot be sent together with the cookie of a session (400).
- Creating: `POST /api/account/tokens` (`{"name", "role", "days", "password"}`). A user with a session creates it for themselves. The current password is needed.
  - `name`: 1 to 64 printable ASCII bytes
  - `role`: the user's own role or lower. A higher role is refused with 403 `the role is above the role of the user`.
  - `days`: 1 to 365. The token expires after this number of days from the time it was created.
  - One user can have up to 50 tokens (more is refused with 409 `the user has too many tokens`). The 50 includes expired tokens. Expired tokens are not deleted automatically, so delete them with `DELETE /api/account/tokens/<id>`.
  - The response is the information of the token (`id`, `owner`, `name`, `role`, `created`, `expires`, `expired`, `last_used`; the times are epoch milliseconds) with `token` (the whole string) added.
- APIs it can use: status, generations, import, choosing, rollback, removal, history, logs, the audit log, the managed configuration, and the values of the configuration file (those with "yes" in the "Token" column of "API Paths" below). It cannot be used for the account APIs and the APIs for managing users (403). This keeps a token of an owner from resetting the password or the two-factor authentication of another user and logging in as that user.
- The role of the request is the role of the token (the role of the owner or lower). A CSRF token is not needed. The `Origin` of a changing request, if there is one, must be the same as `admin.origin`.
- Every time it is used, these are checked:
  - The form is correct, the store has that ID, and the SHA-256 of the secret matches
  - The owner exists, is not disabled, and has a role that is the role of the token or higher
  - The token was created after the owner's "tokens made before this time are invalid" time
  - The expiry has not passed
  - If `admin.mfa` is `required`, the owner has set up two-factor authentication
- It becomes invalid in these cases (even if the file cannot be deleted, it no longer passes the checks above):
  - The expiry came, or it was removed (`DELETE /api/account/tokens/<id>`; for an owner, `DELETE /api/tokens/<id>`)
  - The owner was disabled
  - The role of the owner was lowered (all tokens of the owner become invalid)
  - The password of the owner was changed (by the owner, set by an owner, or `admin reset`)
- A token that does not match counts toward the attempt count of the client (see "Lockout and Attempt Limits" above). It is not written to the audit log. This keeps anyone who can send requests from filling the audit log.
- The last-used time (`last_used`) is written at most once every 10 minutes. If it cannot be written, the request still passes.
- An example of use (put the token in `$TOKEN`):

  ```bash
  curl -sS -H "Authorization: Bearer $TOKEN" https://admin.example.com/api/status
  curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"generation":"<target-fingerprint>","expect":"<current-fingerprint>"}' \
    https://admin.example.com/api/activate
  ```

## Audit Log

The admin process keeps logins, changes, and refused requests as lines of the audit log.

| Field | Content |
|---|---|
| `ts`, `type` | The same as in the logs. `type` is `audit` |
| `id` | The request ID (`X-Request-ID`). Not present in the lines of commands (`admin bootstrap`, `admin reset`) |
| `actor` | The name of the verified user. Not present if the user could not be verified. It is not taken from the request headers |
| `session` | The first 8 digits of the SHA-256 of the session ID. The ID itself is not written |
| `auth` | The authentication method when it is not a session: `token:<id>`, `bootstrap`, `reset` |
| `client` | The client address. Not present in the lines of commands |
| `action` | The operation (the table below) |
| `target` | The target of the operation (the name of a user, the ID of an API token, the fingerprint of a generation, the name of a version of the managed configuration). Not present for a login with a name that does not exist |
| `result` | `ok`, `denied` (refused), `failed` (the operation was tried and failed) |
| `reason` | A fixed word (`wrong password`, `locked`, `expect`, `store`, and so on) |
| `before`, `after` | Before and after a change: the role, the enabled or disabled state, the fingerprint of a generation, the name of a version of the managed configuration |

Passwords, API tokens, verification codes, recovery codes, secrets of two-factor authentication, and cookies are not written.

| `action` | Case |
|---|---|
| `login` | A successful login (`ok`) and a failed one (`denied`; `reason` is `unknown user`, `wrong password`, `locked`, `disabled`). When a session cannot be created (`failed`, `no session`). When the password of a user who has set up two-factor authentication is right, `reason` is `second factor pending` |
| `mfa` | Success and failure of a verification code (`wrong code`, `locked`). A success with a recovery code has `reason` `recovery code` |
| `lock` | A lockout of a user (`reason` is `too many failures`) |
| `logout` | A logout. When a session was ended because there were too many, `reason` is `too many sessions` |
| `password`, `mfa_setup`, `mfa_confirm`, `mfa_disable` | A user's own password; starting and confirming the two-factor setup; disabling two-factor authentication. An error of the password or the verification code is `denied` (`wrong password`, `wrong code`, `locked`). However, no line is written for an error of the verification code of `mfa_confirm` |
| `token_create`, `token_revoke` | Creating (`after` is the role) and removing an API token |
| `user_create`, `role`, `disable`, `enable`, `user_password`, `user_mfa` | User management by an owner |
| `import`, `activate`, `rollback`, `remove` | Generation operations (see "Generation Operations" below) |
| `managed-import` | In `POST /api/managed/apply` (the "Save and apply" operation), before the version is saved (see "Save and Apply" under "Managed Configuration Operations" below) |
| `managed-apply`, `managed-activate`, `managed-rollback` | The "Save and apply", "Apply by name", and "Roll back" operations of the managed configuration (see "Managed Configuration Operations" below) |
| `managed-remove` | Removing a version of the managed configuration |
| `create`, `reset` | The commands `admin bootstrap` and `admin reset` |
| `action` of each API | The name of an API that was refused; a `denied` line is written (see the note below). Besides the `action` values of the generation operations and the managed configuration above, the names are `status`, `generations`, `generation` (reading one generation), `history`, `records`, `audit`, `session`, `users`, `user_update` (`PUT /api/users/<name>`), `tokens`, `managed` (`GET /api/managed`), `managed-versions`, `managed-version` (reading one version), `managed-job`, `managed-history`, `managed-check`, `managed-certificates`, and `config` (`GET /api/config`) |

- A request that is refused by a check of an API gets a `denied` line if the user is known. `reason` is `origin`, `csrf`, `token` (an API that cannot use an API token), `role`, `state`, `second factor pending`, `password change`, or `second factor setup`.
- A request that is refused at a stage where the user is not known is not written. Examples are a request with neither a session nor an API token, an API token that does not match, a login over the count of the client, a login with a wrong `Origin`, and a path that does not exist. This keeps anyone who can send requests from pushing out the old lines.
- A line of a generation operation has the fingerprint of the target generation in `target`. An `ok` line of `activate` and `rollback` also has the generation that was chosen before in `before` and the generation that was requested in `after`. An `ok` line is written before the change, so it is not a line that shows success. Check how the operation ended with the `failed` line that follows it and with the switch history. The `reason` of `failed` is `expect`, `store`, `refused`, `failed`, `unconfirmed`, or `history` (the line of the history could not be written), and for an import, `store` and `trial`. When the operation was refused before the change, it is `denied` and `reason` is `expect`, `engine`, `version` (a proxy that does not return the state of each engine), `busy`, or `unreachable`. For a removal, a generation that is chosen is `chosen`, and a rollback target is `rollback target`.
- A line of the managed configuration has the name of the target version in `target`. An `ok` line of `managed-apply`, `managed-activate`, and `managed-rollback` is written before the apply job asks the proxy, with the version before the change in `before` and the version after it in `after`. It is not a line that shows success, so check how the operation ended with the lines that follow and with the configuration history.
  - When the operation was refused before the change, it is `denied`, and `reason` is `managed`, `configuration`, `expect`, `unreachable`, `busy`, `unmanaged`, `engine` (in `managed-activate` and `managed-rollback`, when the rules store has no chosen generation for an upstream engine of the version), or a word for the result of the apply job (`current changed`, `no version`, `store`).
  - When the operation failed after the line before the change was written, it is `failed`, and `reason` is a word for the result of the apply job (`refused`, `busy`, `error`, `failed`, `unconfirmed`, `not recorded`) or `history` (the line of the configuration history could not be written). When the apply job could not be started, it is also `failed`, and `reason` is `time`, `stopping`, or `thread`.
  - The `reason` of a failure of `managed-import` is `store`, `version`, or `configuration`. For a removal, a refusal is `managed`, `configuration`, `chosen` (the selected version), or `rollback target` (the rollback target), and a failure is `store`.
  - A check and an API that only reads are not changes, so they write no line except when they are refused at the entrance.

How it is written:

- A change is made after the audit log line is written first. If the line cannot be written (for example, the disk is full), the change is not made and the request is refused with 503 `unavailable`. The line is synced to disk and then also written to standard error.
- The exception is logout. It is an operation that revokes authority, so the session ends even if the line cannot be written.
- When a change fails, a `failed` line is written afterwards (the response does not change even if it cannot be written).
- It is stored in `audit/audit.log` under `admin.store.dir`, as one JSON object per line. When one file goes over 16 MiB, it moves to the next file, and 8 files are kept (`audit.log` and `audit.1.log` to `audit.7.log`). The same lines are also written to standard error (the journal).
- `GET /api/audit` (operator or above, API tokens allowed) returns the newest 200 lines, newest first, as `{"entries": [...]}`. It reads from the end of the file, and reads the older files if it needs more. It reads only up to the last 1 MiB of one file, and if the file is larger than that, it stops there without reading the older files. Lines that cannot be read are skipped.

## Generation Operations

A viewer can read the list and contents of generations. An operator or above can import, choose, roll back, and remove.

### Listing and Contents

- `GET /api/status`: returns the following.
  - `current`: the fingerprint of the generation that the rules store has chosen for the default engine (`null` if there is none)
  - `reachable`: whether the proxy can be reached. A proxy that cannot respond because of the limit of concurrent connections is treated as reachable
  - `proxy`: the state of the proxy (`generation`, `mode`, `engine`, `phase`, `switching`, `engines`, `reloading`, `ready`) and numbers (`uptime_ms`, `requests`, `blocked`, `policy_refused`, `upstream_failures`, `config`, `managed`, `resolve_timeout_ms`, `config_reloads`). It is the response of the proxy as it is, and `null` if it cannot be read. `generation`, `mode`, `engine`, and `phase` are the values that the proxy gave for the default engine. `engines` is an array of `{"engine", "generation", "mode", "phase"}` for each engine that runs in the proxy (in the order of the engine names), and `ready` is whether the state is one for which `/readyz` responds that the proxy is ready. A proxy of an earlier version does not send `engines`, `reloading`, or the numbers, so whatever was not sent is `null` (the response is not refused). `reloading` is whether a configuration reload is in progress. The contents of the numbers are as follows; for details, see "Control Socket" in the [operator reference](operator-reference.md)
    - `uptime_ms`: milliseconds since the proxy started
    - `requests`: the number of requests (all 7 `class` values of the log)
    - `blocked`: the number of requests that rules blocked
    - `policy_refused`: the number of requests that the global `access` and `rate_limit`, and the host policies, refused
    - `upstream_failures`: the failure count of the servers of the upstreams of the running configuration. When the configuration is switched by a configuration reload, it is counted again from 0
    - `config`: the SHA-256 of the running configuration file (64 lowercase hexadecimal digits)
    - `managed`: the name of the version of the managed configuration that is running (64 lowercase hexadecimal digits). `null` for a configuration without `managed`
    - `resolve_timeout_ms`: `forward.resolve_timeout_ms` of the running configuration
    - `config_reloads`: the number of configuration reloads by SIGHUP and by `reload` of the control socket. `{"replaced", "refused"}` (the number switched and the number refused)
  - `rollback_to`: the generation that would be chosen if a rollback of the default engine were requested now (`null` if there is none)
  - `default_engine`: `kernel.default_engine` when the admin process started (`coraza` or `modsecurity`; `coraza` if it is not written). If only one of the admin process and the proxy was restarted, it may differ from `engine` of `proxy`
  - `engines`: an array of `{"engine", "current", "rollback_to"}` for each engine (in the order `coraza`, `modsecurity`). These are the generation that the rules store has chosen for that engine and the rollback target of that engine. `current` and `rollback_to` above are the values of the engine of `default_engine` in this array
  - `crs`: `{"available", "files"}`. Whether `admin.crs_dir` exists, and the names of the `.conf` files of the CRS that an import can leave out
- `GET /api/generations`: `{"reachable", "generations"}`. For each generation, newest first, it returns `fingerprint`, `made` (the time it was made, in seconds since the epoch), `mode` (`block`, `detect`, or `unknown` if the manifest cannot be read), `engine` (`coraza`, `modsecurity`, or `unknown` if the manifest cannot be read), `routes` (the number of bypass routes), `current` (whether the rules store has chosen it for any engine), and `serving` (whether it is running in the proxy for any engine).
- `GET /api/generations/<fingerprint>`: in addition to the above, it returns `load` (the order of loading) and `files` (`path`, `size`, `sha256`). `routes` here is an array of routes (`host`, `path`, `action`), not a number. If a route has no `host`, `host` is not present. A generation that is not in the rules store gives 404.

The "Chosen" generation and the "Serving" generation are different, and there is one of each for each engine. Even if a generation is chosen in the rules store, it is not running if the proxy failed to switch to it, or if that engine is not running. The admin screens show a warning when the two differ for any engine while no switch is in progress, or when a generation is chosen but that engine is not running.

### Import

`POST /api/generations` (operator or above, API tokens allowed) creates a generation in the same order as `rules import`. It collects the files, puts them in the rules store temporarily, runs a trial with an inspector process, and, if the trial passes, makes them a generation. It does not choose the generation.

The body is a JSON object, and all keys can be omitted.

| Key | Content |
|---|---|
| `rules` | The rule files. An array of `{"name", "data"}`, loaded in the order written. `name` is a name without a directory (the same rule as `--rules`), and `data` is standard base64 (with padding) |
| `data` | The data files. The form is the same as `rules` (it corresponds to `--data`) |
| `crs` | `true` uses the CRS of `admin.crs_dir`. A request cannot give a path. If there is no `admin.crs_dir`, it gives 400 |
| `crs_off` | An array of the names of the `.conf` files of the CRS that are not loaded (it corresponds to `--crs-off`) |
| `routes` | An array of bypass routes (the same form as a `--routes` file) |
| `engine` | The name of the inspection engine (it corresponds to `--engine`). `coraza` or `modsecurity` (lowercase). If omitted, it is the default engine of the admin process (the same value as `default_engine` of `GET /api/status`) |
| `detect_only` | `true` makes a detect-only generation |
| `accept_block` | `true` does not make it a failure even if a request of the trial is blocked |

- The limits and the rules for names are the same as for `rules import` (see "`rules`" in the [operator reference](operator-reference.md)). Up to 128 files, 2 MiB per file, and 8 MiB in all. A file over 2 MiB is refused before it is decoded.
- If `engine` is not the name of an engine, or if that engine cannot be used, it is refused with 400 before the files are collected. Nothing is put in the rules store temporarily, and no trial is run. The sentence is one of these:
  - `engine is not the name of an engine (coraza or modsecurity)`
  - `kernel.engines has no inspector for the engine of the generation` (the configuration has no inspector process for that engine)
- The trial is the same as for `rules import`: the admin process starts one inspector process and inspects three fixed requests (`GET /`, a form `POST /`, and a JSON `POST /`). The inspector process is the one for the engine in `engine` (`kernel.inspector` for `coraza`, `kernel.engines` for `modsecurity`). It uses the values of `kernel`, and `ready_wait_ms`, `inspect_wait_ms`, `stop_inspect_ms`, and `drive_slice_ms` of `proxy`.
- Import, choosing, rollback, and removal proceed one at a time, in order, inside the admin process. If another change is in progress, it does not wait and gets 409 `a change of the rules is under way`. If a command or another process holds the lock of the rules store, it gets 409 `the rules store is in use by another command`.

The response:

| Status code | Case | Body |
|---|---|---|
| 200 | A generation was created | `{"fingerprint", "result", "trial"}`. `result` is `created`, `existing` (the same generation was already there) or `repaired` (a damaged generation with the same fingerprint was made again) |
| 400 | The input was refused (including an engine that cannot be used) | `{"error"}`. If there is the name of an input file, it is added to `subject` (bytes outside 0x20 to 0x7e are written as `\xNN`, up to 128 bytes) |
| 409 | Refused by the rules store, or another change is in progress | `{"error"}` |
| 422 | The trial failed. No generation is created | `{"error": "the trial failed", "trial": {..}}` |
| 500 | The trial could not be run | `{"error"}` |
| 503 | The audit log line could not be written | `{"error": "unavailable"}` |

`trial` is `{"passed": true, "accepted": [..]}` when it passed and `{"passed": false, "failure": <message>}` when it failed. If there is output from the inspector process, `detail` (up to 512 bytes) is added, whatever the value of `passed`. Even if all requests of the trial passed, if the inspector process or the work directory was not cleaned up, `passed` is `false` and `failure` is `the inspector did not stop cleanly; a process or a directory may be left behind`, and the response is 422 and no generation is created. In that case, check that no process or directory is left on the host. `accepted` is the blocks (`{"kind": "block", "probe", "rule", "phase", "status"}`) and detections (`{"kind": "detected", "probe", "rule", "status"}`) that the trial accepted. `probe` is the name of the request of the trial (`GET /`, `POST / with a urlencoded body`, `POST / with a JSON body`).

### Choosing and Rolling Back

`POST /api/activate` (`{"generation", "expect"}`) and `POST /api/rollback` (`{"engine", "expect"}`; `engine` can be omitted) change the generation that the rules store has chosen and make the proxy switch. They need an operator or above, and API tokens can be used. A switch is made for one engine. For `activate` it is the engine of the generation, and for `rollback` it is the engine in `engine` (the default engine of the admin process if omitted). The chosen generation and the rollback target exist for each engine (see "Chosen Generation per Engine" in the [operator reference](operator-reference.md)).

- A fingerprint is 64 lowercase hexadecimal digits. If not, it gives 400 `a generation is not 64 lowercase hexadecimal digits`.
- If `engine` of `rollback` is not lowercase `coraza` or `modsecurity`, it gives 400 `engine is not the name of an engine (coraza or modsecurity)`.
- `expect` is the "Chosen generation" that you saw on the screen for that engine. If someone else or a command has chosen again since you saw the screen, it is refused with 409, to keep you from overwriting by choosing again on an old screen.
  - `expect` of `activate` is the generation that is chosen for the engine of the generation in `generation`. If no generation is chosen for that engine, write `null`. If you write `null` while a generation is chosen, it is refused with 409.
  - Always write the key `expect` for `activate`. If you omit it, it gives 400. `expect` of `rollback` is a 64-character string.
- If no generation is chosen for that engine, you can choose one with `expect` set to `null`. The screen also shows the choose operation for a generation of an engine that has no chosen generation. The first generation of the default engine is needed for the proxy to start, so choose it with the command (`rules activate`) (see "Choosing the Inspection Engine" in the [operator reference](operator-reference.md)).
- If you give `generation` the generation that is chosen now, the chosen generation of the rules store does not change, and only the proxy is made to switch (in the admin screens, "Apply to the proxy"). If that engine is not running in the proxy, that engine is started (in the admin screens, "Start the engine"). Even if you give a generation that is not chosen yet, an engine that is not running in the proxy is started with that generation. `rollback` also starts that engine with the rollback target if that engine is not running in the proxy.

Steps:

1. The generation is in the rules store (`activate`; if not, 404 `no such generation`). For a rollback, the rollback target is decided (below).
2. In the rules store, the generation that is chosen for that engine is the same as `expect` (if no generation is chosen, `expect` is `null`). If not, 409 (no change. Nothing is written to the history. The audit log gets `denied` with `reason` `expect`).
3. The engine of the generation to switch to can be used. If not, 409 with `{"error": <message>}` (no change. Nothing is written to the history. The audit log gets `denied` with `reason` `engine`). The sentence is the same as `kernel.engines has no inspector for the engine of the generation` of the 400 of "Import" above. A generation whose manifest cannot be read is not refused here, but is refused at the stage where the rules store chooses the generation.
4. The state of the proxy is asked.
   - It cannot be reached: 503 `the proxy cannot be reached`. The rules store is not changed, and `unreachable` is written to the history (the audit log also gets `denied` with `reason` `unreachable`).
   - It accepts the connection and closes without responding (the limit of concurrent connections): 503 `the proxy is busy`. The rules store is not changed, and nothing is written to the history (the audit log gets `denied` with `reason` `busy`).
   - The state has no `engines` (a proxy of an earlier version that does not support the choice per engine): 409 `the proxy does not report its engines`. The rules store is not changed, and nothing is written to the history (the audit log gets `denied` with `reason` `version`). Use the same build for the admin process and the proxy (see "Version Updates" in the [operator reference](operator-reference.md)).
5. An audit log line is written (if it cannot be written, 503 `unavailable`, and nothing is changed).
6. The rules store chooses the generation. The choice is made inside the lock, and `expect` is verified once more. If another process chose in the meantime, it is not overwritten and the result is 409.
7. The proxy is asked to switch, and the admin process waits for the end (see "Control Socket" above).
8. One line is written to the history and the response is returned.

The response (the body is `{"result", "engine", "from", "generation", "chosen"}`; a failure also has `error`):

| `result` | Status code | Meaning | `chosen` |
|---|---|---|---|
| `switched` | 200 | The proxy now uses that generation | `true` |
| `unchanged` | 200 | The proxy was already using that generation | `true` |
| `refused` | 409 | The proxy refused (`the proxy refused the switch`). This includes the case where the proxy found that `expect` did not match | `true` |
| `failed` | 502 | The proxy did not switch (`the proxy did not switch`). This includes the case where it did not switch in time | `true` |
| `unreachable` | 503 | The proxy cannot be reached. The rules store was not changed | `false` |
| `unconfirmed` | 503 | The rules store was changed, but the proxy did not say the result (`the proxy did not say how the switch ended`) | `true` |

- `chosen` shows whether that generation is now chosen in the rules store.
- Even if the switch ends in `refused`, `failed`, or `unconfirmed`, the rules store is not put back. With `refused` and `failed`, the proxy keeps using the previous generation. With `unconfirmed`, it is not known which generation the proxy is using, so check `generation` of that engine in `proxy.engines` of `GET /api/status`. When the proxy is restarted, each engine starts with the generation that the rules store has chosen. If you do not want to use that generation, choose the previous generation again.
- If a line could not be written to the history, `"history": "not written"` is added to the response.
- Only the six cases in the table above have `result` and `chosen`. The body of the other failures is only `{"error": <message>}`. These are: the 409 where `expect` does not match (`the chosen generation is not the one that was expected`), the 503 `the proxy is busy`, the 409 where the rollback target cannot be decided, the 409 where the engine of the generation cannot be used, the 409 for a proxy that does not return the state of each engine, and the 409 where the choice was refused by the rules store itself. Among these, a line (`refused`) is written to the history only when the choice was refused by the rules store itself.

The rollback target:

- It is the `from` of the newest line in the history that is a line of that engine, whose result is `switched`, and whose `from` and `to` differ. A line without `engine` (a line that an admin process of an earlier version wrote) is used as a line of that engine only when the engines of the generations of `from` and `to` are both that engine (it is not used if the engine of a generation cannot be read).
- However, this applies only when the `to` of that line is the generation that the rules store has chosen now for that engine. After a switch failed, or after a generation was chosen with a command, the end of the history does not match the chosen generation, so a rollback is not possible (409 `the history does not end at the chosen generation`). If there is no `switched` line, it gives 409 `there is no switch to go back from`.
- If the generation to go back to is not in the rules store, it gives 409 `the generation to go back to is not in the store`.
- A rollback is also entered in the history, as `rollback`. If you roll back again right after, it goes back to the original generation.

### Removal

`DELETE /api/generations/<fingerprint>` (operator or above, API tokens allowed) removes a generation from the rules store. It cannot be undone. The following generations are not removed, and are refused with 409.

| Generation | `error` |
|---|---|
| The generation that the rules store has chosen (for any engine) | `the generation is the one the rules store chooses` |
| A generation that is a rollback target (for any engine) | `the generation is the target of a rollback` |
| A generation that is running in the proxy (for any engine) | `the generation is used by a running proxy` |

A generation that is not in the rules store gives 404. If another change is in progress, it is refused with 409 `a change of the rules is under way` (inside this admin process) or `the rules store is in use by another command` (a command or another process holds the lock of the rules store). If a command chose a generation after the check for the removal, it gives 409 `the generation is the current one`. On success, it returns `{"removed": <fingerprint>}`.

## Managed Configuration Operations

The managed configuration is a configuration in which the sites and certificates, the upstreams, the routes, the default upstream, the global access control and rate limits, and the host policies are kept as versions in a managed store separate from the configuration file, and are changed from the admin screens and the admin API. For whether to use the managed configuration, the form of the managed store and versions, the commands, and the order of applying, see "Managed Configuration" in the [operator reference](operator-reference.md). This section describes the operations of the admin API.

- A viewer can read the state, the list of versions, the apply jobs, and the configuration history. An operator or above can read the contents of a version, the certificate information, and the values of the configuration file, and can check, save and apply, apply by name, roll back, and remove. All of them can be used with API tokens.
- The contents of a version and the values of the configuration file are limited to an operator or above because a rewrite of a route (`rewrite`) can hold a secret such as an authentication value for the upstream.
- These APIs can be used only if the configuration file had `managed` when the admin process started. If it did not, `GET /api/managed` returns `{"managed": false}`, `GET /api/config` can be used as when there is one, and the others are refused with 409 `the configuration has no managed object`.
- The managed store is the directory that `managed.dir` pointed to when the admin process started, and it is opened at every request. If it cannot be opened, the response is 500 with a sentence of the managed store. A check and a change read the configuration file again, and if `managed.dir` differs from that at start, they are refused with 409 `the managed object of the configuration names another directory than at the start`. If you change whether `managed` is present or change `managed.dir`, restart the admin process.

### State and Listing

- `GET /api/managed`: returns the following.
  - `managed`: `true`
  - `current`: the version that the managed store has selected (`null` if there is none)
  - `serving`: the version that is running, as the proxy responded on the control socket (`null` if the state cannot be read, or if the proxy is running with a configuration without `managed`)
  - `reachable`: whether the proxy can be reached. A proxy that cannot respond to a query because of the limit of concurrent connections is treated as reachable
  - `reloading`: whether the proxy is reloading the configuration (`null` if not known)
  - `rollback_to`: the version that would be applied if a rollback were requested now (`null` if there is none; see "Applying and Rolling Back by Name" below)
  - `job`: the last apply job (`null` if there is none; see "Apply Jobs" below)

  If the configuration history cannot be read, it gives 503.
- `GET /api/managed/versions`: `{"reachable", "versions"}`. For each version, newest first, it returns `name` (the name of the version; the 64 lowercase hexadecimal digits of its SHA-256), `made` (the modification time of the file of the version, in seconds since the epoch), `current` (whether it is selected), and `serving` (whether it is running).
- `GET /api/managed/versions/<version>` (operator or above): in addition to the above four, it returns `version` (the JSON of the version as it is in the managed store). A version specifies files only by SHA-256, and no response holds the contents of a file. A version that is not in the managed store gives 404, and a version whose contents do not match its name gives 500.

The "Selected" version and the "Running" version are different. When an apply stopped halfway, or when a version was selected with a command, the two may differ. If you apply either version again, the two become the same. When they differ, the admin screens show a notice and two operations to make them the same (see "Admin Screens" below).

### Certificate Information

`GET /api/managed/certificates/<version>` (operator or above) returns the state of the certificates in the managed store for each site of the version, in the order of the version. The response is `{"name", "sites"}`, and each site has the following keys.

| Key | Content |
|---|---|
| `name` | The name of the site |
| `kind` | `files` (files of a certificate chain and a private key), `acme`. `null` if it is in neither form |
| `chain`, `key` | For a `files` site, the names (SHA-256) of the files of the certificate chain and the private key. The contents are not returned |
| `hosts` | The hosts of an `acme` site. Only when it is in a readable form |
| `state` | The table below |
| `not_after`, `expired` | The expiry of the first certificate of the certificate chain (in seconds since the epoch), and whether it has expired by the clock of the server. Only when the expiry could be read |
| `names`, `more` | The host names in the certificate (DNS names, up to 100) and the number of other names. Only when the names could be read too. `[]` shows that the certificate has no DNS name |

`state` is the first of the following that matches.

| `state` | Meaning |
|---|---|
| `unreadable` | The file of the certificate chain or the private key cannot be read (a symbolic link, not a regular file of 1 MiB or less, a `files` site whose contents do not match the name, and so on). A certificate that is in neither form is also this |
| `missing` | For a `files` site, the file of the certificate chain or the private key is not in the managed store |
| `waiting` | For an `acme` site, it has not been issued yet (the certificate chain or private key that `acme renew` writes is missing) |
| `unparsed` | The names or the expiry cannot be read from the first certificate of the certificate chain |
| `present` | For a `files` site, the certificate chain can be read and the file of the private key exists |
| `issued` | For an `acme` site, the certificate chain can be read and the file of the private key exists |

- The response is the state of the certificates on the disk, not the state of the certificates in the memory of the proxy. After `acme renew`, the two differ until the proxy reads the certificates again (SIGUSR2). The version does not have to be the running one.
- `present` and `issued` show only that the files exist and that the certificate chain can be read. It is not verified what the private key contains, whether the certificate chain and the private key are a pair, or whether the certificate includes the hosts of the site. The proxy may still refuse a version in which every site is `present`.
- The proxy does not check the expiry of a certificate, and uses an expired certificate as it is. The validation by `check` and `apply` does not check the expiry either.
- This API does not take the right to run a change or a lock, does not ask the proxy, and does not write to the audit log.

### Configuration File Values

`GET /api/config` (operator or above) returns the current values of the configuration file. It can be used whether the configuration file has `managed` or not.

- It reads the configuration file again at every request, and responds only when the file passed all the validation of the configuration file. If it cannot be read or is rejected, it responds with 409 and a fixed sentence.
- The response is `{"sha256", "managed", ...}`. `sha256` is the SHA-256 of the file (the value that appears in `proxy.config` of `/api/status` once the proxy has read it), `managed` is whether the configuration file has `managed`, and the rest are the setting keys of the configuration file, in the same names and form as in the configuration file.
- It outputs only the setting keys in a fixed list. Values that are paths (certificates, private keys, CA files, directories, inspector processes, sockets, database files) are returned as `true` if they are written and `null` if not, and the path strings are not returned.
- It is limited to an operator or above because a rewrite of a route can hold a secret, and because the addresses of servers and listeners are included.

### Check

`POST /api/managed/check` (operator or above) validates a version in the same way as `POST /api/managed/apply` and saves nothing. It is an API for the screen to show errors in their fields before saving.

- The body is `{"version", "files", "expect"}`, in the same form as for `POST /api/managed/apply` (see "Save and Apply" below). `expect` can be omitted, and its form is not validated even if it is present.
- Steps (the response comes from the first stage that refuses):
  1. The slot for validation. If another request holds it, 503 `a check of a managed version is under way`. If `managed` was absent when the admin process started, 409 at once.
  2. The form of the body, the files and the version. A refusal is 400 (a sentence and a place).
  3. The configuration file is read again. If there is no `managed`, if `managed.dir` differs from that at start, or if it is rejected, 409.
  4. The managed store is opened. If it cannot be opened, 500.
  5. The version and the files are validated against the configuration file, and against the files of the request and the files of the managed store. A refusal is 400 (a sentence and a place). It is also 400 when the rules store has no chosen generation for an upstream engine of the version (the sentence is `no generation is chosen for the engine of an upstream`, and `at` is `upstreams.<name>.engine` of the first upstream that hit it). If the rules store cannot be read, 500.
- The response is 200 `{"version", "detect"}`. `version` is the name of the version if it were saved. `detect` is `[{"upstream", "engine"}, ..]` of the upstreams that are inspected by an engine whose chosen generation is a detect-only generation (in the order of the upstreams; `[]` if there are none). For those upstreams, even a request that matches a rule is not blocked.
- It does not take the right to run a change, does not ask the proxy, puts nothing in the managed store, and does not write to the audit log. It can validate even for a managed store that has no selected version (before the first version is created with a command).
- The slot for validation: the validation of a version by `check` and `apply` runs only one at a time inside the admin process, because it reads the 12 MiB body and the files of the managed store again and uses a lot of memory.

### Save and Apply

`POST /api/managed/apply` (operator or above) saves a version in the managed store and applies it to the running proxy. The body is a JSON object, and all three keys are needed.

| Key | Content |
|---|---|
| `expect` | The selected version that you saw on the screen (64 lowercase hexadecimal digits) |
| `version` | The version to save. In the form of a version of the managed store (files are specified by SHA-256 and have no path); how it is written does not matter. When it is saved, it is written in one fixed way, and its SHA-256 is the name of the version |
| `files` | An array of the files to save with the version (PEM strings of the certificate chain, the private key, and the CA files) |

- `files` is up to 192 files, and up to 1 MiB per file. The same file cannot be sent twice, and every file must be one that the version specifies. A file that the version specifies and that the request does not include must already be in the managed store.
- The contents of the files are not written to the response, the audit log, or the configuration history.

Steps (the response comes from the first stage that refuses):

1. The slot for validation. If another request holds it, 503. It is not written to the audit log.
2. The body. 400 if the form of the JSON is wrong, if there are too many files or a file is too large, if the form of the version is wrong (a repeated setting key, an unknown setting key, a missing setting key, a type mismatch), or if `expect` is not 64 lowercase hexadecimal digits. It is not written to the audit log.
3. The right to run a change, the reload of the configuration file, the managed store and `expect`, and the state of the proxy (the same as 1 to 4 of "Applying and Rolling Back by Name" below). If the proxy cannot accept the version, nothing is saved.
4. The version is validated against the configuration file and the files (the same validation as `managed import`; the country database is not loaded, and the proxy loads it at the time of the apply). It is also validated that the rules store has a chosen generation for each upstream engine of the version (the same as step 5 of "Check"). A refusal is 400 (a sentence and a place). It is not written to the audit log.
5. A `managed-import` line (the target is the name of the version) is written to the audit log. If it cannot be written, 503, and nothing is saved.
6. The files and the version are placed inside the lock of the managed store. If a command holds the lock, 409 `the managed store is in use by another command`; other refusals of the managed store are also 409. If the version that was read together with the files of the managed store is refused, 400 (no place); if the configuration file is refused, 409. In every case, a failure (`store`, `version`, `configuration`) is written to the audit log.
7. The apply job is started (step 6 of "Applying and Rolling Back by Name" below). A version that was saved but whose apply job could not be started stays in the managed store. It does no harm.

The response is 202, and has `version` (the name of the version), `placed` (the result of saving: `created`, `existing` if the same version was already there, or `recreated` if a damaged copy was replaced), and `job` (the apply job that was started).

### Applying and Rolling Back by Name

`POST /api/managed/activate` (`{"expect", "version"}`) applies a version of the managed store, by name, and `POST /api/managed/rollback` (`{"expect"}`) applies the rollback target version, to the running proxy. They need an operator or above, and API tokens can also be used.

- `expect` and `version` are 64 lowercase hexadecimal digits. If not, it gives 400 `a version is not 64 lowercase hexadecimal digits`.
- `expect` is the selected version that you saw on the screen. If another user or a command has selected again since you saw the screen, it is refused with 409, so that an old screen does not overwrite it.
- In a managed store that has no selected version, nothing can be applied because `expect` does not match. Create and select the first version with commands (`managed import` and `managed activate`) (see "First Start with the Managed Configuration" in the [operator reference](operator-reference.md)).

Steps (step 3 of "Save and Apply" above is the same. The response comes from the first stage that refuses):

1. The right to run a change. Inside the admin process, changes proceed one at a time, including the end of the apply job. If another change (including removing a version) is in progress, 409 `a change of the managed configuration is under way`; if the admin process is stopping, 503. It is not written to the audit log.
2. The configuration file is read again. If there is no `managed` (including the case where there was none when the admin process started), if `managed.dir` differs from that at start, or if it is rejected, 409. A refusal (`managed`, `configuration`) is written to the audit log.
3. The managed store. If it cannot be opened, or if the file that shows the selected version (`current`) cannot be read, 500. If the selected version is not `expect` (including when there is none), 409 `the chosen managed version is not the one that was expected` (a refusal, `expect`, in the audit log). For a rollback, the rollback target is decided here. If there is none, 409, and if the configuration history cannot be read, 503 (neither is written to the audit log).
4. The state of the proxy is asked on the control socket.
   - It cannot be reached: 503 `the proxy cannot be reached`. An `unreachable` line is written to the configuration history (a refusal, `unreachable`, in the audit log).
   - It accepts the connection and closes without responding (the limit of concurrent connections): 503 `the proxy is busy` (a refusal, `busy`, in the audit log).
   - The running configuration has no `managed`: 409 `the configuration in force has no managed object` (a refusal, `unmanaged`, in the audit log).
5. For apply by name and rollback, the version must be in the managed store. If not, apply by name gives 404, and rollback gives 409 `the version to go back to is not in the store`. If it is, the rules store must have a chosen generation for each upstream engine of the version. If not, 409 `no generation is chosen for the engine of an upstream` with `at` (`upstreams.<name>.engine` of the first upstream that hit it), and a refusal (`engine`) is written to the audit log. If the rules store cannot be read, 500. `POST /api/managed/apply` saves the version here (4 to 6 of "Save and Apply" above).
6. The apply job is started. If the time left of the response (30 seconds) is 5 seconds or less, or if the admin process began to stop after 1, 503 (a failure, `time`, `stopping`, in the audit log). If a thread cannot be created, 503 (a failure, `thread`, in the audit log).

The response is 202, and has `version` (the version to apply) and `job`.

The rollback target:

- It is the `from` of the newest line in the configuration history whose result is `applied` and whose `from` and `to` differ.
- However, this applies only when the `to` of that line is the version that is selected now. After an apply that did not end in `applied`, or after a version was selected with a command, the end of the history does not match the selected version, so a rollback is not possible (409 `the history does not end at the chosen version`). If there is no `applied` line, it gives 409 `there is no change to go back from`.
- A rollback is also entered in the history, as `rollback`. If you roll back again right after, it goes back to the original version.

### Apply Jobs

A change ("Save and apply", "Apply by name", "Roll back") gets the response 202 as soon as it has passed the stages above, and the apply continues as an apply job (`job`) inside the admin process. This is because an apply may take longer than the time that one response can wait. You can read how it ended with `GET /api/managed/job` (viewer or above; `{"job"}`, or `null` if there is none) or with `job` of `GET /api/managed`.

- The admin process keeps only the last apply job, and it is only in memory. It is lost when the admin process restarts. An apply job that is running ends together with the admin process, and the lock of the managed store is released together with the process.
- An apply job cannot be cancelled. It does not stop even if the role of the user who requested it changes.
- An apply job holds the right to run a change until it ends. During that time, other changes and the removal of versions get 409.
- For the order of applying (the lock of the managed store, the request to the proxy to reload, and the order in which the selected version is advanced) and what happens when it stops halfway, see "Applying" in the [operator reference](operator-reference.md). For the time that the admin process waits on the control socket, see "Control Socket" above.

| Key | Content |
|---|---|
| `kind` | `apply` (Save and apply), `activate` (apply by name), `rollback` |
| `actor` | The name of the user who requested it |
| `from`, `to` | The version before the change (`expect`) and the version after it |
| `started`, `ended` | The time it started and the time it ended (in seconds since the epoch). While it is running, `ended` is `null` |
| `state` | `running` (applying) or `ended` |
| `result` | How it ended (the table below). While it is running, `null` |
| `reason` | A fixed word. The part where the proxy refused (`configuration`, `version`, `store`, `upstream`, `tls`, `fixed`, `listener`, `thread`), the reasons for `busy` (`store in use`, `proxy busy`, `reload under way`, `starting`, `too many orders`, `stopping`), the reasons for `error`, and the reasons for `not recorded` (`current changed`, `store`) |
| `detail` | The sentence of the proxy that refused, or the sentence of the managed store |
| `config_before`, `config_after` | The SHA-256 of the configuration file that was in use before and after the apply. Only when known |
| `history` | Whether a line was written to the configuration history. `null` for an ending that writes no line |

| `result` | Meaning | Audit log | Configuration history |
|---|---|---|---|
| `applied` | The proxy runs the version after the change, and the managed store has selected the version after the change | The `ok` line written before the change | A line is written |
| `refused` | The proxy refused. Nothing was changed | A failure | A line is written |
| `busy` | The managed store or the proxy was in use. Nothing was changed | A refusal if it happened before the line before the change was written, a failure if after | A line is written if after |
| `current changed` | The selected version was no longer `expect` | A refusal | Not written |
| `no version` | The version is not in the managed store | A refusal | Not written |
| `unmanaged` | The configuration of the running proxy has no `managed` | A refusal | Not written |
| `store` | The lock of the managed store could not be taken, or the file that shows the selected version (`current`) is missing or cannot be read, and so on | A refusal | Not written |
| `audit` | The audit log line before the change could not be written. Nothing was changed | − | Not written |
| `error` | The proxy did not accept the request (`unknown op` means an old proxy that does not support `reload` of the control socket) | A failure | A line is written |
| `unreachable` | The proxy could not be reached | A refusal | A line is written |
| `failed` | The proxy did not switch to the version after the change | A failure | A line is written |
| `unconfirmed` | The result could not be confirmed | A failure | A line is written |
| `not recorded` | The proxy switched to the version after the change, but the managed store did not select it (`current changed`: the selected version was changed by hand; `store`: the file that shows the selected version (`current`) cannot be written) | A failure | A line is written |

- `reason` of `refused` is `fixed` when a setting key that cannot change while running differs (`detail` is `<key> cannot change while running`), and when an upstream engine of the version is not running in the proxy (including when it is starting; `detail` is `the engine of an upstream is not ready (upstream <name>)`). Start an engine that is not running first (with "Start the engine" on the "Rule generations" screen, or with SIGUSR1; see "Chosen Generation per Engine" in the [operator reference](operator-reference.md)), and then apply again.
- The `ok` line of the audit log is written before the change (`from` and `to` are written to `before` and `after`. The SHA-256 of the configuration file is written to the configuration history, not to the audit log). It is not a line that shows success, so check how the operation ended with the lines that follow and with the configuration history.
- If a line could not be written to the configuration history, a failure (`history`) is written to the audit log.
- If an apply job ended abnormally on the way, it becomes `unconfirmed`, and the admin process writes one line to its log.
- After `unconfirmed` and `not recorded`, the selected version and the running version may differ. Check with `current` and `serving` of `GET /api/managed`, and if they differ, apply either version again.

### Removing Versions

`DELETE /api/managed/versions/<version>` (operator or above, API tokens allowed, no body) removes a version from the managed store. It cannot be undone. It also cleans up the files and ACME certificates that no version specifies any more (for what the cleanup removes, see "Removing Versions" in the [operator reference](operator-reference.md)).

Steps (the response comes from the first stage that refuses):

1. If the name is not 64 lowercase hexadecimal digits, 404.
2. The right to run a change (an apply job also holds it). If another change is in progress, 409, and if the admin process is stopping, 503. It is not written to the audit log.
3. The configuration file is read again. If there is no `managed`, if `managed.dir` differs from that at start, or if it is rejected, 409 (a refusal, `managed`, `configuration`, in the audit log).
4. If the managed store cannot be opened, 500.
5. A version that is not in the list of the managed store gives 404.
6. The selected version is not removed (409, a refusal, `chosen`, in the audit log).
7. The rollback target version is not removed (409, a refusal, `rollback target`, in the audit log). If the configuration history cannot be read, 503.
8. A `managed-remove` line (the target is the name of the version) is written to the audit log. If it cannot be written, 503, and nothing is removed.
9. It is removed from the managed store. A refusal is 409 with a sentence of the managed store (a failure, `store`, in the audit log).

| Version | `error` |
|---|---|
| The selected version | `the version is the one the managed store chooses` |
| The rollback target version | `the version is the target of a rollback` |
| A version in use (for which versions are in use, see "Removing Versions" in the [operator reference](operator-reference.md)) | `the managed version is in use` |

- On success, it returns 200 `{"removed", "cleaned"}`. `removed` is the name of the removed version, and `cleaned` is a boolean for whether the cleanup finished. If `cleaned` is `false`, the cleanup could not finish (for example, another version could not be read). The removal is not undone, and the cleanup is tried again at the next removal.
- It does not ask the proxy. A version in use is refused by the managed store.
- A removal reads the other versions one by one, so it takes longer when there are more versions. If the response is not in time, it gives 503, but the removal may still complete.
- It writes no line to the configuration history. Lines that specify the removed version remain.

## Switch History

`GET /api/history` (viewer or above, API tokens allowed) returns the history of choosing generations and of rollbacks, newest first, up to 200 lines, as `{"entries": [...]}`.

| Field | Content |
|---|---|
| `ts` | The time (UTC, RFC 3339, to the millisecond) |
| `actor` | The name of the user who requested the switch |
| `from` | The generation that the rules store had chosen before the request, for the engine that the generation in `to` belongs to (the same as `to` if there was none) |
| `to` | The generation that was requested (the rollback target for a rollback) |
| `kind` | `activate`, `rollback` |
| `result` | A word for the result (see the note below) |
| `engine` | The engine of the generation in `to` (`coraza` or `modsecurity`). `null` for a line that an admin process of an earlier version wrote |

`result` is the same six values as `result` in the response of "Choosing and Rolling Back" (`switched`, `unchanged`, `refused`, `failed`, `unreachable`, `unconfirmed`), with the same meanings.

- The history is appended to `activations.log` in `admin.store.dir`, as one file for all engines. A line is synced after it is written, and then the response is returned. It is not rotated, and it is not deleted. Only the last 1 MiB (about 4000 lines) is read back, and lines older than that are not used for deciding the rollback target either.
- Only switches requested through the admin screens and the admin API are entered. A choice and a switch by the command (`rules activate`) and by SIGUSR1 are not entered.
- A line is written to the history only when the proxy could not be reached, and for the results after the audit log line was written (when the rules store refused the choice, and the response of the proxy). It is not written for an input error, a generation that does not exist, a rollback target that cannot be decided, another change in progress, an old `expect`, a proxy that did not respond to the query for the state because of the limit of concurrent connections, or an audit log line that could not be written.

## Configuration History

`GET /api/managed/history` (viewer or above, API tokens allowed) returns the history of the changes of the managed configuration ("Save and apply", "Apply by name", "Roll back"), newest first, up to 200 lines, as `{"entries": [...]}`.

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

`result` is one of these eight: `applied`, `refused`, `busy`, `error`, `failed`, `unconfirmed`, `not recorded`, `unreachable`. The meanings are the same as in the table of "Apply Jobs" under "Managed Configuration Operations". `reason` also uses the same words as `reason` of the apply job.

- The history is appended to `managed.log` in `admin.store.dir`, as one JSON object per line. A line is synced after it is written. It is not rotated, and it is not deleted. Only the last 1 MiB is read back, and lines older than that are not used for deciding the rollback target either. Lines that do not match the fixed form are left out.
- Only changes requested through the admin screens and the admin API are entered. A choice by the command (`managed activate`) and an apply by SIGHUP are not entered.
- A line is written only when the proxy could not be reached (`unreachable`) and for the endings after the audit log line before the change was written (the table of "Apply Jobs"). It is not written for an input error, another change in progress, an old `expect`, a rollback target that cannot be decided, a proxy that did not respond to the query because of the limit of concurrent connections, or an audit log line that could not be written.
- The sentences of the proxy and the managed store are not written to the history. They are only in `detail` of the apply job.
- If a line could not be written, `history` of the apply job is `false` and a failure (`history`) is written to the audit log.
- If `managed` was absent when the admin process started, it gives 409, and if the history cannot be read, 503.

## Reading Logs

`GET /api/records` (viewer or above, API tokens allowed) reads the files of `records.dir` from the newest line and returns the lines that match the conditions. A line is the JSON object as it was written, and characters that came from a request (such as `path`) stay in the `%XX` form (see "Logs" in the [operator reference](operator-reference.md)). The order of the keys may change.

The conditions (the query) are as follows. Each can be given once, and a value can be written with `%XX` (up to 128 bytes after decoding).

| Condition | Form |
|---|---|
| `from`, `to` | The start and end times. RFC 3339 in UTC, ending in `Z`. Up to 9 digits of fraction of a second (cut down to milliseconds), or none |
| `type` | `request`, `connection`, `tunnel`, `line`, `audit`, `dropped` |
| `class` | The result of a request log (1 to 32 characters of lowercase letters, digits, `_`, and `-`) |
| `status` | A status code (1 to 3 digits) |
| `rule` | A rule ID. One that is in the rule that decided, or in the other rules that matched |
| `id` | The request ID |
| `client` | An IP address |
| `generation` | The fingerprint of a generation. The first 16 digits or all 64 (the log has only the first 16 digits) |
| `engine` | The engine that inspected the request. `coraza` or `modsecurity` (lowercase only). A log without `engine` (such as a request that went through a bypass route) does not match this condition |
| `file`, `offset`, `inode` | The position to continue from. It can be used only when all three are given |

- A log of `audit` is the one that is written to the standard error of the admin process and to the store of the audit log, and it does not go into the log files of the proxy. Even if you search with `type=audit`, it cannot be found in these files. Read the audit log with `GET /api/audit`.
- It returns up to 500 lines at a time, and reads up to 256 MiB. When it reaches either one and logs still remain, `next` in the response holds the position to continue from. When the read limit stops the reading before a line that matches the conditions is found, `next` is present even if `records` is empty. Keep reading until `next` is `null`.
- The response is `{"records": [..], "next": null or {"file", "offset", "inode"}}`. `inode` is returned as a string. To continue, add the three values of `next` to the same conditions.
- The position to continue from is decided by the number of the file, the position in it, and the inode of the file. Even if the numbers change by the rotation of the log files, the file is found by its inode. If the file was deleted by rotation, or the position is no longer at the end of a line, it gives 409 `the continuation names no place in the record files any more`. In that case, read again from the start.
- It reads from the newest line, and when it meets a line older than `from`, it ends the reading there. It does not return the last line that has no newline because it is being written, a line without `ts`, or a line that is too long.
- Failures:
  - The configuration has no `records`: 404 `records are not configured`
  - An error in the conditions (an unknown condition, the same condition twice, an error in the form of a value, the three values of the position to continue from are not all given): 400. The sentence is one fixed English sentence
  - The directory of the log files does not pass the check of the owner and permissions: 503. The sentence is the sentence of the check
  - The file cannot be read: 503 `unavailable`

## Admin Screens

The admin screens are served by the admin process. Open `https://admin.example.com/` (`admin.origin`) in a browser.

- The files are in `proxy/admin-ui/`, and are built into the executable. The admin process and the admin screens are always the same version. The admin process does not read any files of the host.
- The only paths that it serves are `GET /` (the page) and `GET /ui/<ui-version>/<name>` (a style sheet, an icon, and 34 scripts, 36 files in all). The name of a script is its path from `proxy/admin-ui/js/` (`js/app.js` is `/ui/<ui-version>/app.js`, and `js/waf/waf.js` is `/ui/<ui-version>/waf/waf.js`). No session is needed (the files contain no secret).
- `<ui-version>` in the path is 16 lowercase hexadecimal digits made from the names and contents of the 36 files (the first 16 digits of the SHA-256 of a list that has the name and the SHA-256 of each file). It is made once, when the first request for the page or a file comes, and the page is served with `/ui/` in it replaced by `/ui/<ui-version>/`. If the contents of the files do not change, `<ui-version>` does not change either.
- `/ui/<name>` without `<ui-version>`, a path with a different `<ui-version>`, and a name that is not one of the 36 all fall through to the table of the API and get 404. A method other than `GET` and `HEAD` for the page and for the files under `<ui-version>` gets 405 (`Allow: GET, HEAD`).
- The headers of the responses for the page and the files:

| Header | Value |
|---|---|
| `Cache-Control` | The page is `no-store`. The files under `<ui-version>` are `public, max-age=31536000, immutable` |
| `X-Content-Type-Options` | `nosniff` |
| `Content-Security-Policy` | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'` |
| `Referrer-Policy` | `same-origin` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Permissions-Policy` | `accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()` |

- The page is loaded every time, and refers to the files with the path of the `<ui-version>` at that time. The files under `<ui-version>` never change, so the browser uses its cache for up to a year. When you restart the admin process with an executable in which the files of the screens changed, `<ui-version>` changes, and the browser loads the files with the new path only then.
- The scripts of the screens cannot make markup from a string (Trusted Types). The screens can do nothing except load their own scripts, styles, and icons, and call their own API.
- `Referrer-Policy` of API responses is `no-referrer`, and that of the files of the screens is `same-origin`.

Language and storage:

- The languages are Japanese and English. The screens use the saved language if there is one, otherwise the browser language (Japanese if it starts with `ja`, English if it starts with `en`), and English if it is neither. You can switch the language in the bar at the top of the screen.
- The theme (Auto, Light, Dark) and how times are shown (Local or UTC) can also be chosen in the bar at the top of the screen. The only things that the screens save in the browser storage (`localStorage`) are these three: the language, the theme, and how times are shown. The password, verification code, recovery codes, API token, CSRF token, secret of two-factor authentication, and draft of the managed configuration (see "Drafts" below) are all kept only in the memory of the screen. Those that are returned only once (the recovery codes, an API token, a secret that is being set up) are also discarded when you leave the screen. However, when the response that confirmed the two-factor setup arrives after you left the screen, its recovery codes are kept until they are shown on the next screen. At logout and when the session ends, all of these are discarded. They are not put in the URL or the history either.
- When you switch the language, the theme, or how times are shown, the screen is not drawn again, and only the text is replaced. The text you entered, the files you selected, and the filters stay as they are.
- The QR code of two-factor authentication is drawn inside the screen (nothing is sent outside).

Which screens you can use depends on the role. The menu arranges the screens in 7 groups (the "Menu" column of the table below), and shows only the screens that the role can use.

| Menu | Screen | Role | Content |
|---|---|---|---|
| (no name) | Overview | viewer or above | It shows the numbers of the proxy (five: "Requests", "Blocked", "Refused by policy", "Upstream failures", and "Config reloads", with the time since the start added under "Requests"; for the contents, see `GET /api/status` under "Listing and Contents" above), the state of the proxy (whether all engines are ready, and whether a generation switch is in progress), the state of the generations for each engine, and the SHA-256 of the current configuration file. The panel of each engine shows the name of the engine (the badge "Default" for the default engine), the phase of the inspection kernel, the chosen generation, the running generation, the mode, the rollback target, and a sentence about what the two generations are doing. For an engine that has a chosen generation but is not running in the proxy, it shows the badge "Not running" and a sentence that says to start the engine on the Rule generations screen ("A generation is chosen for this engine, but the proxy does not run it. Start the engine on the Rule generations screen."). An engine that has neither a chosen generation nor a running generation, and is not the default engine, is not shown. When no switch is in progress but the two generations differ for any engine, or when a generation is chosen but that engine is not running, a warning is shown in the bar at the top of the screen. While a switch is in progress, only a message to that effect is shown on the Overview screen. When the managed configuration is used, the "Managed configuration" panel shows the selected version and the running version, and "Matching" or "Different" for the two ("Applying" while an apply job is running), and "Open versions" moves to the Configuration versions screen |
| WAF | Rule generations | viewer or above | It shows the list of generations and the detail (files, load order, bypass routes). An operator or above can choose, switch the proxy, start the engine, and remove, for each engine of the generation. Choosing is "Switch to this generation"; switching when the proxy has not caught up with the chosen generation is "Apply to the proxy"; starting an engine that has a chosen generation but is not running in the proxy is "Start the engine". For a generation whose manifest cannot be read, so that its engine is not known, the buttons for choosing and starting are not shown. The chosen generation, the running generation, and the rollback target of any engine cannot be removed |
| WAF | Rule import | operator or above | Select files in the browser and import them, specifying the inspection engine (Coraza or ModSecurity; the initial value is the default engine, and Coraza if it is not known), whether to use the CRS and which files not to use, the bypass routes, and detect only. Write the bypass routes one per line, as a host (optional) and a path. The description says "The route of the admin page is inspected by the default engine. When the request of an import is blocked by the inspection, put a route that is not inspected into a generation of the default engine." The action is always `bypass`, and `routes` in the body that is sent is JSON of the same form as a `--routes` file. A line with only a host is shown as an error, and a line with nothing in it is not sent. The browser also counts the limits. If the trial is blocked, you can use "Accept the block and import" after a confirmation. The new generation is not chosen |
| WAF | Switch history | viewer or above | It shows the history of switches (newest first, up to 200; the screen says so too; the "Engine" column shows "—" for old lines that have no `engine`) and the rollback target of each engine. An operator or above can roll back ("Roll back") for each engine that has a rollback target |
| Logs | Access log | viewer or above | It searches the logs with conditions. The condition "Engine" (Any, Coraza, ModSecurity) narrows the logs by the engine that inspected. Text that came from a request is shown in the `%XX` form as it is. A log that has a request ID opens its detail when you press the content of the row (the method, host, and path, and so on). The request ID appears in the `title` attribute of the content, and in "All fields" and "JSON" of the detail. A log without a request ID (such as a connection or a sentence line of the proxy) is opened with "Open" on the row. When opened, it first shows the main points (the `class`, `status`, and `reason` of the result, the rule, `score`, the time, the client, the method, host, and path, the generation, and the engine), and below them a folded "All fields" and "JSON". In "All fields", if you select "Also show the text with %XX read", the decoded text is also shown |
| Logs | Audit log | operator or above | It shows the newest 200 lines (newest first; the screen says so too). When the request ID is in the form that the proxy and the admin process give, you can open the access log from that ID |
| Proxy | Sites | operator or above | The list and editing of the sites of the draft of the managed configuration (name, hosts, certificate; the certificate is the files of a certificate chain and a private key, or ACME). The list and the editing panel show the expiry, the state, and the host names in the certificate that are in the managed store (see "Certificate Information" above) |
| Proxy | Upstreams | operator or above | The default upstream of the draft, and the list and editing of the upstreams (engine, servers, TLS, and CA file). The engine is chosen from "Default engine (Coraza)" (the parentheses hold the name of the default engine), "Coraza" and "ModSecurity". The explanation of the choices points to "ModSecurity Generations" in the [operator reference](operator-reference.md). The "Engine" column of the list shows the engine that inspects ("(default engine)" is added for an upstream that follows the default engine). Before saving, a notice is shown when the chosen engine has no chosen generation, is not running in the proxy, is starting, or when the inspector process of ModSecurity is not in `kernel.engines` of the configuration file |
| Proxy | Routes | operator or above | The list and editing of the routes of the draft (host, path, upstream; in the folded part, access control, streaming responses, and rewrite). It loads up to 1024 routes |
| Policy | Access control and rate limits | operator or above | The list and editing of the global access control and rate limits of the draft, and of the host policies (see "Host policy screen" below) |
| Configuration | Configuration versions | viewer or above | It shows the selected version and the running version, the state of the proxy, the state of the apply, and the list of versions (see "Managed configuration screens" below). An operator or above can show the contents of a version (JSON and certificates), apply by name, remove, and make a draft. The selected version, the running version, and the rollback target cannot be removed |
| Configuration | Configuration history | viewer or above | It shows the configuration history (newest first, up to 200; the screen says so too) and the rollback target. A line where the configuration file differs before and after the apply shows "Changed". An operator or above can roll back ("Roll back to the previous version") |
| Configuration | Configuration file | operator or above | It shows the current values of the configuration file (see "Configuration File Values" above). It cannot be changed here. It does not show paths; it shows true if a path is written, and "—" if not. It shows a comparison with the running proxy ("The same" or "Different (waiting to be read)") |
| Admin | Account | viewer or above | Changing the password, setting up and disabling two-factor authentication, and creating and removing API tokens |
| Admin | Users | owner | The list of users, creating, changing the role, disabling and enabling, resetting passwords and two-factor authentication, and the list and removal of the API tokens of everyone |

- When the numbers of the Overview cannot be obtained from the proxy, the screen shows "—" and a short word in place of the numbers, so that they are distinguished from 0. The reason is shown only once, in the panel of the proxy. The reason is one of these: the proxy cannot be reached (`reachable` is `false`), the proxy is busy (`proxy` is `null`), or that proxy does not return the numbers (a proxy of an earlier version, where the value is `null`). The SHA-256 of the configuration file is treated the same way.
- The display for each engine shows these notices.
  - When the default engine differs between the admin process and the proxy (when only one of them was restarted), the "Default" badge is not shown, and "The admin process and the proxy have different default engines. Restart both to make them the same." is shown on the Overview, Rule import, and Upstreams screens.
  - For a proxy of an earlier version (one that does not return `engines`), "This proxy does not report the state of its engines. Use the same build for the admin process and the proxy." is shown on the Overview, Rule generations, and Switch history screens, and the buttons for choosing a generation, applying to the proxy, starting an engine, and rolling back are not shown (see "Version Updates" in the [operator reference](operator-reference.md)).
- Choosing, rolling back, and removing a generation show a confirmation first. The confirmation puts the generation "Now" and the generation "After the switch" ("After the rollback" for a rollback, "After the delete" for a removal) side by side in a table of the fingerprint (first 12 digits), the mode, the engine, and the number of bypass routes, and shows the values that change in bold. For choosing, "Now" is the chosen generation and "After the switch" is the generation to choose, and if the proxy is using a generation different from the chosen one, that generation is also shown. For a rollback, "After the rollback" is the rollback target, and for a removal, "After the delete" is "Gone" for every item. A value that is not known is "—". The confirmation for an engine that is not running in the proxy (including the first choice when the engine has no chosen generation, starting with the chosen generation, and a rollback) also says that the engine will be started, and adds "This engine will start again after the proxy is restarted. If it fails while it runs, the whole proxy stops. When you no longer use it, remove its choice with the rules deactivate command." (see "Chosen Generation per Engine" in the [operator reference](operator-reference.md)). An import is sent without a confirmation, and a confirmation is shown only when you accept the block of the trial and import again. While one is running, no other change can be started.
- When the result is not known (a 502 or 504 whose body has no `result`, or a dropped connection), a choice and a rollback read again and show the state and the history of the engine that the switch was for; an import reads again and shows the newest three of the list of generations; a removal reads again and shows the list of generations. When a change of the managed configuration was sent and it is not known whether the change started, the screen reads the state again and shows it as "Result unknown".
- The screens never read again by themselves after a time. The exception is the apply job of the managed configuration: until the apply job ends, the screen reads `GET /api/managed/job` 1 second after the previous response to check the state. If it cannot read a response 3 times in a row, or when the time that an apply job may take has passed, it stops checking and shows a message to that effect. While it checks, every request counts as a use of the session, so the session does not end by `admin.session_idle_ms` (it does end by `admin.session_total_ms`). When you use the screens through the proxy, and what the logs keep is not `security`, each check adds one line to the log of the proxy. When you change something from a screen, the related displays are read again. To get the latest data, use "Reload" (the Rule import screen does not have it).
- In the table of a list, pressing the name of a column that can be sorted sorts by that column (each press switches between ascending and descending, and rows with no value come last). If you type words in the field above the table, it narrows to the rows whose visible text in the cells has all the words (words are separated by spaces, and case is not distinguished; the column of operation buttons is not searched). Rows are divided into pages of 50, and you move with "Previous" and "Next". Sorting and narrowing are done only among the rows that the screen has loaded. Some small tables, such as the table of bypass routes in a generation, have no field for narrowing.
- The Access log shows one response of `GET /api/records` (up to 500 lines) in pages of 50 lines. If the response has a continuation (`next`), "Next" on the last page loads the older logs that follow. "Previous" on the first page goes back to the newer ones that were loaded before. The position to continue from is not put in the URL, so if you open the URL again, it loads from the start.
- The screen is identified by the part of the URL after `#`. It is `#/<screen>` (`overview`, `generations`, `import`, `history`, `records`, `audit`, `sites`, `upstreams`, `routes`, `policy`, `managed`, `managed-history`, `config`, `account`, `users`); in addition, the detail of a generation is `#/generations/<fingerprint>`, the contents of a version are `#/managed/<version>`, one log is `#/records/<id>`, and the search of the logs is `#/records?<key>=<value>` (the names of the conditions are the same as for `GET /api/records`, except the position to continue from). Every move enters the history of the browser, so you can go back and forward with the back and forward operations of the browser. If you open the URL again, you get the same screen.
- The values in the URL are validated for their form before they are used. A value in the wrong form, a condition that the screen does not recognize, and extra parts are not used and are removed from the URL, and "Removed what was not valid in the address." is shown. An unknown screen, and a screen that the role cannot use, open the Overview. For one log, if it is not in the rows that were loaded, the screen reads it with the condition of that request ID, and if it is not found, it shows a message to that effect.
- Times are shown in one way. By default they are local times (in the form `2026-11-04 16:33:56 (JST)`; the parentheses hold the short name of the time zone that the browser returns, such as `JST` or `GMT+8`), and "Time" in the bar at the top of the screen switches them to UTC (`(UTC)`). In a table, the name of the time zone is written once in the name of the column (`Time (JST)` and so on), not in the cells. Only a time in a time zone different from the one in the column name (because of summer time, for example) also has the time zone in its cell. The other way of showing a time appears in the `title` attribute of that time (the text shown when you hold the pointer over it). `from` and `to` of the search of the logs are always written in RFC 3339 in UTC (ending in `Z`), whichever is selected.
- After login, while the session is waiting for a password change or for two-factor setup, only that screen is shown.
- The screens call the admin API with `fetch` of the browser. The screens replace the sentence of an API response (`error`) with a sentence in each language.
- For a failure with no `error` sentence in the response (a 403 for a request that a proxy in front blocked by a rule, a 502 where the proxy could not connect to the admin process, and so on), the screen shows the request ID of `X-Request-ID` of the response after the sentence about the failure. If you search the "Access log" screen with that ID, you can find the rule that blocked the request and so on (see "CRS Tuning for the Admin Host" above). The ID is shown only when it is in the form that the proxy and the admin process give.

Managed configuration screens:

- When the admin process was started without the managed configuration, the Configuration versions screen and the editing screens show what the managed configuration can do and the main points of the steps until you start using it. The steps follow "Moving to the Managed Configuration" in the [operator reference](operator-reference.md).
- The Configuration versions screen shows the selected version, the running version, and the state of the proxy ("Reachable", "Not reachable", "Proxy busy", "Not using the managed configuration", "Reading its configuration again"). When the two versions differ, it shows a notice about it, and, to an operator or above, two operations: "Apply the selected version again" and "Select the running version". The former switches the proxy to the selected version, and the latter applies the running version by name and makes it the selected version.
- When the configuration file differs from what the running proxy has read (`sha256` of `GET /api/config` differs from `proxy.config` of `/api/status`), the screen says so. If you apply from this screen, the changes of the configuration file are also applied. If the configuration file has an error, the apply is refused.
- Apply by name ("Apply this version"), rollback, the operation that makes the two versions the same, and removal ("Remove this version") show a confirmation first. The confirmation puts the version "Now" and the version "After applying" ("After removing" for a removal) side by side in a table of the number of sites, the number of upstreams, the number of upstreams for each engine ("Coraza upstreams" and "ModSecurity upstreams"; when the default engine is not known, one row "Upstreams that name an engine"), the number of routes, the default upstream, the global access control, the global rate limit, and the number of host policies, and for an apply it also shows "The marks of servers that have failed and the failure counts of the upstreams start again." For apply by name, rollback, and the operation that makes the two versions the same, for an engine whose generation is running as a detect-only generation, if the version after the apply has an upstream of that engine, the badge "Detect only now" is added to the value of "After applying".
- When you send a change, "Applying" is shown until the apply job ends, and when it ends, the result ("Applied", "Refused", "Busy", and so on), what happened, and what to do next are shown. When the proxy refused the apply with `fixed`, it shows "A key that cannot change while the proxy runs is different, or the engine of an upstream is not running in the proxy." and the next step ("If the engine is not running, start it on the Rule generations screen, then apply again. Otherwise put that key of the configuration file back, or restart the proxy."). When `at` of a 409 of apply by name or rollback is `upstreams.<name>.engine`, the name of the upstream is added before the sentence of the refusal, as in "Upstream app:".
- The contents of a version (`#/managed/<version>`) can be opened only by an operator or above. The contents may include secrets, so they are kept in the memory of the screen only while they are open. For a version that is not the selected one, "Make a draft from this version" makes a draft from that version.

Drafts:

- The four screens Sites, Upstreams, Routes, and Access control and rate limits edit one draft of the managed configuration. The draft is made from the selected version (it can also be made from another version on the screen for the contents of a version). A change made here has no effect until you press "Save and apply".
- The draft is only in the memory of this page. It is not put in the browser storage, the URL, or the history. It is lost when you log out, when the session ends without any operation, and when you close the tab. If you try to leave the page with a draft that has changes, the browser shows a confirmation.
- While you type into the draft, `GET /api/session` is sent at most once every 30 seconds to extend the session (typing counts as using the session).
- The bar at the top of the screen shows the base version and "Changed" or "No changes". "Changed" appears only when the version that would be made from the draft differs from the base version. A draft that you typed into and then put back is "No changes". A draft that has an error in the form of its input is "Changed".
- "Check" in the bar sends `POST /api/managed/check` and, if it is refused, shows the error in its field (see `at` of "Response Format" below). "Save and apply" goes through the check, a confirmation, and `POST /api/managed/apply`, in this order. A draft with "No changes" cannot be saved (the check says "This is the same as the base version: nothing has changed.").
- The confirmation of "Save and apply" lists the changes to save (adding, removing, and changing upstreams, the default upstream, access control, rate limits, host policies, sites, and routes) by name, and does not show the values (because a rewrite can hold a secret). When an upstream engine changes (only for upstreams that are in both versions), it is listed as "Upstream engine", and when only the setting of the engine was added or removed and the engine that inspects is the same, as "Upstream engine setting". When there are upstreams that are inspected by an engine whose chosen generation is a detect-only generation, it shows "{n} upstream(s) ({names}) are inspected by an engine whose generation only detects. A request that matches a rule is not blocked." (`{n}` is the number and `{names}` are the names. Up to 20 names are shown, and the rest are shown as a count such as "3 more"). When there is a site that needs a new ACME certificate (`{n}` is that number), it shows "{n} site(s) need a new certificate. Until acme renew issues it (a little over a day at most when left to the timer), the hosts of the site cannot be reached over TLS."
- When the base version of the draft is no longer the selected one (another user or a command changed it first), it cannot be saved as it is.
- The PEM files of the certificate chain, private key, and CA are read in the browser, validated as UTF-8 text of 1 MiB or less, and specified by the SHA-256 of the text that is sent. The contents of a file are not shown. The SHA-256 is calculated with the cryptography functions of the browser, so a file can be selected only over a secure connection (https or localhost). The bytes that were read are filled with 0 as soon as they have been used, but the text is not filled with 0 inside the browser, and stays in memory until nothing refers to it.

Host policy screen:

- From the top, the Access control and rate limits screen has the notice "The global settings and the per-host settings do not apply to the route to this admin screen.", the panel of the global access control and rate limits, the list of host policies with "Add a per-host setting", and the panel for editing the host policy that is open.
- For the setting keys of a host policy, the rules for comparing hosts, and how they are layered, see "Host Policies (`host_policies`)" in the [operator reference](operator-reference.md).
- In the editing panel, write a name and the hosts (one per line), and choose one of these three for each of access control and rate limits. Your input stays in the draft when you switch.
  - "Inherit": the global settings also apply to this host. The rate limit is counted with the same counter as the global one.
  - "Settings for this host": the values in this panel apply in place of the global settings. The global access control is not inherited. The rate limit is counted with a counter for this host.
  - "Not used": it does not apply to this host. For access control, even a global refusal does not apply to this host.
- In a draft that changes the global access control or the global rate limit, the panel of the global settings and the confirmation of "Save and apply" show "This change does not reach the {n} per-host setting(s) that do not inherit the global access control ({names})." (`{n}` is the number and `{names}` are the names. The same form for rate limits). This is because global changes (including an urgent denial) do not take effect for hosts with "Settings for this host" or "Not used".
- The list shows "A per-host setting applies only to requests whose Host header is one of its hosts. When a request for another host reaches the same upstream through the default upstream, a route with no host or a route whose host starts with *., only the global settings apply to it. Write a route for each host, and set the default upstream to None."
- If you write a country list in a configuration file that has no `geo`, `at` of the check shows the access control of that host policy. If you write the same host as the admin route, `at` of the check shows that row.

## API Paths

The "Token" column shows whether an API token can be used. The "State" column shows the session states in which the API can be used ("Normal" means that there is no restriction by the state; for the states, see "Login and Two-Factor Authentication" above).

| Method | Path | Minimum role | Token | State | Content |
|---|---|---|---|---|---|
| POST | `/api/login` | (none) | no | | Login. `{"name", "password"}` |
| POST | `/api/login/mfa` | viewer | no | Waiting for a verification code | Verification of the two-factor code. `{"code"}` or `{"recovery"}` |
| POST | `/api/logout` | viewer | no | Any state | Logout |
| GET | `/api/session` | viewer | no | Not waiting for a verification code | Session information |
| PUT | `/api/account/password` | viewer | no | Normal, waiting for a password change | Change the password. `{"current", "new"}` |
| POST | `/api/account/mfa/setup` | viewer | no | Normal, waiting for two-factor setup | Start the two-factor setup. `{"password"}` |
| POST | `/api/account/mfa/confirm` | viewer | no | Normal, waiting for two-factor setup | Confirm the setup. `{"code"}` |
| DELETE | `/api/account/mfa` | viewer | no | Normal, waiting for two-factor setup | Disable two-factor authentication. `{"password", "code"}` |
| GET | `/api/account/tokens` | viewer | no | Normal | List of your own API tokens |
| POST | `/api/account/tokens` | viewer | no | Normal | Create an API token |
| DELETE | `/api/account/tokens/<id>` | viewer | no | Normal | Remove your own API token. An API token of another user gives 404 |
| GET | `/api/status` | viewer | yes | Normal | State of the proxy and the generations |
| GET | `/api/generations` | viewer | yes | Normal | List of generations |
| GET | `/api/generations/<fingerprint>` | viewer | yes | Normal | Detail of a generation |
| POST | `/api/generations` | operator | yes | Normal | Import |
| DELETE | `/api/generations/<fingerprint>` | operator | yes | Normal | Remove a generation |
| POST | `/api/activate` | operator | yes | Normal | Choose a generation and switch the proxy |
| POST | `/api/rollback` | operator | yes | Normal | Roll back to the previous generation. `{"engine", "expect"}` (`engine` can be omitted) |
| GET | `/api/history` | viewer | yes | Normal | Switch history |
| GET | `/api/managed` | viewer | yes | Normal | State of the managed configuration |
| GET | `/api/managed/versions` | viewer | yes | Normal | List of versions of the managed configuration |
| GET | `/api/managed/versions/<version>` | operator | yes | Normal | Contents of a version |
| DELETE | `/api/managed/versions/<version>` | operator | yes | Normal | Remove a version |
| GET | `/api/managed/certificates/<version>` | operator | yes | Normal | Certificate information of the sites in a version |
| POST | `/api/managed/check` | operator | yes | Normal | Check a version. `{"version", "files", "expect"}` (`expect` can be omitted) |
| POST | `/api/managed/apply` | operator | yes | Normal | Save a version and apply it. `{"expect", "version", "files"}` |
| POST | `/api/managed/activate` | operator | yes | Normal | Apply by name. `{"expect", "version"}` |
| POST | `/api/managed/rollback` | operator | yes | Normal | Roll back to the previous version. `{"expect"}` |
| GET | `/api/managed/job` | viewer | yes | Normal | The last apply job |
| GET | `/api/managed/history` | viewer | yes | Normal | Configuration history |
| GET | `/api/config` | operator | yes | Normal | Values of the configuration file |
| GET | `/api/records` | viewer | yes | Normal | Reading logs |
| GET | `/api/audit` | operator | yes | Normal | The newest 200 lines of the audit log |
| GET | `/api/users` | owner | no | Normal | List of users |
| POST | `/api/users` | owner | no | Normal | Create a user. `{"name", "role", "password"}` |
| PUT | `/api/users/<name>` | owner | no | Normal | Change the role or the enabled or disabled state. Either `{"role"}` or `{"disabled"}`, only one of them |
| POST | `/api/users/<name>/password` | owner | no | Normal | Set the password of another user. `{"password"}` |
| DELETE | `/api/users/<name>/mfa` | owner | no | Normal | Disable the two-factor authentication of another user |
| GET | `/api/tokens` | owner | no | Normal | List of the API tokens of everyone |
| DELETE | `/api/tokens/<id>` | owner | no | Normal | Remove an API token of anyone |

- An API marked "Normal" cannot be used by a session that is waiting for a password change or waiting for two-factor setup.
- The main response bodies (times are epoch milliseconds for users and API tokens; epoch seconds for `made` of a generation, `made` of a version of the managed configuration, `started` and `ended` of an apply job, and `not_after` of a certificate; and RFC 3339 for `ts` of the histories and the audit log):
  - `POST /api/login`, `POST /api/login/mfa`: `{"name", "role", "csrf", "mfa", "must_change"}` and a cookie
  - `GET /api/session`: `{"name", "role", "csrf", "mfa", "recovery_left", "must_change", "state", "idle_expires_in_ms", "total_expires_in_ms"}`. `mfa` is whether two-factor authentication is set up
  - `PUT /api/account/password`, `DELETE /api/account/mfa`: `{"csrf"}` and a new cookie. The other sessions end. A password change removes all API tokens
  - `POST /api/account/mfa/setup`: `{"secret", "uri"}`. `POST /api/account/mfa/confirm`: `{"csrf", "recovery"}` and a new cookie
  - `GET /api/users`: `{"users": [..]}` (`name`, `role`, `disabled`, `mfa`, `must_change`, `created`, `changed`). `POST /api/users` and `PUT /api/users/<name>` return that user
  - `GET /api/account/tokens`, `GET /api/tokens`: `{"tokens": [..]}` (newest first; the secret is not included)
  - `POST /api/managed/check`: 200 `{"version", "detect"}`. `POST /api/managed/apply`: 202 `{"version", "placed", "job"}`. `POST /api/managed/activate`, `POST /api/managed/rollback`: 202 `{"version", "job"}`. `DELETE /api/managed/versions/<version>`: 200 `{"removed", "cleaned"}` (see "Managed Configuration Operations" above)

## Response Format

### Responses

- Every response is JSON and has these headers (the files of the admin screens are different; see "Admin Screens" above): `Content-Type: application/json`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `X-Request-ID` (the request ID).
- The request ID is the `X-Request-ID` of the request when the request comes from a peer in `admin.trusted_proxies` and that value is in the form that the proxy gives (16 lowercase hexadecimal digits, `-`, and 1 to 16 digits). Otherwise the admin process makes an ID of the same form. For a request that went through the proxy, `id` in the log of the proxy and `id` in the audit log are the same.
- A failure response is `{"error": "<sentence>"}`. The sentence is one fixed English sentence for each kind of error, and does not contain a value of the request (only the name of an input file is added, as a separate item, as `subject` of the 400 of an import). The 422 of an import also has `trial`, and the failures of choosing a generation and of rollback also have the items of the table above. The admin screens replace this sentence with a sentence in each language.
- The 400 of `POST /api/managed/check` and `POST /api/managed/apply` is `{"error", "at"}`. `at` is the location, in the body, of the value that was refused. If there is no location, it is `null`. The 409 that `POST /api/managed/activate` and `POST /api/managed/rollback` give because no generation is chosen for an upstream engine is also `{"error", "at"}`.
  - A location is written as the path of the setting keys in the request body. `files` is for when there are too many files, and `files[k]` is for a file that is too large, that appears twice, or that the version does not specify. A location in the version takes forms such as `sites[1].hosts[0]`, `upstreams.app.servers[2].address`, `upstreams.app.engine`, `sites[0].certificate.key`, and `host_policies[1].rate_limit.keys`.
  - Array indexes count from 0.
  - A body whose JSON has the wrong form, and an `expect` that is not 64 lowercase hexadecimal digits, have no location (`null`). A 400 that is refused in "Order of Admin API Checks" below has no `at` key.
  - The sentence is a fixed sentence that does not contain a location. A refusal of the configuration file (409) also has only a sentence and no location.
- `detail` of the apply job (the sentence of the proxy that refused) does not have the location in `at`, and writes it inside the sentence. In it, listeners and upstream servers count from 1 (`listener 1 cannot be bound`, `(upstream app, server 1)`, and so on), and a site is written by its name (`site app`). The way of counting differs from `at` of the check.

### Status Codes

| Status code | Case | Main `error` |
|---|---|---|
| 400 | The body is not a JSON object, it has a key that the API does not recognize, there are both a cookie and an API token, an input error | `bad request`, a sentence for each API. `/api/managed/check` and `/api/managed/apply` also have `at` |
| 401 | There is neither a session nor an API token, the session has ended, the user was changed, an invalid API token. A login error | `unauthorized`, `invalid credentials` |
| 403 | Refused by `Origin`, CSRF, the role, the state, or an API that cannot use an API token. An error of the password or the verification code. Other refusals | `forbidden`, `second factor required`, `password change required`, `second factor setup required`, `the password is wrong`, `the current password is wrong`, `the code is wrong`, `mfa is required` |
| 404 | A path that is not in the table, a generation, a version of the managed configuration, a user or an API token that does not exist, a configuration without `records` | `not found`, `no such generation`, `records are not configured` |
| 405 | The path does not have that method. `Allow` is added (it includes `HEAD` if there is `GET`) | `method not allowed` |
| 408 | The body does not arrive within 30 seconds | `request timeout` |
| 409 | It overlaps another change, it does not fit the state, a limit on a number, the engine of the generation cannot be used, a proxy that does not return the state of each engine, no generation is chosen for an upstream engine, there is no managed configuration, the configuration file is rejected | `conflict`, `the name is taken`, `the store has too many users`, `the user has too many tokens`, `the last enabled owner stays`, `the user was changed since it was read`, a sentence of a generation operation (`the chosen generation is not the one that was expected`, `the proxy does not report its engines`, and so on), `the configuration has no managed object`, `a change of the managed configuration is under way`, a sentence of a managed configuration operation (`no generation is chosen for the engine of an upstream`, and so on) |
| 413 | The body is over the limit | `payload too large` |
| 415 | An API that reads a body gets a `Content-Type` that is not `application/json` | `unsupported media type` |
| 422 | The trial of an import failed | `the trial failed` |
| 429 | The count of the client is exceeded | `too many tries` |
| 500 | An inconsistency inside the admin process. The rules store or the managed store cannot be read | `internal error`, the sentences of the rules store and the managed store |
| 502 | The proxy did not switch | `the proxy did not switch` |
| 503 | The store or an audit log line cannot be read or written, a timeout, the proxy cannot be reached, checks of the managed configuration overlap | `unavailable`, `the proxy cannot be reached`, `the proxy is busy`, `the proxy did not say how the switch ended`, `a check of a managed version is under way` |

A change of the managed configuration ("Save and apply", "Apply by name", "Roll back") gets the response 202 when it is accepted. Read how it ended from the apply job (see "Managed Configuration Operations" above).

### Order of Admin API Checks

The first check that is not passed gives the response.

1. The path (404 if it is not in the table) and the method (405 if it does not have it)
2. For an API that has a minimum role, the credentials (the cookie of a session or `Authorization: Bearer`). If both are present, 400; if neither is present or it does not match, 401; for a client that has used up its API token count, 429
3. For a change, `Origin` (403) and, for a session, `X-CSRF-Token` (403)
4. An API token for an API that cannot use an API token (403)
5. The state of the session (403; a fixed sentence)
6. The role (403)

A request that was refused at 3 to 6 is written to the audit log, because the user is known. After that, if the API reads a body, it validates `Content-Type` (415) and the form of the JSON (400).
