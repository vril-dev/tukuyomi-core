[English](system-overview.md) | [日本語](system-overview.ja.md)

# System Overview

> **Status: initial draft**
>
> This repository holds the source code for the following parts, and the release artifacts from 0.1.0 on (a tarball of executables for Linux x86_64).
>
> - The initial implementation of the inspection kernel (`kernel/` and `inspector/`) and the ModSecurity inspector process (`inspector-modsecurity/`)
> - In `proxy/`: receiving and forwarding HTTP/HTTPS requests, access control and rate limits, log files, the admin process (admin API and admin screens), and the managed configuration
> - The records shipper (`records-ship/`)
>
> "Current Status" shows what is implemented. Everything else is a goal, an assumption, a candidate, or an open point.
> Content marked "candidate" or "proposal" is not an adopted decision.

## Scope of This Document

This document describes the purpose of tukuyomi-core, its current status, the assumptions and candidates for the design, the scope under study, and the terms used.

- For the candidate structure, the division of responsibilities, the failure scope, and the design obligations, see the [architecture overview](architecture.md).
- For the design principles and how they apply, the distinction between inspection modes and technical failures, and the policy on porting and versions, see [design principles and constraints](design-principles.md).

## Purpose

tukuyomi-core is derived from tukuyomi (the tukuyomi WAF) and aims to be a product focused on the WAF.

- The criteria for which features to keep and which to remove are undecided (OV-01). Until they are decided, no decision is made to keep or remove any individual feature.
- The version of tukuyomi to port from is undecided (OV-02).

## Current Status

| Field | Current status |
|---|---|
| Product code | Source code exists for the inspection kernel, receiving and forwarding HTTP/HTTPS requests, access control and rate limits, the admin process (admin API and admin screens), the managed configuration, and the records shipper (see the sections below). There is no other code |
| Built executables and release artifacts | Since 0.1.0, the four executables for Linux x86_64 have been bundled into one tarball and distributed through GitHub releases. The product can also be built from source (see "Release Tarball" and "Building from Source" in the [build and deployment guide](../../build/binary-deployment.md)) |
| Request inspection (URI, headers, body) | The inspection kernel inspects the URI, the headers, and the start of the body of each received request. Only some body types can be inspected (see the next two sections). The overall scope is still under study |
| Response inspection | Not implemented, and whether to implement it is also undecided (OV-04) |
| Rule generations | Implemented: importing rule sets, choosing and switching generations for each engine (Coraza or ModSecurity), choosing the inspection engine for each upstream, detect-only mode, and bypass routes (see "HTTP/HTTPS Receiving and Forwarding (Implemented)" below). The admin API and the admin screens can also import rule sets, choose a generation for each engine, switch, and roll back to the previous generation (see "Admin Process (Implemented)" below) |
| Access control and rate limits | Implemented: global allow and deny by IP address and country, and per-client rate limits. Both can be set differently for each host with host policies (`host_policies`). The country database is not bundled; the operator provides it (see "Access Control and Rate Limits (Implemented)" below) |
| Managed configuration | Sites and certificates, upstreams, routes, the default upstream, global access control and rate limits, and host policies are saved as versions, separately from the configuration file. They can be changed from the admin screens and the admin API and applied without stopping the proxy (see "Managed Configuration (Implemented)" below). The proxy can also run with the configuration file alone, without the managed configuration |
| Logs | Per-request logs and other lines are written to standard error as one JSON object per line and, if configured, to files that rotate by size and count. For each route, you can choose between refusing the request when the log cannot be kept and keeping only the security logs. A separate process (the records shipper) can ship the lines in the files to PostgreSQL or MySQL (see "Records Shipper (Implemented)" below). The admin API and the admin screens can search the log files. A monitoring listener provides health checks and metrics. The policy on the storage method, retention period, and capacity for logs is undecided (DP-10, OV-07) |
| Admin UI | Available. The admin process serves the screens built into the executable (see "Admin Process (Implemented)" below). The commands (`rules`, `managed`, `acme renew`, `config check`) can also be used. How far to reuse and improve tukuyomi's admin UI is undecided (OV-03) |
| Isolation and privilege restriction on the OS | Does not run as root. At start, an inspector process restricts its own privileges with Landlock and by dropping capabilities. The inspector processes, the admin process, and the records shipper run as the same OS user as the proxy (AR-04) |
| Supported environments and deployment structure | Undecided (OV-06). The current implementation runs on a single Linux host, and a systemd example is provided |
| Documents | [Documentation Index](../../README.md), the three documents in 00_overview (including this one; all are initial drafts), [Build and Deployment](../../build/binary-deployment.md), [Operator Reference](../../operations/operator-reference.md), [Admin Reference](../../operations/admin-reference.md) |

### Inspection Kernel (Implemented)

The inspection kernel is the part that inspects requests. The current implementation is an initial one and does not mean the WAF is complete.

- The Rust library [`kernel/`](../../../kernel/) uses only the standard library. It creates no threads of its own and runs on the caller's threads. The supervisor (`Supervisor`) in this library owns starting, stopping, and restarting the inspector processes, and the temporary directory for each start.
- The Go inspector process [`inspector/`](../../../inspector/) uses the Coraza Go API directly. The initial implementation of the inspection kernel pins Coraza v3.8.1. This is the version the current code uses; it is not a recommendation, and it does not decide the procedure for DP-09.
- The ModSecurity inspector process [`inspector-modsecurity/`](../../../inspector-modsecurity/) is a bridge between Rust and C++ and statically links libmodsecurity v3.0.17. Each rule set generation records which engine inspects with it, and the library starts the inspector process for that generation's engine. The proxy runs an inspection kernel for each started engine, and a request is inspected only by the inspection kernel for the engine that its destination upstream uses. Both inspector processes use the same protocol and have the same protection mechanisms described below (see "ModSecurity Generations" in the [operator reference](../../operations/operator-reference.md)).
- The library starts the inspector process directly, and the two communicate on the same host through an inherited pair of Unix domain sockets (fd 0 of the inspector process). Neither the library nor the inspector process adds a TCP listening port.
- Each request gets one of three results: allow (`Allow`), block (`Block`), or uninspectable (`Uninspectable`). A request whose inspection could not be completed is not allowed. Input that is known to be uninspectable is returned to the caller at intake (`Refused`) and is not allowed either. This applies, for example, to a request that has a body whose Content-Type is none of `application/x-www-form-urlencoded`, `multipart/form-data`, `application/json`, or `application/<name>+json`, to a request with Content-Encoding, and to a request with Transfer-Encoding. One case is accepted: a request that passes only the start of its body, whose only Transfer-Encoding is a single `chunked` line, and that has no Content-Length. This lets the start of an HTTP/1.1 chunked body be inspected.
- Restarts are limited to a set number within a recent period (the configured window). Once the limit is reached, there are no more restarts until the number of restarts within the window falls below the limit, and requests that wait in the meantime are treated as uninspectable (503 for HTTP). A deterministic failure, such as a rule error, does not cause a restart.
- Each start gets its own temporary directory, with permissions that only the process's OS user can use. It is deleted once the inspector process is confirmed to have exited. If the exit cannot be confirmed, the directory is left in place and no new inspector process is started.
- After reading the rule set generation, the inspector process uses Landlock to make files outside the temporary directory unreachable (on Linux 6.7 or later, it also forbids TCP bind and connect), drops its capabilities, and sets `no_new_privs`. It does not start on Linux without Landlock. UDP, Unix domain sockets, and MPTCP sockets cannot be restricted.
- At most 1 MiB of a request's body can be passed for inspection. When only the start of the body is passed, the inspector process is told that the body was truncated, and a parse failure caused by the truncation does not block the request.

### HTTP/HTTPS Receiving and Forwarding (Implemented)

This part receives and forwards requests and sits in front of the inspection kernel. It does not mean the WAF is complete. For details on setting keys, commands, and logs, see the [operator reference](../../operations/operator-reference.md).

- The Rust executable [`proxy/`](../../../proxy/) uses tokio, hyper, and rustls, and uses the inspection kernel as a library. A single configuration file (JSON) defines the listeners, upstreams, routes, and the limits and timeouts of each stage. When the managed configuration is used, upstreams, routes, the default upstream, sites and certificates, global access control and rate limits, and host policies go into a managed configuration version, and everything else goes into the configuration file (see "Managed Configuration (Implemented)" below). Setting values have no defaults; their ranges and the relations between them are validated at start. The `config check` command runs the same validation before start.
- There are 1 to 8 listeners, of three kinds: plain HTTP, TLS (1.2 and 1.3, with the certificate chosen by server name), and redirect to https. They handle HTTP/1.1 and HTTP/1.0, and TLS listeners can also handle HTTP/2. Connection reuse (keep-alive and pipelining) is supported.
- An upstream is a named group of servers, and servers are chosen by weight. A server whose requests keep failing is marked as failed and left out for a while, and an upstream can also have backup servers. Connections are reused. A request whose method is safe to send twice can be retried on the next server. Server names are resolved at start and when the configuration is reloaded. The proxy can connect to each upstream over TLS (it uses HTTP/1.1 to upstreams).
- A route chooses the upstream by the request's Host and path. For each route, you can set restrictions by client IP address and country, rewrite the request and the response (Host, path, query, headers), set the body limit, and decide how streaming responses and WebSocket are handled. WebSocket frames are not inspected.
- The header section of a request is strictly validated before HTTP parsing. For example, line endings must be CRLF only, the request-target must be origin-form only, there must be exactly one Host, and a request with both Transfer-Encoding and Content-Length is refused. A request that violates these rules or exceeds a limit is refused with a fixed response that has no body (400, 408, 413, 414, 415, 417, 431), and nothing is sent to the upstream. HTTP/2 requests are also rewritten into the same form and validated by the same rules.
- The body is inspected up to a configured number of bytes from its start (up to 1 MiB). If the body is longer, the rest is passed to the upstream uninspected once the request is allowed. Chunked bodies are supported. `gzip` is the only Content-Encoding accepted, and on routes that inspect, the decompressed body is inspected without Content-Encoding (a body that exceeds the inspected length after decompression, a corrupt body, and other encodings are refused). On routes that inspect, as in the inspection kernel, the only body types are `application/x-www-form-urlencoded`, `multipart/form-data`, `application/json`, and `application/<name>+json` (the name consists of letters, digits, `.`, and `-`), and other types are refused with 415. On bypass routes, bodies are passed whatever their type. On every route, a body with two or more Content-Type headers is refused with 415. For a JSON body, the inspector process selects the Coraza JSON body processor to parse it (the operator's rules cannot change this). JSON nesting is limited to 64 levels (because the expanded amount is limited, nested arrays in a short body can be blocked at a shallower depth). A body nested more than 64 levels deep, a body that does not conform to RFC 8259, and a body that exceeds the limit on the number of arguments are blocked.
- Only the following are forwarded to the upstream: requests allowed by inspection (`Allow`), requests that matched a rule in detect-only mode, and requests on bypass routes. Before forwarding, per-connection headers (hop-by-hop headers: Connection and the headers it lists, Keep-Alive, TE, Transfer-Encoding, Upgrade, Expect, and so on) and headers whose names contain `_` are removed, and X-Forwarded-For, X-Forwarded-Host, and X-Forwarded-Proto are added. For X-Forwarded-For, only the values from proxies that the configuration trusts are kept. The proxy answers a blocked request with the rule's status code (500 if it is outside the range 200 to 599) and an uninspectable request with 503 (500 when it indicates an internal inconsistency in the program); neither is forwarded. If, for example, the proxy cannot connect to the upstream, the upstream times out, or its response is invalid, the proxy responds with 502.
- The `rules import` command imports a rule set, and a rule set that passes the trial becomes a generation. `rules activate` chooses a generation for each engine, and SIGUSR1 switches to the chosen generation without stopping the proxy. The inspecting engine can be chosen for each upstream (see "Choosing the Inspection Engine" in the [operator reference](../../operations/operator-reference.md)). A generation is either in block mode or detect-only (a request that matches a rule is let through and logged), and it can have bypass routes (Host and path). The CRS is not bundled; it is fetched with a script that pins the version and the checksum.
- Certificates are either placed as files or issued and renewed with the `acme renew` command (ACME HTTP-01), and SIGUSR2 reloads them. When the managed configuration is used, site certificates are kept in the managed store (see "Managed Configuration (Implemented)" below).
- SIGHUP reloads the configuration file and switches to the new configuration without stopping the proxy. When the managed configuration is used, the version selected in the managed store is read along with it. The admin process requests the same reload, naming a version, through `reload` on the control socket. The switch covers routes and upstreams, access control and rate limits (including the country database), added and removed listeners, certificates, and so on, and connections accepted after the switch use the new configuration. An open connection finishes its requests with the configuration it was accepted under and is then closed; requests are not refused. If a configuration is rejected (it has errors, changes a setting key that cannot change while running, has an upstream whose engine is not running, or has a listener that cannot bind), nothing changes.
- Logs are written to standard error as one JSON object per line. A request log has the request ID, the method, Host, and path (without the query), the response, the generation of the rules that made the decision, and the ID, severity, and anomaly score of the matched rules. The request ID is also set in `X-Request-ID` on the request sent to the upstream and on the response to the client (a value sent by the client is replaced). A log that cannot be written is discarded and counted, and the request is not stopped. If configured, the same lines are also written to files in a directory. The files rotate by size and count and, if configured, are synced to disk at a fixed interval; a line that could not be written to a file goes to standard error and is counted. For each route, you can choose between refusing the request with 503 when its log cannot be kept (`required`) and keeping only security logs, such as those for requests decided by rules (`security`).
- If the configuration places a monitoring listener on a loopback address, it responds to `/healthz`, `/readyz`, and `/metrics` (Prometheus text format). The proxy tells systemd (`Type=notify`) when it is ready and when it is stopping.
- It does not run as root. Starting it and all commands are refused if any of the user IDs is 0.
- On SIGTERM or SIGINT, the proxy stops accepting new connections and requests, keeps processing in-flight requests until the timeout, and then stops the inspector processes and exits.

### Access Control and Rate Limits (Implemented)

Access control and rate limiting is the mechanism that refuses requests before a route is chosen. It does not mean the WAF is complete. For details on setting keys and how requests are counted, see "Access Control and Rate Limits" in the [operator reference](../../operations/operator-reference.md).

- It is set by the top-level `access`, `rate_limit`, `host_policies`, and `geo` in the configuration (when the managed configuration is used, everything except `geo` goes into a managed configuration version). It applies to every request that passes the header checks, except ACME challenges, the monitoring listener, and, when the managed configuration is used, the admin route. It also applies to requests that match a bypass route and to the listener that redirects to https. New values take effect on a reload, by SIGHUP or by `reload` on the control socket.
- `access` allows and denies requests by the network the client address belongs to and by country. A route's own `access` can also take a country list. A refused request gets 403.
- The country is looked up in a MaxMind DB format database that the operator provides. The database is neither bundled nor fetched. Private addresses and addresses that are not in the database are treated as `UNKNOWN`.
- `rate_limit` limits the request rate of each client, counting IPv4 per address and IPv6 per /64. The number of tracked clients is limited; when the limit is exceeded, the oldest clients stop being counted. A client that exceeds the limit gets 429 with `Retry-After`.
- `host_policies` (host policies) is a setting that applies, in place of the global `access` and `rate_limit`, to requests whose Host is a given host. For access control and for rate limiting, you can choose to inherit the global setting, apply this host's own setting, or not use it. Hosts are compared by the same rules as for routes. A request whose Host cannot be read is treated as possibly matching any host: it is refused unless it passes the global `access` and the `access` of every host policy, and it is counted by each rate limit counter. Up to 64 host policies can be written, with up to 1024 hosts in total.
- The client address is taken from `X-Forwarded-For` only when the value comes from a trusted peer (`trusted_proxies` in the configuration).

### Admin Process (Implemented)

The admin process is separate from the proxy and provides the admin API and the admin screens. It does not mean the WAF is complete. For details, see the [admin reference](../../operations/admin-reference.md).

- It runs as the `admin` command of the same executable as the proxy. It runs as the same OS user as the proxy and listens for plain HTTP connections on a loopback address. To use it from outside, go through a route on the proxy's TLS listener (when the managed configuration is used, the admin route set in `admin.route` in the configuration file).
- It has users, roles (`viewer`, `operator`, `owner`), sessions, API tokens, password changes, MFA (TOTP), a limit on login attempts, and an audit log. Users, API tokens, and history are stored in files.
- It can list, import (with a trial), choose, and remove rule generations, ask the running proxy to switch, and roll back to the previous generation. Choosing, switch requests, and rollbacks are done for each engine. It keeps a switch history.
- It can list, check, save and apply, and remove managed configuration versions, apply a version by name, and roll back to the previous version. It keeps a configuration history (see "Managed Configuration (Implemented)" below).
- It sends its requests to the proxy through a Unix domain socket (the control socket). On this socket, the proxy answers only status queries, generation switch requests (which name the engine to switch), and reload requests that name a managed configuration version.
- Log files can be searched by time, type, class, status, rule, request ID, client, generation, and engine.
- The admin screens are static files built into the executable ([`proxy/admin-ui/`](../../../proxy/admin-ui/)), served by the admin process. For how the screens are organized, see "Admin Screens" in the [admin reference](../../operations/admin-reference.md). The screens are available in Japanese and English.

### Managed Configuration (Implemented)

The managed configuration moves part of the configuration out of the configuration file so that it can be changed from the admin screens and the admin API. It does not mean the WAF is complete. For setting keys, commands, and procedures, see "Managed Configuration" in the [operator reference](../../operations/operator-reference.md). For the admin API and the screens, see "Managed Configuration Operations" and "Admin Screens" in the [admin reference](../../operations/admin-reference.md).

- It is used when the configuration file has `managed`; otherwise the proxy runs with the configuration file alone. Turning it on or off requires restarting the proxy and the admin process.
- Sites and certificates, upstreams, routes, the default upstream, global access control and rate limits, and host policies are saved as versions in the managed store (the directory set by `managed.dir` in the configuration). A version is named by the SHA-256 of its content, and the content of a saved version does not change. Certificate chain, private key, and CA files are also saved under the SHA-256 of their content. A configuration file that has `managed` cannot contain the setting keys that belong in a version.
- The proxy reads the version selected in the managed store, along with the configuration file, at start, when `config check` runs, and when it receives SIGHUP. The proxy does not write to the managed store.
- The admin process checks and saves a version made from a draft on the admin screens, then asks the proxy to apply it through `reload` on the control socket. The version becomes the selected one in the managed store only after the proxy has switched its configuration to it; a version that the proxy refused is not selected. Applying does not stop the proxy.
- When the managed configuration is used, the admin screens are reached through the admin route set in `admin.route` in the configuration file, and the proxy creates this route itself. Neither the global settings nor the host policies apply to it; it is protected by the network list in `admin.route.access`.
- The `managed` command (`import`, `activate`, `list`, `remove`) creates, selects, lists, and removes versions. `acme renew` writes the certificates of ACME sites to the managed store.

### Records Shipper (Implemented)

The records shipper is a process separate from the proxy that reads the proxy's log files and ships their lines to a DB table. It does not mean the WAF is complete. For details, see "Records Shipper" in the [operator reference](../../operations/operator-reference.md).

- The Rust executable [`records-ship/`](../../../records-ship/) reads the same configuration file as the proxy and runs as the same OS user. It does not read managed configuration versions. The libraries that connect to the DB (`tokio-postgres` for PostgreSQL and `mysql_async` for MySQL) are included only in this executable, not in the proxy executable that receives external requests. The DB password is kept in a file separate from the configuration file, and only the records shipper reads it.
- The destination, PostgreSQL or MySQL, is chosen in the configuration. The table is created if it does not exist. Connections to the DB use TLS by default, and the certificate and the host name are validated.
- It tracks each log file by inode and creation time, and writes the lines and the shipped position in one transaction. Line hashes are UNIQUE, so a line sent twice is stored once. While it cannot connect to the DB, it waits, and when the connection is back, it continues from where it stopped.
- The proxy estimates the lag by reading the file where the records shipper writes its shipped position, and on `required` routes it refuses requests before rotation would delete logs that have not been shipped.
- Old rows are deleted after the configured number of days.

### Not Implemented or Not Decided

Not implemented:

- Parts of HTTP receiving and forwarding outside the scope above (HTTP/3, plain HTTP/2, HTTP/2 to the upstream, request trailers, relaying 1xx responses (except WebSocket's 101), PROXY protocol, response caching). For the supported scope, see OV-05
- Inspection of XML bodies, of JSON types other than the forms above (such as `text/json`), and of bodies with a Content-Encoding other than `gzip` (AR-09)
- Response inspection (OV-04)
- Editing the configuration file itself through the admin API or the admin screens (the admin screens edit the managed configuration; the configuration file is only displayed). The admin process and the records shipper applying changes to their own configuration while running (the admin process reloads the configuration file each time it validates or changes the managed configuration, but keeps using the values it had at start, such as `admin`). Replacing the executable without dropping connections
- Issuing the ACME certificates for a managed configuration version before that version is applied. If you apply a version that adds an ACME site or changes its hosts, and the managed store has no certificate for that set of hosts, the site's hosts cannot be reached over TLS until you issue one with `acme renew`
- Handling the TLS private key in a process separate from the proxy (AR-04)
- Signed audit logs and tracing. Storing users, API tokens, and history anywhere other than files. Storing logs anywhere other than PostgreSQL and MySQL. Searching logs in the DB through the admin API and the admin screens (DP-10, OV-07)
- Built executables for environments other than Linux x86_64
- Running the inspector processes and the records shipper as different OS users or as different services (AR-04)

Not decided:

- Whether to adopt the candidate structure as a whole. For the initial implementation of the inspection kernel only, AR-01 adopted a structure of a Rust library and a Go inspector process that runs as a separate process. The comparison with libcoraza is not finished.
- The open points in each document, such as the communication method, the supervisor's responsibilities, the restart conditions, and body handling, remain undecided as a whole, and the current implementation of the inspection kernel does not settle them. For example, refusing by body type is a rule of the initial implementation of the inspection kernel; it does not settle AR-09. The refusal rules, response status codes, limits, and timeouts of HTTP/HTTPS receiving and forwarding are also rules of this implementation and do not settle AR-06, AR-07, AR-16, AR-18, or OV-05. The implementations of the admin process, the admin API, the admin screens, the log files, the records shipper, access control and rate limits, and the managed configuration also do not settle OV-03, OV-07, AR-05, or DP-10.
- The security of the product as a whole has not been evaluated.

## Assumptions, Candidates and Open Points

These documents sort their content into the following categories.

| Category | Meaning |
|---|---|
| Assumption | A direction set for the project. Changing it requires a new decision |
| Candidate | A strong proposal that has not yet been verified or adopted |
| Undecided | Something whose candidates have not been narrowed down, or whose decision is on hold |
| Implemented | Only the scope of the inspection kernel, HTTP/HTTPS receiving and forwarding, access control and rate limits, the admin process, the managed configuration, and the records shipper (the sections under "Current Status"). Nothing else is in this category |

### Assumptions

- The main implementation language is Rust.
- The product is derived from tukuyomi and centered on WAF functionality. Features other than the WAF are removed after the criteria (OV-01) are decided.
- Its design principles are privilege separation, distrust of all input, minimalism, deterministic resources, and structural security (see [design principles and constraints](design-principles.md)).
- For the admin UI, reusing and improving tukuyomi's admin UI is under study. The scope and the base version are undecided (OV-03).
- Code is organized by responsibility, type, and owner, and files are not split excessively. The concrete structure of modules and files is decided as needed during implementation.

### Candidates

- The comparison assumes the proposal to use Coraza as the inspection engine. The proposal to build an inspection engine from scratch is not a candidate.
- The first candidate for the connection method is a structure that splits the system into a Rust proxy and a small Go inspector process that uses the Coraza Go API directly (AR-01). For the initial implementation of the inspection kernel only, a Rust library and a Go inspector process running as a separate process were implemented from this structure. The Rust proxy that handles HTTP was implemented within the scope of "HTTP/HTTPS Receiving and Forwarding (Implemented)" above.
- A structure in which the Rust proxy calls libcoraza (Coraza's C library) is kept for comparison (AR-01).

Which structure is faster, simpler, or safer is not decided before verification. For the points of comparison, see the [architecture overview](architecture.md).

## External Elements

| Element | Role | Handling |
|---|---|---|
| Client | Sends HTTP requests to the protected application | Everything it sends is treated as untrusted input |
| Upstream application | The protected application that tukuyomi-core forwards requests to | Responses are also treated as input. For response inspection, see OV-04 |
| Operator | Manages settings and rules, and checks logs | For the means and scope of administration, see OV-03 and AR-05. For the current implementation, see "Current Status" |
| Rules and settings | Determine what is inspected | Rules and settings are also validated as input. For the functions and privileges they may use, see DP-07 |

## Scope Under Study

The following table lists what is under study. It does not decide whether any feature is kept or removed (OV-01).

| Area | Content | Status |
|---|---|---|
| HTTP receiving and forwarding | Accepting connections, interpreting HTTP, forwarding to the upstream | In the candidate structure, the Rust proxy handles this. For the implemented scope, see "Current Status". For the supported HTTP versions, see OV-05 |
| Request inspection | Inspecting connection information, the URI, headers, and body, and deciding the result | Implemented in the inspection kernel for a limited scope (see "Current Status"). The overall scope is still under study |
| Response inspection | Inspecting response headers and the response body | Undecided (OV-04) |
| Rule and configuration management | Validating and applying rules, and switching generations | Importing rule sets with a trial, and choosing and switching generations for each engine, are implemented through commands and signals and through the admin API and the admin screens. Editing and applying part of the configuration (the managed configuration) through the admin API and the admin screens is also implemented (see "Current Status"). Editing the configuration file itself is not implemented. The area as a whole is still under study (AR-11) |
| Logs | Logs of detections, blocks, the reasons inspection was not done, uninspectable requests, and upstream failures | Writing request logs (JSON) to standard error and to files, searching them through the admin API and the admin screens, and metrics for monitoring are implemented. The policy on the storage method, period, and capacity is undecided (DP-10, OV-07) |
| Admin UI | Operating and displaying settings, rules, and logs | The admin process and the admin screens are implemented (see "Current Status"). The scope of reuse and improvement and the base version are undecided (OV-03). For authentication and how privileges are divided as a whole, see AR-05 |
| Access control and rate limits | Global and per-host allow and deny by IP address and country, and per-client rate limits | Implemented (see "Current Status"). The area as a whole is still under study |
| Operation | Starting, stopping, restarting, checking readiness, and monitoring | The inspection kernel implements starting, stopping, and restarting the inspector processes and checking their readiness. Stopping the proxy, validating the configuration, switching generations, reloading certificates, the monitoring listener and metrics, and notifying systemd are also implemented. The area as a whole is still under study (AR-03, AR-12, AR-17) |

## Terms

| Term | Meaning in this set of documents |
|---|---|
| Rust proxy | In the candidate structure, the Rust process responsible for receiving, interpreting, and forwarding HTTP, for the configuration, and for storing logs |
| Inspection kernel | The part responsible for inspecting requests. It consists of a Rust library (`kernel/`) and a Go inspector process (`inspector/`). For ModSecurity generations, the library starts the ModSecurity inspector process (`inspector-modsecurity/`) |
| Inspector process | In the candidate structure, the Go process responsible only for building rules with Coraza and for inspection |
| WAF instance | The unit that does the inspecting, built from the rules and settings of one generation |
| Transaction | The unit in which the inspection engine inspects one request (and the response too, if responses are inspected). It processes the phases needed for the adopted inspection scope in order and, at the end, runs the logging phase (phase 5) and Close. For which phases are called on each route, see AR-10 |
| Phase | A stage of the inspection engine's evaluation. The order is request headers, request body, response headers, response body, and logging. After an early block, or in a structure that does not inspect responses, intermediate phases may not be called, so a transaction does not always go through all the phases |
| Rule generation | The combination of rules and settings that is in effect at a point in time. Each update makes a new generation. One is chosen for each engine |
| Managed configuration | A mechanism that moves part of the configuration (sites and certificates, upstreams, routes, the default upstream, global access control and rate limits, and host policies) out of the configuration file so that it can be changed from the admin screens and the admin API. For the implemented scope, see "Managed Configuration (Implemented)" under "Current Status" |
| Managed store | The directory (`managed.dir` in the configuration) that holds the versions of the managed configuration and the files that the versions use, such as certificates |
| Version (of the managed configuration) | The content of the managed configuration at a point in time. The name is the SHA-256 of the content, and once a version is saved, its content does not change. It is not the same thing as a rule generation |
| Host policy | A setting (`host_policies`) applied to requests whose Host is that host, in place of the global access control and rate limits |
| Traffic that requires inspection | Traffic that the settings say must not be forwarded without inspection. For its definition, see DP-02 |
| Uninspectable | A state in which inspection cannot be completed for a technical reason such as a stop, a disconnection, a timeout, or an exceeded limit. It is handled separately from the case where inspection is intentionally not done |
| Explicit bypass | A route (bypass route) that the settings intentionally leave uninspected. Whether to keep it is an open point (DP-01) |
| On / DetectionOnly / Off | The modes of a Coraza WAF instance. On executes the disruptive actions of rules (deny, drop, redirect, and so on). DetectionOnly evaluates rules but does not execute disruptive actions. Whether logs are kept depends on the rules and the audit log settings (DP-10). Off does not evaluate rules. A rule match (detection) and the execution of a disruptive action (blocking) are handled separately |
| fail-closed | Not forwarding traffic that requires inspection when it is uninspectable. For where it applies, see [design principles and constraints](design-principles.md) |

## Open Points

Open points have IDs that are unique across documents, and this document uses OV-. Open points about the structure go under AR- ([architecture overview](architecture.md)), and those about principles and policies go under DP- ([design principles and constraints](design-principles.md)).

| ID | Item | Current handling | Affected scope |
|---|---|---|---|
| OV-01 | Criteria for which features to keep and which to remove | Undecided. Until the criteria are decided, no decision is made to keep or remove any feature | Functional requirements, AR-07, DP-01, DP-07, DP-08 |
| OV-02 | The version of tukuyomi to port from | Undecided | Precedents for porting, checking upstream behavior |
| OV-03 | How far to reuse and improve the admin UI, and the base version | Studying reuse and improvement is an assumption. The scope and the version are undecided | UI design, AR-05, DP-10 |
| OV-04 | Whether to inspect responses, and if so, the scope | Undecided | AR-08, AR-10, the "Returning the response" column of "States × Operations" |
| OV-05 | Supported HTTP versions and kinds of communication (HTTP/1.1, HTTP/2, HTTP/3, Upgrade, incremental sending, and so on) | Undecided | AR-06, AR-08 |
| OV-06 | Distribution form (including whether a single executable is required), supported environments, and deployment structure | Undecided | AR-01, AR-03, AR-04, AR-13, AR-17, DP-09 |
| OV-07 | How settings, rules, and logs are stored | Undecided | AR-05, AR-11, DP-10 |

## Related Documents

- [Architecture Overview](architecture.md)
- [Design Principles and Constraints](design-principles.md)
- [Documentation Index](../../README.md)
