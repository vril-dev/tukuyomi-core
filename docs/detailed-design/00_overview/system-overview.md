[English](system-overview.md) | [日本語](system-overview.ja.md)

# System Overview

> **Status: initial draft**
>
> This repository holds the source code of the following parts, and the release artifacts since 0.1.0 (a tarball of executables for Linux x86_64).
>
> - The initial implementation of the inspection kernel (`kernel/` and `inspector/`) and the ModSecurity inspector process (`inspector-modsecurity/`)
> - In `proxy/`: receiving and forwarding of HTTP/HTTPS requests, access control and rate limits, log files, the admin process (admin API and admin screens), and the managed configuration
> - The records shipper (`records-ship/`)
>
> The implemented scope is given in "Current Status". Everything else is a goal, an assumption, a candidate, or an open point.
> Content marked "candidate" or "proposal" is not an adopted decision.

## Scope of This Document

This document describes the purpose of tukuyomi-core, its current status, the assumptions and candidates of the design, the scope under study, and the terms used.

- For the candidate structure, the division of responsibilities, the failure scope, and the design obligations, see the [architecture overview](architecture.md).
- For the design principles and how they apply, the distinction between inspection modes and technical failures, and the policy on porting and versions, see [design principles and constraints](design-principles.md).

## Purpose

tukuyomi-core is derived from tukuyomi (the tukuyomi WAF) and aims to be a product specialized in WAF functionality.

- The criteria for which features to keep and which to remove are undecided (OV-01). Until the criteria are decided, no individual feature is decided to be kept or removed.
- The version of tukuyomi to port from is undecided (OV-02).

## Current Status

| Field | Current status |
|---|---|
| Product code | The source for the inspection kernel, HTTP/HTTPS request receiving and forwarding, access control and rate limits, the admin process (admin API and admin screens), the managed configuration, and the records shipper exists (see the sections below). There is no other code |
| Built executables and release artifacts | Since 0.1.0, four executables for Linux x86_64 are bundled into one tarball and distributed as a GitHub release. The product can also be built from source (see "Release Tarball" and "Building from Source" in the [build and deployment guide](../../build/binary-deployment.md)) |
| Request inspection (URI, headers, body) | The inspection kernel inspects the URI, the headers, and the start of the body of each received request. The body types that can be inspected are limited (see the next two sections). The overall scope is still under design consideration |
| Response inspection | Not implemented. Whether to do it is also undecided (OV-04) |
| Rule generations | Implemented: importing rule sets, choosing and switching generations for each engine (Coraza or ModSecurity), choosing the inspection engine for each upstream, detect-only mode, and bypass routes (see "HTTP/HTTPS Receiving and Forwarding (Implemented)" below). The admin API and the admin screens can also import, choose for each engine, switch, and roll back to the previous generation (see "Admin Process (Implemented)" below) |
| Access control and rate limits | Implemented: global allow and deny by IP address and country, and per-client rate limits. Both can be varied for each host with host policies (`host_policies`). The country database is not bundled; the operator provides it (see "Access Control and Rate Limits (Implemented)" below) |
| Managed configuration | Sites and certificates, upstreams, routes, the default upstream, global access control and rate limits, and host policies are saved as versions, separately from the configuration file. They can be changed from the admin screens and the admin API and applied without stopping the proxy (see "Managed Configuration (Implemented)" below). The proxy can also run with the configuration file alone, without the managed configuration |
| Logs | Per-request logs and other lines are written to standard error as one JSON object per line and, if configured, to files that rotate by size and count. For each route, you can choose between refusing the request when the log cannot be kept and keeping only the security logs. A separate process (the records shipper) can ship the lines of the files to PostgreSQL or MySQL (see "Records Shipper (Implemented)" below). The admin API and the admin screens can search the log files. A monitoring listener provides health checks and metrics. The policy on the storage method, retention period, and capacity of logs is undecided (DP-10, OV-07) |
| Admin UI | Available. The admin process serves the screens built into the executable (see "Admin Process (Implemented)" below). The commands (`rules`, `managed`, `acme renew`, `config check`) can also be used. How far to reuse and improve the admin UI of tukuyomi is undecided (OV-03) |
| Isolation and privilege restriction on the OS | Does not run as root. At start, an inspector process restricts its own privileges with Landlock and by dropping capabilities. The inspector processes, the admin process, and the records shipper run as the same OS user as the proxy (AR-04) |
| Supported environments and deployment structure | Undecided (OV-06). The current implementation runs on a single Linux host, and a systemd example is provided |
| Documents | [Documentation Index](../../README.md), the three documents in 00_overview (including this one; all are initial drafts), [Build and Deployment](../../build/binary-deployment.md), [Operator Reference](../../operations/operator-reference.md), [Admin Reference](../../operations/admin-reference.md) |

### Inspection Kernel (Implemented)

The inspection kernel is the part that inspects requests. The current implementation is an initial implementation and does not mean the WAF is complete.

- The Rust library [`kernel/`](../../../kernel/). It uses only the standard library. The library creates no threads of its own and runs on the caller's threads. The supervisor (`Supervisor`) inside this library owns starting, stopping, and restarting the inspector processes, and the temporary directory of each start.
- The Go inspector process [`inspector/`](../../../inspector/). It uses the Coraza Go API directly. The initial implementation of the inspection kernel pins Coraza v3.8.1. This is the version the current code uses; it is neither a recommended version nor a decision on the procedure of DP-09.
- The ModSecurity inspector process [`inspector-modsecurity/`](../../../inspector-modsecurity/). It is a bridge between Rust and C++ and statically links libmodsecurity v3.0.17. A rule set generation records which engine inspects with it, and the library starts the inspector process of the generation's engine. The proxy runs an inspection kernel for each engine that is started, and a request is inspected only by the inspection kernel of the upstream engine of its destination. Both inspector processes communicate with the same protocol and have the protection mechanisms below in the same way (see "ModSecurity Generations" in the [operator reference](../../operations/operator-reference.md)).
- The library starts the inspector process directly. They communicate on the same host through an inherited pair of Unix domain sockets (fd 0 of the inspector process). Neither the library nor the inspector process adds a TCP listening port.
- The result for each request is one of three: allow (`Allow`), block (`Block`), or uninspectable (`Uninspectable`). A request whose inspection could not be completed is not allowed. Input that is known to be uninspectable is returned to the caller at intake (`Refused`) and is not allowed. For example, a request that has a body and whose Content-Type is none of `application/x-www-form-urlencoded`, `multipart/form-data`, `application/json`, or `application/<name>+json`, a request with Content-Encoding, and a request with Transfer-Encoding are returned in this form. However, a request that passes only the start of the body, whose Transfer-Encoding is only a single `chunked` line, and that has no Content-Length is accepted (this is to inspect the start of an HTTP/1.1 chunked body).
- The number of restarts has a limit within a recent period of time (the configured window). When the limit is reached, no restart happens until the number of restarts within the window falls below the limit, and requests waiting in the meantime are made uninspectable (503 for HTTP). Deterministic failures such as rule errors do not trigger a restart.
- A dedicated temporary directory is created for each start, with permissions that only the OS user of the process can use. It is deleted after the exit of the inspector process is confirmed. When the exit cannot be confirmed, the directory is left in place and no new inspector process is started.
- After reading the rule set generation, the inspector process uses Landlock to make files outside the temporary directory unreachable (on Linux 6.7 or later, it also forbids TCP bind and connect), drops its capabilities, and sets `no_new_privs`. It does not start on a Linux without Landlock. UDP, Unix domain sockets, and MPTCP sockets cannot be restricted.
- A request can pass at most 1 MiB of body for inspection. When only the start of the body is passed, the inspector process is told that the body was truncated, and a failure to parse the body that is caused by the truncation does not block the request.

### HTTP/HTTPS Receiving and Forwarding (Implemented)

This is the part that receives and forwards requests, placed in front of the inspection kernel. It does not mean the WAF is complete. For the details of setting keys, commands, and logs, see the [operator reference](../../operations/operator-reference.md).

- The Rust executable [`proxy/`](../../../proxy/). It uses tokio, hyper, and rustls, and uses the inspection kernel as a library. A single configuration file (JSON) defines the listeners, upstreams, routes, and the limits and timeouts of each stage. When the managed configuration is used, upstreams, routes, the default upstream, sites and certificates, global access control and rate limits, and host policies are placed in a version of the managed configuration, and everything else is placed in the configuration file (see "Managed Configuration (Implemented)" below). The setting values have no defaults, and their ranges and the relations between values are validated at start. The `config check` command runs the same validation before start.
- There are 1 to 8 listeners. There are three kinds: plain HTTP, TLS (1.2 and 1.3, with the certificate chosen by server name), and redirect to https. HTTP/1.1 and HTTP/1.0 are handled, and TLS listeners can also handle HTTP/2. Connection reuse (keep-alive and pipelining) is handled.
- An upstream is a named group of servers, and servers are chosen by weight. A server whose requests keep failing is marked as failed and left out for a while, and an upstream can have backup servers. Connections are reused. A request with a method that is safe to send twice can be retried on the next server. Server names are resolved at start and when the configuration is reloaded. TLS can be used to connect to each upstream (HTTP/1.1 to the upstream).
- A route chooses the upstream by the request's Host and path. For each route, you can set restrictions by the client's IP address and country, rewriting of the request and the response (Host, path, query, headers), the body limit, and the handling of streaming responses and WebSocket. WebSocket frames are not inspected.
- The header section of a request is strictly validated before HTTP parsing. For example, line endings must be CRLF only, the request-target must be origin-form only, there must be exactly one Host, and the combination of Transfer-Encoding and Content-Length is refused. Violations and exceeded limits are refused with fixed responses that have no body (400, 408, 413, 414, 415, 417, 431), and nothing is sent to the upstream. An HTTP/2 request is also rewritten into the same form and validated by the same rules.
- The first configured number of bytes of the body (up to 1 MiB) is inspected. For a longer body, after the request is allowed, the rest is passed to the upstream without being inspected. Chunked bodies are handled. Only `gzip` is accepted as Content-Encoding, and on routes that inspect, the decompressed body is inspected without Content-Encoding (a body that exceeds the inspected length after decompression, a corrupt body, and other encodings are refused). On routes that inspect, as in the inspection kernel, the body types are only `application/x-www-form-urlencoded`, `multipart/form-data`, `application/json`, and `application/<name>+json` (the name consists of letters and digits, `.`, and `-`), and other types are refused with 415. On bypass routes, bodies are passed regardless of type. On every route, a body with two or more Content-Type headers is refused with 415. For a body of a JSON type, the inspector process selects the Coraza JSON body processor and parses with it (the operator's rules cannot change this). JSON nesting is limited to 64 levels (because of the limit on the expanded amount, nested arrays can be blocked at a shallower depth for a short body). A body that exceeds 64 levels, a body that does not conform to RFC 8259, and a body that exceeds the limit on the number of arguments are blocked.
- Only the following are forwarded to the upstream: requests allowed by inspection (`Allow`), requests that matched a rule in detect-only mode, and requests of bypass routes. Before forwarding, per-connection headers (hop-by-hop headers: Connection and the headers it lists, Keep-Alive, TE, Transfer-Encoding, Upgrade, Expect, and so on) and headers whose names contain `_` are removed, and X-Forwarded-For, X-Forwarded-Host, and X-Forwarded-Proto are added. For X-Forwarded-For, only the value from proxies trusted in the configuration is kept. The proxy responds to a block with the status code of the rule (500 if it is outside the range 200 to 599) and to an uninspectable request with 503 (500 when it indicates an internal inconsistency of the program); neither is forwarded. It responds to a failed connection to the upstream, a timeout, or an invalid response with 502.
- A rule set is imported with the `rules import` command, and a rule set that passes the trial becomes a generation. `rules activate` chooses a generation for each engine, and SIGUSR1 switches to the chosen generation without stopping. The engine that inspects can be chosen for each upstream (see "Choosing the Inspection Engine" in the [operator reference](../../operations/operator-reference.md)). A generation is either in block mode or detect-only (a request that matches a rule is passed and logged). A generation can have bypass routes (Host and path). The CRS is fetched with a fetch script that fixes the version and the checksum, and is not bundled.
- Certificates are placed as files, or issued and renewed with the `acme renew` command (ACME HTTP-01). They are reloaded with SIGUSR2. When the managed configuration is used, the certificates of sites are placed in the managed store (see "Managed Configuration (Implemented)" below).
- SIGHUP reloads the configuration file and switches to the new configuration without stopping. When the managed configuration is used, the selected version of the managed store is read together with it. The admin process requests the same reload, with a version specified, through `reload` on the control socket. Routes and upstreams, access control and rate limits (including the country database), the addition and removal of listeners, certificates, and so on are switched, and connections accepted after the switch use the new configuration. An open connection finishes its requests with the configuration it was accepted with and is then closed; requests are not refused. For a configuration that is rejected (one with errors, a difference in setting keys that cannot change while running, an upstream engine that is not running, a listener that cannot bind), nothing is changed.
- Logs are written to standard error as one JSON object per line. A request log has the request ID, the method, Host, and path (the query is not included), the response, the generation of the rules that decided, and the ID, severity, and anomaly score of the matched rules. The request ID is also put into `X-Request-ID` of the request sent to the upstream and of the response to the client (a value sent by the client is replaced). A log that cannot be written is discarded and counted, and the request is not stopped. If configured, the same lines are also written to files in a directory (rotated by size and count and, if configured, synced to disk at a fixed interval; a line that could not be written to the file is written to standard error and counted). For each route, you can choose between refusing the request with 503 when the log cannot be kept (`required`) and keeping only the security logs, such as requests decided by rules (`security`).
- If a monitoring listener is placed on a loopback address in the configuration, it responds to `/healthz`, `/readyz`, and `/metrics` (Prometheus text format). The proxy notifies systemd (`Type=notify`) of readiness and stopping.
- It does not run as root. Start and all commands are refused if any of the user IDs is 0.
- SIGTERM and SIGINT stop accepting new connections and requests, process in-flight requests until the timeout, and then stop the inspector processes and exit.

### Access Control and Rate Limits (Implemented)

This is the mechanism of access control and rate limits that refuses requests before the route is chosen. It does not mean the WAF is complete. For the details of setting keys and counting, see "Access Control and Rate Limits" in the [operator reference](../../operations/operator-reference.md).

- It is defined by the top-level `access`, `rate_limit`, `host_policies`, and `geo` of the configuration (when the managed configuration is used, everything except `geo` is placed in a version of the managed configuration). It applies to every request that passes the header checks (excluding ACME challenges, the monitoring listener, and, when the managed configuration is used, the admin route). It also applies to requests that match a bypass route and to the listener that redirects to https. The values are switched by a reload with SIGHUP or `reload` on the control socket.
- `access` allows and denies by the network of the client address and by country. The `access` of each route can also take a country list. The response to a refusal is 403.
- The country is determined from a database in MaxMind DB format provided by the operator. The database is not bundled and is not fetched. Private addresses and addresses that are not in the database are treated as `UNKNOWN`.
- `rate_limit` limits the request rate for each client. IPv4 is counted per address and IPv6 per /64. The number of tracked clients has a limit, and when it is exceeded, the oldest clients are dropped from counting. The response to a client that exceeds the limit is 429 with `Retry-After`.
- `host_policies` (host policies) is a setting applied to requests whose Host is that host, in place of the global `access` and `rate_limit`. For each of access control and rate limits, you can choose to inherit the global setting, apply the setting of this host, or not use it. The rules for comparing hosts are the same as for routes. A request whose Host cannot be read is treated as one that may match any host: it is refused unless it passes the `access` of the global setting and of every host policy, and rate limits are counted by each counter. Up to 64 host policies can be written, and up to 1024 hosts in total.
- The client address is determined using only the value received from a peer that is trusted for `X-Forwarded-For` (`trusted_proxies` in the configuration).

### Admin Process (Implemented)

This is a process separate from the proxy that provides the admin API and the admin screens. It does not mean the WAF is complete. For details, see the [admin reference](../../operations/admin-reference.md).

- It runs with the `admin` command of the same executable. It runs as the same OS user as the proxy and listens for plain HTTP connections on a loopback address. For use from outside, go through a route of the proxy's TLS listener (when the managed configuration is used, the admin route written in `admin.route` of the configuration file).
- It has users, roles (`viewer`, `operator`, `owner`), sessions, API tokens, password changes, MFA (TOTP), a limit on login attempts, and an audit log. Users, API tokens, and history are stored in files.
- It can list rule generations, import them (with a trial), choose them, request the running proxy to switch, roll back to the previous generation, and remove them. Choosing, requesting a switch, and rolling back are done for each engine. It keeps a switch history.
- It can list the versions of the managed configuration, check them, save and apply them, apply by name, roll back to the previous version, and remove them. It keeps a configuration history (see "Managed Configuration (Implemented)" below).
- Requests to the proxy go through a Unix domain socket (the control socket). On this socket, the proxy responds only to status queries, requests to switch generations (the engine to switch is specified), and requests to reload with a managed configuration version specified.
- Log files can be searched by time, type, class, status, rule, request ID, client, generation, and engine.
- The admin screens are static files built into the executable ([`proxy/admin-ui/`](../../../proxy/admin-ui/)) that the admin process serves. For the structure of the screens, see "Admin Screens" in the [admin reference](../../operations/admin-reference.md). The screens support Japanese and English.

### Managed Configuration (Implemented)

This is a mechanism that separates part of the configuration from the configuration file and changes it from the admin screens and the admin API. It does not mean the WAF is complete. For setting keys, commands, and procedures, see "Managed Configuration" in the [operator reference](../../operations/operator-reference.md). For the admin API and the screens, see "Managed Configuration Operations" and "Admin Screens" in the [admin reference](../../operations/admin-reference.md).

- It is used when `managed` is written in the configuration file. If it is not written, the proxy runs with the configuration file alone. When you switch whether to use it, restart the proxy and the admin process.
- Sites and certificates, upstreams, routes, the default upstream, global access control and rate limits, and host policies are saved as versions in the managed store (the directory of `managed.dir` in the configuration). The name of a version is the SHA-256 of its content, and the content of a saved version does not change. Certificate chain, private key, and CA files are also saved with the SHA-256 of their content as the name. A configuration file that has `managed` cannot have the setting keys that belong to a version.
- The proxy reads the selected version of the managed store together with the configuration file at start, when `config check` runs, and when it receives SIGHUP. The proxy does not write to the managed store.
- The admin process checks and saves a version made from a draft in the admin screens, and has the proxy apply it through `reload` on the control socket. The managed store selects the version only after the proxy has switched its configuration to it; a version that the proxy refused is not selected. Applying does not stop the proxy.
- When the managed configuration is used, the entrance to the admin screens is the admin route written in `admin.route` of the configuration file, which the proxy makes by itself. The global settings and the host policies are not applied to it, and it is protected by the network list of `admin.route.access`.
- The `managed` command (`import`, `activate`, `list`, `remove`) can create, select, list, and remove versions. `acme renew` writes the certificates of ACME sites to the managed store.

### Records Shipper (Implemented)

This is a process separate from the proxy that reads the proxy's log files and ships the lines to a DB table. It does not mean the WAF is complete. For details, see "Records Shipper" in the [operator reference](../../operations/operator-reference.md).

- The Rust executable [`records-ship/`](../../../records-ship/). It reads the same configuration file as the proxy and runs as the same OS user. It does not read the versions of the managed configuration. The libraries that connect to the DB (`tokio-postgres` for PostgreSQL and `mysql_async` for MySQL) are included only in this executable, and not in the proxy executable, which receives external requests. The DB password is placed in a file separate from the configuration file, and only the records shipper reads it.
- The destination is PostgreSQL or MySQL, chosen in the configuration. The table is created if it does not exist. TLS is used by default to connect to the DB, and the certificate and the host name are validated.
- It tracks the log file by inode and creation time, and writes the lines and the shipped position in one transaction. The hash of a line is made UNIQUE so that a line sent twice becomes one. While it cannot connect to the DB, it waits, and when the connection returns, it continues from where it stopped.
- The proxy reads the file of the position that the records shipper writes to estimate the lag, and for `required` routes it refuses requests before unshipped logs are deleted by rotation.
- Old rows are deleted after the configured number of days.

### Not Implemented or Not Decided

Not implemented:

- Parts of HTTP receiving and forwarding outside the scope above (HTTP/3, plain HTTP/2, HTTP/2 to the upstream, request trailers, relaying of 1xx responses (except the 101 of WebSocket), PROXY protocol, response caching). The supported scope is OV-05
- Inspection of XML bodies, of JSON types other than the forms above (such as `text/json`), and of bodies with a Content-Encoding other than `gzip` (AR-09)
- Response inspection (OV-04)
- Editing the configuration file itself through the admin API or the admin screens (what the admin screens can edit is the managed configuration; the configuration file is only displayed). The admin process and the records shipper changing the values of their own configuration while running (the admin process reloads the configuration file at each validation and change of the managed configuration, but it keeps using the values such as `admin` that it had at start). Replacing the executable without dropping connections
- Issuing the ACME certificate of a version of the managed configuration before that version is applied. If you add an ACME site, or apply a version whose hosts were changed, and the managed store has no certificate for that combination of hosts, the hosts of that site cannot be reached by TLS until you issue one with `acme renew`
- Handling the TLS private key in a process separate from the proxy (AR-04)
- Signed audit logs and tracing. Storing users, API tokens, and history anywhere other than files. Storing logs anywhere other than PostgreSQL and MySQL. Searching logs from the DB through the admin API and the admin screens (DP-10, OV-07)
- Built executables for environments other than Linux x86_64
- Running the inspector processes and the records shipper as different OS users or as different services (AR-04)

Not decided:

- Adoption of the candidate structure as a whole. In AR-01, only for the initial implementation of the inspection kernel, a structure of a Rust library and a Go inspector process running as a separate process was adopted. The comparison with libcoraza is not finished.
- The open points of each document, such as the communication method, the responsibilities of the supervisor, the restart conditions, and body handling, remain undecided as a whole. The current implementation of the inspection kernel does not decide them. For example, refusal by body type is a refusal rule of the initial implementation of the inspection kernel and does not decide AR-09. The refusal rules, response status codes, limits, and timeouts of HTTP/HTTPS receiving and forwarding are also rules of this implementation and do not decide AR-06, AR-07, AR-16, AR-18, or OV-05. The implementations of the admin process, the admin API, the admin screens, the log files, the records shipper, access control and rate limits, and the managed configuration also do not decide OV-03, OV-07, AR-05, or DP-10.
- The safety of the whole has not been evaluated.

## Assumptions, Candidates and Open Points

This set of documents distinguishes content by the following categories.

| Category | Meaning |
|---|---|
| Assumption | A direction given for the project. If it is changed, it is decided again |
| Candidate | A strong proposal that has not gone through verification and an adoption decision |
| Undecided | Something whose candidates have not been narrowed down, or whose decision is on hold |
| Implemented | Only the scope of the inspection kernel, HTTP/HTTPS receiving and forwarding, access control and rate limits, the admin process, the managed configuration, and the records shipper (the sections of "Current Status"). Nothing else applies |

### Assumptions

- The main implementation language is Rust.
- The product is derived from tukuyomi and centered on WAF functionality. Functions other than the WAF are removed after the criteria (OV-01) are decided.
- As design principles, it sets privilege separation, distrust of all input, minimalism, deterministic resources, and structural security (see [design principles and constraints](design-principles.md)).
- For the admin UI, reuse and improvement of the admin UI of tukuyomi are studied. The scope and the base version are undecided (OV-03).
- Code is organized by responsibility, type, and owner, and files are not split excessively. The concrete structure of modules and files is decided as needed at implementation time.

### Candidates

- The comparison is made on the proposal to use Coraza as the inspection engine. The proposal to build an inspection engine from scratch is not a candidate.
- The first candidate for the connection method is a structure that splits the system into a Rust proxy and a small Go inspector process that uses the Coraza Go API directly (AR-01). Only for the initial implementation of the inspection kernel, a Rust library and a Go inspector process running as a separate process were implemented from this structure. The Rust proxy that handles HTTP was implemented for the scope of "HTTP/HTTPS Receiving and Forwarding (Implemented)" above.
- A structure in which the Rust proxy calls libcoraza (the C library of Coraza) is kept for comparison (AR-01).

Which structure is faster, simpler, or safer is not decided before verification. For the points of comparison, see the [architecture overview](architecture.md).

## External Elements

| Element | Role | Handling |
|---|---|---|
| Client | Sends HTTP requests to the application to be protected | Everything it sends is treated as untrusted input |
| Upstream application | The protected target to which tukuyomi-core forwards requests | Responses are also treated as input. Response inspection is OV-04 |
| Operator | Manages settings and rules, and checks logs | The means and scope of administration are OV-03 and AR-05. For the current implementation, see "Current Status" |
| Rules and settings | Determine the content of inspection | Rules and settings are also validated as input. The available functions and privileges are DP-07 |

## Scope Under Study

The following table shows the subjects of study. It does not decide whether features are kept or removed (OV-01).

| Area | Content | Status |
|---|---|---|
| HTTP receiving and forwarding | Accepting connections, interpreting HTTP, forwarding to the upstream | In the candidate structure, the Rust proxy is responsible. For the implemented scope, see "Current Status". The supported HTTP versions are OV-05 |
| Request inspection | Inspecting connection information, the URI, headers, and body, and deciding the result | Implemented by the inspection kernel in a limited scope (see "Current Status"). The overall scope is still under design consideration |
| Response inspection | Inspecting response headers and the response body | Undecided (OV-04) |
| Rule and configuration management | Validating and applying rules, and switching generations | Importing rule sets with a trial, and choosing and switching generations for each engine, are implemented through commands and signals, the admin API, and the admin screens. Editing and applying part of the configuration (the managed configuration) through the admin API and the admin screens is also implemented (see "Current Status"). Editing the configuration file itself is not implemented. The whole is still under design consideration (AR-11) |
| Logs | Logs of detection, blocking, the reason inspection was not done, uninspectable requests, and upstream failures | A mechanism that writes request logs (JSON) to standard error and to files, search through the admin API and the admin screens, and metrics for monitoring are implemented. The policy on the storage method, period, and capacity is undecided (DP-10, OV-07) |
| Admin UI | Operating and displaying settings, rules, and logs | The admin process and the admin screens are implemented (see "Current Status"). The scope of reuse and improvement and the base version are undecided (OV-03). The whole of authentication and how privileges are divided is AR-05 |
| Access control and rate limits | Global and per-host allow and deny by IP address and country, and per-client rate limits | Implemented (see "Current Status"). The whole is still under design consideration |
| Operation | Start, stop, restart, confirming readiness, and monitoring | The inspection kernel implements starting, stopping, and restarting the inspector processes and confirming their readiness. Stopping the proxy, validating the configuration, switching generations, reloading certificates, the monitoring listener and metrics, and notifying systemd are also implemented. The whole is still under design consideration (AR-03, AR-12, AR-17) |

## Terms

| Term | Meaning in this set of documents |
|---|---|
| Rust proxy | In the candidate structure, the Rust process responsible for receiving, interpreting, and forwarding HTTP, for the configuration, and for storing logs |
| Inspection kernel | The part responsible for inspecting requests. It consists of a Rust library (`kernel/`) and a Go inspector process (`inspector/`). For ModSecurity generations, the library starts the ModSecurity inspector process (`inspector-modsecurity/`) |
| Inspector process | In the candidate structure, the Go process responsible only for building rules with Coraza and inspecting |
| WAF instance | The unit that does the inspecting, built from the rules and settings of one generation |
| Transaction | The unit in which the inspection engine inspects one request (and the response too, if responses are inspected). It processes the phases needed for the adopted inspection scope in order, and at the end runs the logging phase (phase 5) and Close. Which phases are called for each route is AR-10 |
| Phase | A stage of evaluation by the inspection engine. The order is request headers, request body, response headers, response body, and logging. After an early block, or in a structure that does not inspect responses, intermediate phases may not be called, so a transaction does not always go through all the phases |
| Rule generation | The combination of rules and settings that is in effect at a point in time. Each update makes a new generation. One is chosen for each engine |
| Managed configuration | A mechanism that separates part of the configuration (sites and certificates, upstreams, routes, the default upstream, global access control and rate limits, and host policies) from the configuration file and changes it from the admin screens and the admin API. For the implemented scope, see "Managed Configuration (Implemented)" under "Current Status" |
| Managed store | The directory (`managed.dir` in the configuration) that holds the versions of the managed configuration and the files that the versions use, such as certificates |
| Version (of the managed configuration) | The content of the managed configuration at a point in time. The name is the SHA-256 of the content, and once a version is saved, its content does not change. It is a different thing from a rule generation |
| Host policy | A setting (`host_policies`) applied to requests whose Host is that host, in place of the global access control and rate limits |
| Traffic that requires inspection | Traffic that the settings define as not to be forwarded without inspection. The definition is DP-02 |
| Uninspectable | A state in which inspection cannot be completed for a technical reason such as a stop, a disconnection, a timeout, or an exceeded limit. It is handled separately from the case where inspection is intentionally not done |
| Explicit bypass | A route (bypass route) where inspection is intentionally not done, by setting. Whether to keep it is DP-01 |
| On / DetectionOnly / Off | The modes of a Coraza WAF instance. On executes the disruptive actions of rules (deny, drop, redirect, and so on). DetectionOnly evaluates rules but does not execute disruptive actions. Whether logs remain depends on the rules and the audit log settings (DP-10). Off does not evaluate rules. A rule match (detection) and the execution of a disruptive action (blocking) are handled separately |
| fail-closed | Handling in which traffic that requires inspection is not forwarded when it is uninspectable. For the scope of application, see [design principles and constraints](design-principles.md) |

## Open Points

Open points are given IDs that do not overlap across documents. This document uses OV-. Those about the structure go under AR- ([architecture overview](architecture.md)), and those about principles and policies go under DP- ([design principles and constraints](design-principles.md)).

| ID | Item | Current handling | Affected scope |
|---|---|---|---|
| OV-01 | Criteria for the features to keep and remove | Undecided. Until the criteria are decided, no feature is decided to be kept or removed | Functional requirements, AR-07, DP-01, DP-07, DP-08 |
| OV-02 | The version of tukuyomi to port from | Undecided | Precedents for porting, checking upstream behavior |
| OV-03 | Scope of reuse and improvement of the admin UI, and the base version | Studying reuse and improvement is an assumption. The scope and the version are undecided | UI design, AR-05, DP-10 |
| OV-04 | Whether to inspect responses, and if so, the scope | Undecided | AR-08, AR-10, the "Returning the response" column of "States × Operations" |
| OV-05 | Supported HTTP versions and kinds of communication (HTTP/1.1, HTTP/2, HTTP/3, Upgrade, incremental sending, and so on) | Undecided | AR-06, AR-08 |
| OV-06 | Distribution form (including whether a single executable is required), supported environments, and deployment structure | Undecided | AR-01, AR-03, AR-04, AR-13, AR-17, DP-09 |
| OV-07 | Storage method of settings, rules, and logs | Undecided | AR-05, AR-11, DP-10 |

## Related Documents

- [Architecture Overview](architecture.md)
- [Design Principles and Constraints](design-principles.md)
- [Documentation Index](../../README.md)
