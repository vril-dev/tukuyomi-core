# Chapter 1. Introduction to tukuyomi core

This chapter explains what kind of product tukuyomi core is. It looks at the processes that make it up, what each of them is responsible for, and what each of them does not have. It also lists what 0.2.1 implements, what it does not implement, and what is not decided.

Concrete settings and commands come from Chapter 2 on. The goal here is to get the overall picture and the main terms.

## 1.1 What tukuyomi core Is

tukuyomi core is an HTTP/HTTPS reverse proxy with a built-in WAF. It inspects incoming requests with Coraza or ModSecurity v3 and forwards them to upstreams. Inspection uses rule sets such as the OWASP Core Rule Set (CRS).

Main features:

- Receiving HTTP/1.1 and HTTP/2 (over TLS) requests and forwarding them to upstreams
- Request inspection with Coraza or ModSecurity v3 (managing rule set generations, and a detect-only mode)
- Access control by IP address and country, and rate limiting (global and per host)
- Certificate issuance and renewal with ACME (HTTP-01)
- Admin API and admin screens (editing the managed configuration and applying it without stopping the proxy, operations on rule set generations, log search, and an audit log)
- Log files, and log shipping to PostgreSQL / MySQL

It has been tested only on Linux x86_64 with Landlock enabled. The inspector processes use Landlock to restrict their own privileges. The product as a whole has not had a security review yet.

## 1.2 Components

tukuyomi core runs not as one process but as several processes, each with its own role. All of them come in the same release tarball.

| Component | Role | Boundary |
|---|---|---|
| Proxy (`tukuyomi-proxy`) | Receives and forwards HTTP/HTTPS requests, and starts, stops, and restarts the inspector processes | The proxy process does not connect to a DB, and does not write to the managed store |
| Inspector process (Coraza, `tukuyomi-inspector`) | Inspects requests with Coraza | Has no listening port |
| Inspector process (ModSecurity v3, `tukuyomi-inspector-modsecurity`) | Inspects requests with ModSecurity v3. Needed only when you use ModSecurity | Has no listening port |
| Admin process (`tukuyomi-proxy admin`) | Provides the admin API and the admin screens, and works with rule set generations and the managed configuration | Listens on a loopback address. It is reached from outside through the proxy |
| Records shipper (`tukuyomi-records-ship`) | Ships the lines of the proxy's log files to a PostgreSQL or MySQL table. Needed only when you ship logs to a DB | Has no listening port |

### Proxy

The proxy is the main part: it receives requests and forwards them to upstreams. It has 1 to 8 listeners, of three kinds: plain HTTP, TLS (1.2 and 1.3), and redirect to https. TLS listeners can also handle HTTP/2. The proxy connects to upstreams with HTTP/1.1.

The proxy embeds a part called the inspection kernel (a Rust library), which starts, stops, and restarts the inspector processes. For each request, the inspection kernel asks an inspector process to inspect it and receives one of three results: allow, block, or uninspectable.

Besides the proxy, the same executable provides the following commands, which are used from Chapter 2 on.

- The rules store commands (`rules`)
- The certificate command (`acme renew`)
- The configuration check (`config check`)
- The managed configuration commands (`managed`)
- The admin process (`admin`)

### Inspector Processes

An inspector process only inspects requests. The proxy starts it as a child process, and the two communicate over a pair of Unix domain sockets that the inspector process inherits from the proxy. It has no listening port.

There are two inspection engines. The Coraza inspector process is written in Go. The ModSecurity v3 inspector process is written in Rust and C++, and statically links libmodsecurity 3.0.17 into the executable.

The ModSecurity inspector process is needed only when you use a ModSecurity generation or set `modsecurity` as the default engine or an upstream engine. On hosts that do not use it, you can leave it out.

At start, after reading the rule set generation, an inspector process restricts itself with Landlock so that it cannot reach files outside its temporary directory, and drops its capabilities. Chapter 3 explains what this restriction covers and what it cannot restrict.

### Admin Process

The admin process runs separately from the proxy and provides the admin API and the admin screens built into the executable. It listens for plain HTTP connections on a loopback address, and is reached from outside through a TLS listener of the proxy.

The admin process lists, imports, and chooses rule set generations, rolls back to the previous generation, saves and applies managed configuration versions, and so on. It sends requests to the running proxy over a Unix domain socket (the control socket). On this socket, the proxy responds to only three kinds of request: status queries, generation switches, and reloads with a specified version of the managed configuration.

The admin process also holds users, roles (`viewer`, `operator`, `owner`), sessions, API tokens, MFA (TOTP), and the audit log. Chapter 5 explains them in detail.

### Records Shipper

The records shipper reads the log files that the proxy writes and ships their lines to a DB table. The libraries that connect to the DB and the DB password exist only in this process; the proxy, which receives external requests, has neither. When the records shipper cannot connect to the DB, it waits, and once the connection returns, it continues from where it stopped. Chapter 7 explains it in detail.

### Process Boundaries

All the processes run as the same OS user as the proxy, and none of them runs as root. The start and every command are refused if any of the user IDs is 0.

Running the inspector processes and the records shipper as different OS users or as different services is not implemented in 0.2.1, so the processes are separate but share one OS user. Where each process keeps its files, and with what permissions, is decided on this basis (see Chapter 3).

## 1.3 How a Request Is Handled

A request from a client is handled in the following order. Only the main stages are shown here; for the exact order, see "Order of Request Checks" in Appendix A (Operator Reference).

1. **Header checks**: before HTTP parsing, the header section is strictly checked for its format and limits. A request that breaks them is refused with a fixed response that has no body (400, 408, 413, 414, 415, 417, 431), and nothing is sent to the upstream.
2. **Access control and rate limits**: a request refused by access control by IP address and country gets 403, and a request over the rate limit gets 429. Both checks come before the route is chosen. If there are host policies (`host_policies`), they apply in place of the global settings (they can also inherit the global settings).
3. **Route selection**: the upstream is chosen by the `Host` and path of the request. If no route matches and there is no default upstream, the response is 404.
4. **Inspection**: on a route that is inspected, the inspector process of the engine that the destination upstream uses inspects the URI, the headers, and the start of the request body. The result is one of three: allow, block, or uninspectable. A request that matches a bypass route is forwarded without inspection.
5. **Forwarding**: allowed requests, and requests that matched a rule in detect-only mode, are forwarded to the upstream. A blocked request is not forwarded, and the proxy responds with the status code of the rule.

Keep the following in mind when you run tukuyomi core:

- **A request that cannot be inspected is not allowed**: when inspection fails for a technical reason, such as an unavailable inspector process or a full inspection queue, the proxy responds with 503 and does not forward the request. Not inspecting on purpose, as on a bypass route, is handled separately from failing to inspect.
- **Only the start of the body is inspected**: the proxy inspects the body up to the configured number of bytes (at most 1 MiB), and after allowing the request, passes the rest to the upstream without inspection. The body types that can be inspected are also limited. For details, see "Request Body Limits and Inspected Length" and "Body Types" in Appendix A (Operator Reference).
- **Responses are not inspected**: 0.2.1 has no feature that inspects what comes back from the upstream.
- **Upstream failures get 502**: for example, when the proxy cannot connect to the upstream, the response is invalid, or the upstream times out.

## 1.4 The Configuration File and the Processes

The proxy, the admin process, and the records shipper read the same configuration file. The file is one JSON object in UTF-8, up to 256 KiB. The top-level setting keys are as follows.

```text
{"proxy": {..}, "forward": {..}, "kernel": {..}, "rules": {"store": {..}}, "acme": {..}, "status": {..}, "records": {..}, "access": {..}, "rate_limit": {..}, "host_policies": [..], "geo": {..}, "admin": {..}, "managed": {..}}
```

Of these, `acme`, `status`, `records`, `access`, `rate_limit`, `host_policies`, `geo`, `admin`, and `managed` are optional. Every setting key must be written unless it is defined as optional. **No value has a default.** This is why the first configuration file is long (see Chapter 2).

Keep the following in mind about the configuration file:

- An unknown setting key, a duplicate of the same setting key, and a value of the wrong type are rejected. The ranges of values and the relations between values are checked at start. The `config check` command runs the same checks before start.
- The three processes read the same configuration file, and none of them accepts an unknown setting key, so write a new setting key only after replacing all the executables with the same build (see Chapter 9).
- `admin` contains setting keys that the proxy uses (`listen`, `control`, `route`) and setting keys that the admin process uses. For the other setting keys, the proxy only checks the values.
- The records shipper does not read the versions of the managed configuration.

For all the setting keys, see "Overall Structure" and "Example" under "Configuration File" in Appendix A (Operator Reference).

## 1.5 Rule Set Generations and the Managed Configuration

Two mechanisms come up throughout this book. Their names are similar, so this section tells them apart first.

### Rule Set Generations

A rule set generation is the whole rule set that `rules import` creates. It represents the combination of rules and settings in effect at a point in time, and is identified by the fingerprint of its content (the SHA-256 of the manifest). A generation never changes after it is created; each update makes a new generation.

- A generation has the engine that inspects with it (Coraza or ModSecurity) and a mode. The mode is either block mode or detect-only mode, which lets a request that matches a rule through and records it in the log. A generation can also have bypass routes (Host and path).
- An import starts one inspector process, which inspects fixed requests (the trial), and only a rule set that passes becomes a generation. An imported generation is not used until `rules activate` chooses it; one generation is chosen for each engine.
- Choosing a generation with the command does not switch the running proxy. The proxy switches when it receives SIGUSR1, and it keeps running during the switch. The admin screens and the admin API choose the generation and then ask the proxy to switch over the control socket.
- The engine that inspects can be chosen for each upstream (the `engine` of the upstream; if omitted, the default engine).

The CRS is not bundled. It is fetched with a script that pins the version and the checksum (see Chapter 2). Chapter 4 explains how generations are handled.

### Managed Configuration

The managed configuration moves part of the configuration out of the configuration file, so that it can be changed from the admin screens and the admin API. It covers sites and certificates, upstreams, routes, the default upstream, global access control and rate limits, and host policies. These are saved as versions in the managed store (the directory set in `managed.dir` in the configuration).

- The name of a version is the SHA-256 of its content, and the content of a saved version does not change. A version is not the same thing as a rule set generation.
- From the admin screens and the admin API, you can check and save a version and apply it to the running proxy without stopping it. Saved versions remain, so you can go back to a previous version.
- The managed configuration is used when `managed` is written in the configuration file; without it, the proxy runs with the configuration file alone. Turning it on or off requires restarting the proxy and the admin process. With `managed`, some setting keys can no longer be written in the configuration file.

To decide whether to use the managed configuration or run with the configuration file alone, see Chapter 5 and "Whether to Use the Managed Configuration" in Appendix A (Operator Reference).

## 1.6 Relation to Upstream tukuyomi

tukuyomi core is derived from tukuyomi (the tukuyomi WAF) and aims to be a product focused on the WAF. The main implementation language is Rust.

However, the documentation states that the criteria for which tukuyomi features to keep and which to remove are undecided. Until the criteria are decided, no decision is made to keep or remove any individual feature. The version of tukuyomi to port from is also undecided.

To find out whether a feature or setting of tukuyomi exists in tukuyomi core, check section 1.7 and "Current Status" in System Overview (`docs/detailed-design/00_overview/system-overview.md`). The product code covers only the scope listed in section 1.7.

## 1.7 What Is Implemented and What Is Not

This section summarizes what 0.2.1 implements, following the items of "Current Status" in System Overview. For each implemented part, the documentation notes that it "does not mean the WAF is complete".

### Implemented

| Item | Content |
|---|---|
| Request inspection | The inspection kernel inspects the URI, the headers, and the start of the body of each received request. The body types that can be inspected are limited |
| Rule generations | Importing rule sets, choosing and switching generations for each engine, choosing the inspection engine for each upstream, detect-only mode, and bypass routes. The admin API and the admin screens can also import, choose, switch, and roll back |
| HTTP/HTTPS receiving and forwarding | Listeners for plain HTTP, TLS, and redirect to https. TLS connections to each upstream, server selection by weight, marking failing servers as failed, and forwarding of WebSocket (frames are not inspected) |
| Access control and rate limits | Global allow and deny by IP address and country, and per-client rate limits. Both can be set differently for each host with host policies. The country database is not bundled; the operator provides it |
| Managed configuration | Sites and certificates, upstreams, routes, and so on are saved as versions. They are changed from the admin screens and the admin API and applied without stopping the proxy |
| Logs | One JSON object per line is written to standard error and, if configured, also to log files. The records shipper can ship the lines to PostgreSQL or MySQL. The admin API and the admin screens can search the log files |
| Monitoring | `/healthz`, `/readyz`, and `/metrics` (Prometheus text format) on the monitoring listener, and notifications to systemd (`Type=notify`) |
| Certificates | Placed as files, or issued and renewed with `acme renew` (ACME HTTP-01). Reloaded with SIGUSR2 |
| Admin process | Admin API and admin screens (Japanese and English). Users, roles, sessions, API tokens, MFA (TOTP), a limit on login attempts, and an audit log |
| Privilege restriction on the OS | Does not run as root. At start, an inspector process restricts itself with Landlock and by dropping capabilities |
| Distribution | Since 0.1.0, the four executables for Linux x86_64 have been bundled into one tarball and distributed through GitHub releases. The product can also be built from source |

For the changes since 0.1.0, see Appendix C (Release Notes).

### Not Implemented

- Parts of HTTP receiving and forwarding outside the scope above (HTTP/3, plain HTTP/2, HTTP/2 to the upstream, request trailers, relaying of 1xx responses (except the 101 of WebSocket), PROXY protocol, response caching)
- Inspection of the following bodies: XML bodies, JSON types other than `application/json` and `application/<name>+json` (such as `text/json`), and bodies with a Content-Encoding other than `gzip`
- Response inspection
- Editing the configuration file itself through the admin API or the admin screens. What the admin screens can edit is the managed configuration; the configuration file is only displayed
- The admin process and the records shipper changing the values of their own configuration while running
- Replacing the executables without dropping connections
- Issuing the ACME certificate for a managed configuration version before that version is applied
- Handling the TLS private key in a process separate from the proxy
- Signed audit logs and tracing
- Storing users, API tokens, and history anywhere other than files
- Storing logs anywhere other than PostgreSQL and MySQL. Searching logs from the DB through the admin API and the admin screens
- Built executables for environments other than Linux x86_64
- Running the inspector processes and the records shipper as different OS users or as different services

### Not Decided

The documentation states that these are undecided, and the 0.2.1 implementation does not settle them.

- The criteria for which features to keep and which to remove. The version of tukuyomi to port from
- Whether to inspect responses, and if so, the scope
- The supported HTTP versions and kinds of communication
- How far to reuse and improve the admin screens, and which version to base them on
- The distribution form, the supported environments, and the deployment structure
- How settings, rules, and logs are stored. The policy on how long logs are kept and how much space they use
- The security of the product as a whole (it has not been evaluated)

The current implementation runs on a single Linux host, and a systemd example is provided (see Chapter 3).

### Status of the Documentation

Of the documentation in the repository, the documents in `docs/detailed-design/` are initial drafts that record goals, assumptions, candidates, and open points. Content marked "candidate" or "proposal" is not an adopted decision. The implemented scope is only what "Current Status" in System Overview shows, and this book also covers only that implemented scope.

## 1.8 Bridge to the Next Chapter

This chapter has given the overall picture of tukuyomi core. At its center is the proxy, which passes each request to an inspector process for inspection and forwards it to an upstream. The admin process and the records shipper are separate processes. Operations center on two mechanisms: rule set generations and the managed configuration.

In Chapter 2, you start tukuyomi core by hand on a single Linux host before building any production setup, and use the logs to confirm that an ordinary request passes and that an SQL injection request is blocked. If you have not used tukuyomi core before, working through Chapter 2 before going on to Chapter 3 helps you understand what the setting keys mean.
