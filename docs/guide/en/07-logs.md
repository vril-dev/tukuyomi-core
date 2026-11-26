# Chapter 7. Logs and the Records Shipper

This chapter covers the format of the logs that tukuyomi core writes, the log files (`records`), what happens when logs cannot be kept, searching the logs in the admin screens, and the records shipper, which sends the logs to PostgreSQL or MySQL.

How much logging you set up depends on how you use the product, so read the chapter in order and stop when you have what you need.

## 7.1 Overview of the Logs

First, look at where logs are kept. Logs can be kept in up to three places.

- **Standard error (the journal under systemd)**: always written, one JSON object per line.
- **Log files**: if the configuration has `records`, the same lines are also written to files. The admin process reads these files to answer log searches in the admin screens and the admin API (see section 7.6). The files rotate by size and count, so the oldest ones are removed first. The exception is the lines written at start before the log files are opened (such as the `start: configuration accepted` and `start: rules …` lines), which go only to standard error.
- **Records shipper**: if the configuration has `records.ship`, a separate process sends the lines in the files to PostgreSQL or MySQL. `retention_days` sets how many days the DB keeps them (see section 7.7).

If you omit `records`, logs go only to standard error, and you cannot search them in the admin screens or the admin API. Decide how many of these places to use.

Each log has a `type` that shows its kind: one of `request`, `connection`, `tunnel`, `line`, `audit`, and `dropped`. Every log starts with `ts` (the time it was recorded) and `type`. `ts` is UTC in RFC 3339 format with milliseconds (example: `2026-10-27T03:53:27.123Z`). A field with no value is left out rather than set to `null`.

The output of the short-lived commands (`config check`, `rules`, `managed`, `acme`, `admin bootstrap`, `admin reset`) is not a log; it is lines of text for people to read.

## 7.2 Request Logs and Other Logs

### Request Log (`request`)

One request log is written for every request to which the proxy wrote a response, including refusals of the header section, redirects, and responses to ACME challenges. The log is written when the response has been sent (or cut off), so for a streamed response the log appears when the response ends.

```text
{"ts":"2026-10-27T03:53:27.123Z","type":"request","id":"0186af5443bddbd9-1","conn":1,"listener":0,"proto":"h1","tls":false,"client":"192.0.2.10","method":"GET","host":"example.com","path":"/q","class":"blocked","status":403,"reason":"blocked by a rule","ms":3,"mode":"block","engine":"coraza","generation":"2f3bda9b9ca7db60","rule":949110,"rules":[941100,941110],"severity":2,"score":10,"sent":0}
```

This example is the line for a `GET` request (path `/q`) from `192.0.2.10`. A Coraza generation (`engine` is `coraza`, `mode` is `block`) blocked the request with rule 949110 and returned 403.

Start with these fields.

- `id`: the request ID, the same value as the `X-Request-ID` of the response and the `X-Request-ID` sent to the upstream. Use it to match a request with its log.
- `client`, `method`, `host`, `path`: the client address, the method, the `Host`, and the part of the request target before the `?`, in that order.
- `class`, `status`, `reason`: the result of the request.
- `rule`, `rules`, `severity`, `score`: the ID of the rule that blocked the request (in detect-only mode, the ID of the rule that matched), the IDs of the other rules that matched, the severity, and the CRS anomaly score, in that order.
- `mode`, `engine`, `generation`: the mode of the generation that made the decision (`block` or `detect`), that generation's engine, and the first 16 digits of its fingerprint, in that order. A request that was not inspected (including one that a bypass route let through) has none of these three fields.
- `ms`, `sent`: the time taken in milliseconds, and the number of response body bytes sent to the client.

`class` is one of the following seven values.

- `forwarded`: the upstream's response was returned
- `blocked`: a rule blocked the request
- `rejected`: the header section or the body was refused (including refusals by access control and rate limits)
- `redirected`: the request was redirected to https
- `answered`: the proxy responded to an ACME challenge
- `failed`: the proxy could not respond because of a problem on its side (busy, unable to inspect, an upstream failure)
- `closed`: nothing was returned

A line whose `class` is `forwarded` can still record a rule match: if its `reason` is `detected by a rule`, the request matched a rule in detect-only mode and was let through. A line whose `reason` is `bypassed by a route` is a request that a bypass route let through.

In the values that come from the request (`method`, `host`, `path`), bytes outside the range 0x21 to 0x7e, as well as `"` and `\`, are replaced with `%XX` (uppercase hexadecimal). Then `method` is cut at 32 bytes, `host` at 255 bytes, and `path` at 1024 bytes.

The log does not record the query, the body, headers other than `Host` (`User-Agent`, `Cookie`, and so on), the values and variable names that matched a rule, or the `msg` of a rule. However, if a site puts secret values in the path, those values stay in the log.

For all the fields, and for the cases that each `class` covers, see "Request Log (`request`)" in Appendix A (Operator Reference).

### Other Log Lines

Besides the request log, there are the following logs.

- `connection`: written for a connection that ended without a response being written (closed before a request, a failed TLS handshake, and so on), and when an HTTP/2 connection ends.
- `tunnel`: written when a WebSocket tunnel ends.
- `line`: a log with a message about what the proxy is doing. A message is up to 512 bytes; a longer one is cut. Messages from the records shipper start with `records-ship:` (see section 7.7).
- `audit`: the audit log, which only the admin process writes. It does not go into the proxy's log file (see Chapter 5).
- `dropped`: reports how many logs could not be written and were discarded (`count`).

The first word of a `line` message shows its kind. To check start, stop, and configuration reloads, look at the following messages.

- `start:`: the startup steps (`start: the kernel is ready`, `start: listening`, and so on), and the message written when start is refused.
- `reload:`: the receipt of a request for a configuration reload or a generation switch, and its result (`reload: configuration replaced <sha256>` and so on).
- `stop:`: the reason for stopping, and the final message, which gives the result of the stop.

There are also the following messages.

- `control:`: responses to requests on the control socket
- `driver:`: restarts of the inspector process, and the start of a stop
- `notify:`: a notification to systemd could not be sent
- `conn <number>: internal fault: <reason>`: an inconsistency inside the proxy

For the list of all messages, see "Other Log Lines" in Appendix A (Operator Reference).

### When Logs Cannot Be Written

When log writing falls behind or fails, the proxy behaves as follows.

- Logs go into a queue that holds up to 1024 of them, and only one thread writes them. Request handling and stopping do not wait for writes.
- When the queue is full, the log is discarded and counted; once writing works again, one `dropped` log is written. This happens when whatever reads standard error stops reading.
- A write failure loses that log, and it is counted separately from the logs discarded because the queue was full.
- Both counts appear in `/metrics` as `tukuyomi_records_dropped_total` and `tukuyomi_record_write_errors_total`. While standard error is blocked, the proxy cannot report them in the log.
- By default (`best_effort`), requests go through even when logs cannot be kept. You can also choose, for each route, to refuse requests instead (see section 7.4).

## 7.3 Log Files (`records`)

When you write `records` in the configuration, the logs written to standard error also go to files in the directory you name (except the start lines written before the log files are opened; see section 7.1). If `records` is omitted, logs go only to standard error.

```json
"records": {
  "dir": "/var/lib/tukuyomi-core/records",
  "file_bytes": 16777216,
  "files": 8
}
```

`dir`, `file_bytes`, and `files` are required. The other setting keys you can add are `keep`, which sets how logs are kept (see section 7.4), `sync_ms`, which sets the sync interval, and `ship`, which holds the records shipper settings (see section 7.7).

### Preparing the Directory

In `dir`, write the absolute path of the directory for the log files. The proxy does not create this directory, so create it first. The directory must meet the following conditions.

- It is a directory that is not a symbolic link
- It is owned by the proxy's OS user
- It has no permissions for the group and other users

```bash
sudo install -d -m 0700 -o tukuyomi -g tukuyomi /var/lib/tukuyomi-core/records
```

The log directory cannot be the same as another directory such as the rules store, and none of these directories can be inside another (see section 3.4).

### Size and Number of Files

- `file_bytes` is the size of one file (1 MiB to 1 GiB), and `files` is the number of files to keep (2 to 64, including the one in use).
- The disk space used is at most `file_bytes × files`: with the example values, 16 MiB × 8 files, or up to 128 MiB.
- The file in use is `records.log`. Older files are `records.1.log`, `records.2.log`, and so on, and `records.<files - 1>.log` is the oldest.
- If adding a line would make the file exceed `file_bytes`, the proxy first rotates to the next file, and the oldest file is replaced and removed. No file is cut in the middle of a line.
- The proxy rotates the files itself.

### Writing and Syncing

- `records.log` is created with 0600 if it does not exist, and opened for appending. If the file cannot be opened at start, the proxy writes a `start: record file refused: <reason>` line and stops without starting the inspector processes (exit 1).
- Without `sync_ms`, the file is not synced to disk (`fsync`), so if the power goes off, lines that the OS has not yet written to disk are lost.
- With `sync_ms` (1 to 60000), the file is synced when the oldest unsynced line has waited `sync_ms`. If the power goes off, the lines after the last sync are lost.
- If a write, an `open`, or a rename fails, that line does not go into the file and is counted in `tukuyomi_record_file_errors_total`. The line still appears on standard error, and request handling does not wait for this. The first line that arrives at least 1 second after the failure reopens the file.
- When you use the records shipper, `ship.state` (how far it has sent) is placed in the same directory. The proxy only reads `ship.state`.

`records`, except `keep`, cannot change while running. To change it, restart the proxy, and also the admin process and the records shipper, which read the same configuration file (see Chapter 9).

For how files are opened, what happens when something other than the proxy moves a file, and what happens when `files` is reduced, see "Log Files (`records`)" in Appendix A (Operator Reference).

## 7.4 How Logs Are Kept

For each route, you can choose what happens when logs cannot be kept and which logs are written. There are three values.

| Value | When logs cannot be kept | Logs written |
|---|---|---|
| `best_effort` | Discards the log and counts it, and lets the request through | All |
| `required` | Refuses new requests on that route with 503 | All |
| `security` | The same as `best_effort` | Only the four kinds of requests listed below. Logs of requests let through normally are not written |

`security` writes logs for the following four kinds of requests.

- Requests that a rule decided on (blocked requests, and requests that matched in detect-only mode)
- Requests that could not be inspected
- Requests refused by the global `access` and `rate_limit` and by host policies
- Requests cut off after they were accepted and before the response

Set the value in the route's `records`. A route without it uses the global `records.keep` (`best_effort` or `required`), and if `records.keep` is not written either, the value is `best_effort`. The default upstream has no `records`, so requests that go to it use `records.keep`.

```json
{"host": "www.example.com", "upstream": "app", "records": "required"}
```

### `required`

A route with `required` accepts a request only when all three of the following hold.

1. The last write to the log file (and the sync) succeeded, and the thread that writes logs is running.
2. If you use the records shipper (`ship`), the number of bytes it has not yet sent is less than the size of `files − 2` files (`file_bytes × (files − 2)`). This condition refuses requests before unsent logs are lost to rotation, and the proxy also refuses when it cannot tell how far behind the records shipper is.
3. There is a free slot in the log queue.

A refused request gets 503 and is counted in `tukuyomi_records_refused_total`. The log of a refused request (`reason` is `records cannot be kept`) is written with `best_effort` handling: if it cannot be written, it is discarded and counted. However, when the request was refused because the records shipper is behind, that log is only counted, not written, so that logs of refused requests do not use up the room left before unsent logs are lost to rotation. The log of an accepted request, on the other hand, is not discarded even if the queue is full.

- Logs are written after the response has been sent, so even `required` does not guarantee that the log exists before the client receives the response. The logs that can be missing are those of requests already accepted when writes started to fail, and, if the power goes off, those after the last sync.
- `required` needs `records`. When you use both `ship` and `required`, set `files` to 3 or more.
- The logs of requests answered before the route is chosen and of requests answered without reading the body (the 403 and 429 of the global `access` and `rate_limit`, requests refused by the header section checks, connection logs, and so on) are written with `best_effort` handling (discarded and counted if they cannot be written), whatever the route's value.

For the exact rules of the three conditions for accepting a request, and the list of requests logged with `best_effort` handling, see "How Logs Are Kept (`keep` and the `records` of a Route)" in Appendix A (Operator Reference).

## 7.5 Users Who Can Read the Logs

The logs contain the client address and the path. Who can read them depends on where they are kept.

- **Journal**: root and, on Ubuntu, members of the `adm` and `systemd-journal` groups can read it. Keep as few OS users in these groups as possible. The journald settings decide how long the journal is kept and how much space it uses (see section 3.5).
- **Log files (`records`)**: the files are 0600, in a 0700 directory, so only the proxy's OS user and root can read them. The admin process reads them as that same OS user and shows them to users of the admin screens and the admin API.
- **Admin API**: the log search (`GET /api/records`) is open to the viewer role and above, so keep this in mind when you decide who gets the viewer role (see Chapter 5).
- **DB tables**: when you use the records shipper, the same logs also go into the DB tables. Keep the DB users who can read them to a minimum as well.

## 7.6 Access Log in the Admin Screens

When you write `records`, you can search the logs on the Access log screen in the Logs menu of the admin screens (viewer or above), or with `GET /api/records` in the admin API. The admin process reads the files in `records.dir` from the newest line and returns the lines that match the conditions. The Logs menu also has the Audit log screen (operator or above; for the list of screens, see Chapter 5).

- You can search by time (`from`, `to`), `type`, `class`, `status`, `rule`, `id` (the request ID), `client`, `generation`, and `engine` (the engine that inspected the request).
- Lines are returned as the JSON that was written, so text that came from a request (such as `path`) is shown in its `%XX` form. If you select "Also show the URL-decoded text" under "All fields" on the screen, the decoded text is shown as well.
- One response returns up to 500 lines and reads up to 256 MiB. If either limit is reached while logs remain, the response includes the position to continue from (`next`). On the screen, "Next" on the last page loads the older logs that follow.
- When a failure response has no `error` message (a 403 for a request that a proxy in front blocked with a rule, a 502 when the proxy could not connect to the admin process, and so on), the screen shows the request ID from the response's `X-Request-ID` after the failure message. Search the Access log screen with that ID to find the rule that blocked the request and other details. The ID is shown only when it has the form that the proxy and the admin process assign.
- The audit log does not go into the proxy's log files, so a search with `type=audit` does not find it. Read it on the Audit log screen (or with `GET /api/audit`).
- If the configuration has no `records`, this API returns 404 (`records are not configured`). If the log directory fails the owner and permission check, it returns 503.
- Searching the logs in the DB from the admin API or the admin screens is not implemented.

For the condition format, how to continue reading, and the failure responses, see "Reading Logs" in Appendix B (Admin Reference).

## 7.7 Records Shipper

The records shipper (`tukuyomi-records-ship`) is a separate process from the proxy. It reads the proxy's log files and inserts their lines, in order, into a PostgreSQL or MySQL table. You need it only when you send logs to a DB.

The proxy does not run the records shipper and does not connect to the DB. The DB client library and the DB password exist only in the records shipper's executable and process. The records shipper has been tested with PostgreSQL 16 and 18 and MySQL 8.0.

Set it up in the following order.

1. **Prepare the DB user and the DB**
2. **Place the connection string file**: make the OS user of the service its owner, and give it mode 0600 (see "Connection String" below).
3. **Write `records.ship` in the configuration**: when you use both `ship` and `required`, set `files` to 3 or more. If you add it to a running proxy's configuration, restart the proxy, because `records` cannot change while running (see Chapter 9).
4. **Start the records shipper unit**: the unit is in "Records Shipper Unit" in section 3.5.
5. **Check the log**: look for a `records-ship: configuration accepted` line in the records shipper's log. The tables are created on the first connection.

### Starting

```text
tukuyomi-records-ship <config>
```

- For `<config>`, give the absolute path of the proxy's configuration file. It must have `records.ship`; if it does not, the records shipper writes a `records-ship: configuration refused: there is no records.ship object` line and exits.
- It reads only the configuration file, not the versions in the managed store or the country database. It rejects a configuration file with unknown setting keys, so before you add a new setting key (`managed`, `host_policies`, `kernel.default_engine`, the `engine` of an upstream, and so on) to the configuration, replace the records shipper with the same build as the proxy.
- Run it as the same OS user as the proxy. It will not run as root.
- The file system that holds the log directory must report file creation times (the btime of `statx`). The records shipper has been tested on ext4 only. On a file system that does not report them, the records shipper does not start, and the proxy, unable to tell how far behind the records shipper is, refuses `required` requests.
- The exit codes are 0 (stopped by SIGTERM, SIGINT, or SIGHUP), 1 (the connection string cannot be read, the DB refused the login, and so on), and 2 (an argument error, or the configuration was rejected).

The records shipper reads the configuration file and the connection string file only once, at start. SIGHUP is a stop signal for it, so restart it after you change the configuration.

### `records.ship`

Write all five of the following setting keys in `records.ship`.

- `db_driver`: `pgsql` or `mysql`
- `db_dsn_file`: the absolute path of the connection string file. The proxy does not open this file
- `batch`: the maximum number of lines in one transaction (1 to 10000)
- `interval_ms`: how long to wait before the next round when there were no lines to send (100 to 60000). It is also the initial wait after a failure
- `retention_days`: the number of days to keep lines in the DB (0 to 3650). 0 means never delete

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

### Connection String

The connection string contains a password, so do not write it in the configuration file; put it in a separate file. The file must meet the following conditions.

- It is a regular file
- It is owned by the OS user of the records shipper
- It has no permissions for the group and other users (0600)
- It is UTF-8 text of at most 16 KiB

Write it in one of the forms in the following examples, depending on the DB you use.

First, PostgreSQL. You can also write a URL that starts with `postgresql://` (the `tokio-postgres` format). The tables are created in the first schema in the connection's `search_path`.

```text
host=db.example.com port=5432 user=tukuyomi_ship password=<password> dbname=records
```

Next, connecting to PostgreSQL on the same host over a Unix domain socket with peer authentication. With peer authentication, the connection uses the role with the same name as the OS user, and no password is needed.

```text
host=/var/run/postgresql user=tukuyomi dbname=tukuyomi_records sslmode=disable
```

Last, MySQL. The URL uses the `mysql_async` 0.37 format. The DB name is required, and the tables are created in that DB. Percent-encode any value in the URL that contains symbols.

```text
mysql://<user>:<password>@<host>:<port>/<db-name>
```

If you write nothing about TLS, TLS is used, and the certificate and the host name are verified (for both PostgreSQL and MySQL). The connection is plaintext only when you write `sslmode=disable` for PostgreSQL or `require_ssl=false` for MySQL.

Certificates are verified against the system's certificate authorities. If your own certificate authority issued the DB server's certificate, pass a file that holds that authority's certificate with `Environment=SSL_CERT_FILE=<path>` in the unit. For the full list, including the settings that are rejected, see "Connection String (`db_dsn_file`)" in Appendix A (Operator Reference).

### Log Table

When the records shipper connects to the DB, it looks for its tables and creates only those that do not exist. There are three tables.

- `tukuyomi_records`: one row per log line. It has columns such as `ts`, `type`, `request_id`, `client`, `class`, `status`, and `rule`, plus `raw` for the line itself and `line_hash` (UNIQUE) for the line's SHA-256.
- `tukuyomi_records_state`: how far each log directory has been sent.
- `tukuyomi_records_schema`: the schema version (currently 1).

If all the tables exist and the version row is there, the records shipper creates nothing, so the DB user does not need the privilege to create tables. If you do not want to grant that privilege, first run the records shipper once as a user that has it, so that the tables are created, and then change the DB user that the records shipper connects as.

Run only one records shipper per log directory. The sent position is kept separately for each `records.dir` path, so when you send the logs of proxies on different hosts to the same tables, use a different `records.dir` path for each, or a different schema or DB.

With MySQL, set the server's `max_allowed_packet` to 2 MiB or more. For the columns, the indexes, and the differences between MySQL and PostgreSQL, see "Log Table" in Appendix A (Operator Reference).

### How Shipping Works

- In each round, the records shipper reads up to `batch` lines from the log file and, in one transaction, inserts them and advances the position table. After the commit, it writes `ship.state`. Even if the records shipper crashes, the next round continues from the position in the DB.
- After a failure, it doubles the wait, starting from `interval_ms`, up to 1 minute, and resets it after a successful round.
- Even while it cannot connect to the DB, or has no lines to send, it rewrites `ship.state` at least once per second. The proxy uses this to tell that the records shipper is running.
- It tracks the log files by inode and creation time, not by name, so it continues where it left off even when rotation renames a file.
- It sends lines of every `type`, and the line itself is always kept in `raw`. `line_hash` is UNIQUE, so a line sent twice ends up as one row.
- If `retention_days` is not 0, once per minute it deletes up to 1000 lines older than that. Age is judged by the log's `ts` (the proxy's clock).

### Logs That Cannot Be Shipped

- Lines in a log file that rotation removed before the records shipper read them are lost.
- If the records shipper had that file open, it counts the lost lines, adds them to `lost_lines` in the position, and writes the line `records-ship: a record file was removed before it was shipped, <count> lines lost`.
- Lines in a file that was removed before the records shipper opened it (for example, when the proxy rotated more than `files` times while the DB was unreachable for a long time) cannot be counted, and the records shipper writes only a line that contains `lines may be lost`. This line may also appear when nothing was lost.
- On the proxy, a `required` route refuses requests before this happens (see section 7.4). A `best_effort` or `security` route does not.
- Do not truncate the log files (for example, with logrotate's `copytruncate`). The records shipper treats a truncated file as the same file and may not send its first lines. The proxy rotates the files itself.

### Errors

Like the proxy's log, the records shipper's log goes to standard error as JSON, one entry per line. `type` is `line`, and the message starts with `records-ship:`. Messages do not contain the connection string, logs, or text from the server's error messages. A DB error is shown as a fixed message and the SQLSTATE that the server returned (example: `records-ship: the database refused or failed a request (SQLSTATE 42000)`).

- When the DB refuses the login (a PostgreSQL SQLSTATE that starts with 28, or MySQL 1045), waiting will not fix it, so the records shipper writes the line `records-ship: stop: the login is refused, which waiting does not mend` and exits (exit 1). `Restart=on-failure` in the unit keeps restarting it, so fix the connection string.
- For other refusals, the records shipper retries after the wait described above and writes a line each time.

For the rules not covered here, see "Records Shipper" in Appendix A (Operator Reference).

## 7.8 Operational Notes

To close the chapter, here are the points to watch when you manage logs.

- The logs contain the client address and the path. If a site puts secret values in the path, those values stay in the logs too. Keep the users who can read the journal, the log files, and the DB tables to a minimum.
- For each route, you choose what happens when logs cannot be kept. `required` refuses new requests on that route with 503. `best_effort` and `security` let the requests through and lose the logs.
- The proxy writes and rotates the log files. Do not truncate them (for example, with logrotate's `copytruncate`).
- When you use both the records shipper and `required` routes, set `files` to 3 or more. Then, even if the records shipper falls behind or stops, the `required` routes refuse requests before logs are lost to rotation.
- Use `tukuyomi_records_dropped_total`, `tukuyomi_record_write_errors_total`, `tukuyomi_record_file_errors_total`, `tukuyomi_records_unshipped_bytes`, and the other metrics in `/metrics` to check that logs are being written and shipped (see Chapter 9).
- When you change `records` other than `records.keep`, restart the proxy, the admin process, and the records shipper. When you change the connection string file, restart the records shipper.
