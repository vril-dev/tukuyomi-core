# Chapter 2. Quick Start

This chapter walks through downloading the release tarball and starting tukuyomi core on a single Linux host. The goal is to confirm in the logs that an ordinary request passes and that an SQL injection request is blocked.

A production deployment with systemd is covered in Chapter 3. Here you run the commands by hand, to get the product running first.

## 2.1 What This Chapter Builds and What You Need

This chapter builds the following small setup:

- The proxy (`tukuyomi-proxy`) receives requests sent from `curl` on `127.0.0.1:8000`.
- An inspector process (Coraza), which the proxy starts as a child process, inspects the requests.
- Only requests that are not blocked are forwarded to the upstream application (`127.0.0.1:8080`).

Before you start, prepare the following:

- **A Linux x86_64 host with Landlock enabled**: this is the only environment that tukuyomi core has been tested on. You need Linux 5.13 or later with `landlock` in the LSM list, which you can check in `/sys/kernel/security/lsm`. glibc 2.39 or later is also required.
- **bash, curl, sha256sum, and tar**: used to fetch the CRS.
- **Root privileges (`sudo`)**: used to create the OS user and the directories and to place the executables. tukuyomi core itself does not run as root.
- **An application that answers HTTP on `127.0.0.1:8080`**: the destination of the proxy (the upstream). It can be your own web application or an HTTP server for testing. This book does not cover how to set one up.

The release executables were built on Ubuntu 26.04.1 LTS (glibc 2.43) and have been tested only on the host where they were built. If they do not run on an older Linux, build from source. The steps are in "Building from Source" in Build and Deployment (`docs/build/binary-deployment.md`) in the repository.

## 2.2 The Overall Flow

Before the commands, here is what you prepare and in what order.

1. **Place the executables** (section 2.3): check the SHA-256 of the tarball before extracting it.
2. **Prepare the OS user and directories** (section 2.4): the proxy does not run as root, so create a dedicated OS user. Neither the proxy nor the commands create the directories named in the configuration, so create them first.
3. **Write the configuration file** (section 2.5): values have no defaults, so write every required setting key.
4. **Fetch the CRS** (section 2.6): the CRS is not bundled, so fetch it with a script that pins the version and the checksum.
5. **Import the rule set and choose it as a generation** (section 2.7): the import tries the rule set in an inspector process (the trial), and only a rule set that passes becomes a "generation". Once started, the proxy inspects with the chosen generation, and it does not start without one.
6. **Check the configuration and start** (section 2.8)
7. **Send requests and check the logs** (section 2.9)

`rules import` and `rules activate` are commands separate from the proxy, and a running proxy does not notice when they change the generation, so in this chapter you finish preparing the generation before you start the proxy. Chapter 4 explains how to make a running proxy use a new generation.

## 2.3 Downloading the Tarball and Placing the Executables

The release tarball is distributed through GitHub releases (<https://github.com/vril-dev/tukuyomi-core/releases>). Download the following two files:

- `tukuyomi-core_v0.2.2_linux_amd64.tar.gz`
- `tukuyomi-core_v0.2.2_linux_amd64.tar.gz.sha256`

First, create a working directory. The extracted script is run later with `sudo -u tukuyomi`, so the OS user `tukuyomi` must be able to read this directory. `mktemp -d` picks the name, so that no other user can create a directory with that name first, and the permissions 0755 let `tukuyomi` read it.

```bash
d=$(mktemp -d /tmp/tukuyomi-core.XXXXXX) && chmod 0755 "$d" && cd "$d"
```

Put the two downloaded files in this directory, and check the SHA-256 before extracting.

```bash
sha256sum -c tukuyomi-core_v0.2.2_linux_amd64.tar.gz.sha256
tar -xzf tukuyomi-core_v0.2.2_linux_amd64.tar.gz
```

Extracting creates `tukuyomi-core_v0.2.2_linux_amd64/`, which holds the four executables, `scripts/fetch-crs.sh`, and other files.

Place the executables where the OS user of the service cannot modify them (owned by root). This chapter uses only two of them: the proxy and the Coraza inspector process. When you use the ModSecurity inspector process (`tukuyomi-inspector-modsecurity`) and the records shipper (`tukuyomi-records-ship`), place them in the same place (see Chapter 3).

```bash
sudo install -d -m 0755 /opt/tukuyomi-core/bin
sudo install -m 0755 tukuyomi-core_v0.2.2_linux_amd64/tukuyomi-proxy \
  tukuyomi-core_v0.2.2_linux_amd64/tukuyomi-inspector /opt/tukuyomi-core/bin/
```

## 2.4 Preparing the OS User and Directories

Both the service and the commands run as the dedicated OS user `tukuyomi`. The configuration file in this chapter uses three directories:

| Directory | Setting key | Owner and permissions |
|---|---|---|
| `/var/lib/tukuyomi-core/store` | `rules.store.dir` (the rules store) | `tukuyomi`, 0700 |
| `/var/lib/tukuyomi-core/tmp` | `kernel.tmp_root` (the inspector work directory) | `tukuyomi`, 0700. Do not set setgid |
| `/var/lib/tukuyomi-core/records` | `records.dir` (the log directory) | `tukuyomi`, 0700 |

The proxy checks that each of these three is not a symbolic link, is owned by the OS user of the service, and has no permissions for the group and other users. Use a separate directory for each.

The script creates the CRS directory (`/var/lib/tukuyomi-core/crs-4.23.0`) inside its parent directory, so make the parent directory `/var/lib/tukuyomi-core` writable by `tukuyomi`.

```bash
sudo useradd --system --user-group --home-dir /var/lib/tukuyomi-core --no-create-home --shell /usr/sbin/nologin tukuyomi
sudo install -d -o tukuyomi -g tukuyomi -m 0750 /var/lib/tukuyomi-core
sudo install -d -o tukuyomi -g tukuyomi -m 0700 /var/lib/tukuyomi-core/store /var/lib/tukuyomi-core/tmp /var/lib/tukuyomi-core/records
```

## 2.5 Writing the Configuration File

The configuration file goes in `/etc/tukuyomi-core/config.json`. Make root its owner, and make it readable by the OS user of the service.

```bash
sudo install -d -m 0755 /etc/tukuyomi-core
```

Create `/etc/tukuyomi-core/config.json` with the following content. It is the configuration from "Example" under "Configuration File" in Appendix A (Operator Reference), minus the parts that you do not need to start it by hand. It differs from the example as follows:

- It has only one listener, for plain HTTP (`127.0.0.1:8000`). An OS user without `CAP_NET_BIND_SERVICE` cannot listen on ports 80 and 443, which the example uses, and there is no TLS certificate yet.
- Of the optional setting keys in the example, `acme` and `rate_limit` are removed. `records` is kept so that you can check the logs in a file.
- The other values are the same as in the example. They are starting values, and the accepted ranges are in the tables under "Configuration File" in Appendix A (Operator Reference).

```json
{
  "proxy": {
    "listeners": [
      {"address": "127.0.0.1:8000"}
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
  }
}
```

There are many setting keys, but only these four points matter in this chapter:

- **Destination**: `forward.upstreams.app` is the application that requests are forwarded to. `routes` is empty and `default_upstream` is `app`, so every request goes to `app`. Blocked requests are not forwarded.
- **Inspector process**: `kernel.inspector` is the executable of the Coraza inspector process. It cannot be omitted, even on a host that uses ModSecurity generations only.
- **Addresses**: an upstream server cannot have the same address as a listener, so the listener and the upstream use different ports.
- **Logs**: with `records`, the log lines written to standard error are also written to `records.log` in `records.dir`. However, the first lines of a start, written before the log file is opened (such as the `start: configuration accepted` and `start: rules …` lines) go only to standard error.

Running `config check` once at this point finds errors in the configuration file before you fetch the CRS.

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
```

No generation is chosen yet, so even if the configuration file is correct, the command writes a `config check: rules store refused: no generation is chosen` line and exits 1. This is expected. An error in the configuration file itself gives exit 2.

## 2.6 Fetching the CRS

The CRS (OWASP Core Rule Set) is not bundled, so fetch it with `scripts/fetch-crs.sh` in the extracted directory. Run the following command in the working directory that you moved to in section 2.3.

**Always run it as the OS user of the service.** If you run it as root, `rules import`, which runs as `tukuyomi`, cannot read the files the script creates.

```bash
sudo -u tukuyomi tukuyomi-core_v0.2.2_linux_amd64/scripts/fetch-crs.sh /var/lib/tukuyomi-core/crs-4.23.0
```

Things to know about this script:

- The CRS version to fetch (4.23.0) and the SHA-256 of the archive are pinned in the script and cannot be changed with arguments. The archive is fetched over https only, and its contents are read only after its SHA-256 matches.
- The argument is a directory that does not exist yet. The script does not touch an existing directory, and if it fails midway, it leaves nothing behind.
- The new directory contains only four kinds of files: `crs-setup.conf`, `crs-setup.conf.example`, `rules/*.conf`, and `rules/*.data`. You can edit `crs-setup.conf` before the import (see Chapter 4), but in this chapter you use it as it is.
- On a host that cannot connect to GitHub, you can pass a copy of the pinned archive with the environment variable `FETCH_CRS_ARCHIVE_FILE`. The SHA-256 and other checks are the same in that case.
- If you get `Permission denied`, make the extracted directory and its parent directories readable by `tukuyomi`.

## 2.7 Importing and Choosing the First Generation

Import the fetched CRS as a rule set generation.

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules import /etc/tukuyomi-core/config.json --crs /var/lib/tukuyomi-core/crs-4.23.0
```

For the trial, the import starts one inspector process, which inspects three fixed requests. A generation is created only if the trial passes, and `<fingerprint> created` is written to standard output. `<fingerprint>` is the fingerprint of the generation (64 hexadecimal digits). If a generation with the same content already exists, `already exists` is written.

In this chapter, you make a generation in block mode, so that you can see an SQL injection request being blocked. For the first import in production, the documentation recommends adding `--detect-only` to make a detect-only generation, checking for false positives, and then switching to a generation in block mode (see Chapter 4).

With a generation in block mode, if even one trial request is blocked, the trial fails and no generation is created. This can happen, for example, if you made the settings in `crs-setup.conf` stricter; read the log and fix the settings, or add `--accept-block`. For the list of import options, see "`rules`" in Appendix A (Operator Reference).

After the import, choose the generation, giving the value written above for `<fingerprint>`.

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules activate /etc/tukuyomi-core/config.json <fingerprint>
```

On success, `<fingerprint> current` is written. `rules list` lists the generations.

A generation is chosen for each inspection engine. Start with the generation of the default engine, which is `coraza` if `kernel.default_engine` is not written. If the default engine has no chosen generation, the proxy does not start.

## 2.8 Checking the Configuration and Starting

Before starting, check the configuration again.

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
```

If it passes, `accepted` is written to standard output and the command exits 0. `config check` does not start an inspector process, so problems with the work directory, the inspector executable, or Landlock do not show up here; they show up only at the next start.

Then start the proxy. Here you run it directly in a terminal, without systemd.

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy /etc/tukuyomi-core/config.json
```

Logs are written to standard error, one JSON object per line. A `start: the kernel is ready` line appears when the inspection kernel is ready, and a `start: listening` line when the listeners begin to listen (both are logs whose `type` is `line`). Once `start: listening` appears, the proxy has started.

Leave this terminal as it is, and run the following commands in another terminal.

## 2.9 Sending Requests and Checking the Logs

From the other terminal, send two requests. `-H 'Host: example.com'` puts the host name in the `Host` header.

The first is an ordinary request.

```bash
curl -i -H 'Host: example.com' http://127.0.0.1:8000/
```

The upstream's response comes back. Its headers include the `X-Request-ID` that the proxy added.

The second is an SQL injection request. The query is `id=1' OR '1'='1`, URL-encoded.

```bash
curl -i -H 'Host: example.com' 'http://127.0.0.1:8000/item?id=1%27%20OR%20%271%27%3D%271'
```

For this one, the proxy returns 403 with an empty body. The request is not forwarded, so it does not appear in the upstream's access log either.

Check the results in the log file, which only `tukuyomi` and root can read.

```bash
sudo -u tukuyomi grep '"type":"request"' /var/lib/tukuyomi-core/records/records.log
```

Each request log is one line of JSON. Look at the following fields:

| Field | Ordinary request | SQL injection request |
|---|---|---|
| `class` | `forwarded` | `blocked` |
| `reason` | `forwarded` | `blocked by a rule` |
| `status` | The status code that the upstream returned | 403 |
| `mode`, `engine` | `block`, `coraza` | `block`, `coraza` |
| `rule` | Not present if no rule matched | The ID of the rule that blocked the request |

- `generation` is the first 16 digits of the generation's fingerprint, the same value as the generation chosen in section 2.7.
- The query is not recorded in the log. Tell the two requests apart by `path` and `id`. `id` is the same value as the `X-Request-ID` of the response.
- For the list of log fields, see "Request Log (`request`)" in Appendix A (Operator Reference).

If you had imported a detect-only generation, the SQL injection request would also be forwarded to the upstream. Its log would have `class` `forwarded` and `reason` `detected by a rule`, with the ID of the matching rule in `rule` (see "Detect-Only Mode" in Appendix A (Operator Reference)).

## 2.10 Stopping

From the other terminal, send SIGTERM to the main process of the proxy. Always send signals only to the proxy's main process (see "Signals" in Appendix A (Operator Reference)). The inspector processes exit when they receive SIGTERM, SIGINT, or SIGHUP, so send the signal to the PID of the proxy.

```bash
sudo kill -TERM $(pgrep -u tukuyomi -x tukuyomi-proxy)
```

The proxy stops accepting new connections and requests, finishes the requests in progress, then stops the inspector process and exits. The last log line begins with `stop: kernel ...`. The exit code is 0 only if the proxy confirmed that the inspector process ended and the work directory was removed. For the details of the stop sequence, see "Stopping" in Appendix A (Operator Reference).

## 2.11 Troubleshooting

| Symptom | Cause and remedy |
|---|---|
| A `host check refused` line appears, and the command exits 1 | You are running as root. Add `sudo -u tukuyomi` to run as the OS user of the service |
| `config check` exits 2 | The configuration file has an error. A range error, or an error in the relation between setting keys, names the setting key (for example, `max_conns is out of range`). A format error (not JSON, an unknown setting key, a wrong type) does not say which setting key |
| `config check` or the proxy start exits 1 with `rules store refused: no generation is chosen` | No generation is chosen for the default engine. Run `rules activate` as in section 2.7 |
| `rules import` cannot read the CRS directory | If you run `fetch-crs.sh` as root, only root can read the files it creates. Delete that directory and fetch the CRS again as `tukuyomi` |
| The `rules import` trial fails | On a Linux without Landlock, the inspector process does not start, so the trial fails. With a generation in block mode, the trial also fails when a trial request is blocked (`--accept-block`) |
| The proxy stops with `stop: the kernel failed, engine <engine>: Exit(14)` | On a Linux without Landlock, the inspector process does not start. Check that the Linux is 5.13 or later and that `landlock` is in the LSM list |
| Both the start and `rules import` fail with a directory error | Make the directories in the table of section 2.4 owned by `tukuyomi`, with permissions 0700. Symbolic links cannot be used. Neither the proxy nor the commands create these directories |
| The start stops because a listener cannot be bound | Another process is using the same address and port. If even one listener cannot be bound, the proxy uses none of them and stops |
| An ordinary request gets 502 | The proxy cannot connect to the upstream `127.0.0.1:8080`. Start the upstream. The log of such a request has `class` `failed` |

The checks before start also include two more conditions: SIGCHLD is not ignored, and all file descriptors greater than 2 are close-on-exec. Both are met when you start from systemd. If a start by hand is refused, check that the shell does not ignore SIGCHLD and does not pass file descriptors on. For the whole start sequence and the exit codes, see "Start" and "`config check`" in Appendix A (Operator Reference).

## 2.12 Notes on This Setup

- **This setup is for trying the product out**: the listener is on a loopback address only, the protocol is plain HTTP, and the process stays attached to the terminal. In production, run the proxy in a systemd unit. Listening on ports 80 and 443 requires `CAP_NET_BIND_SERVICE`, which the unit grants (see Chapter 3). TLS certificates are either placed as files or issued with ACME (see Chapter 8).
- **The generation in this chapter is in block mode**: for the first import in production, the documentation recommends checking for false positives with a detect-only generation before switching (see Chapter 4). The generation in this chapter has no bypass routes, so if you go on to the admin screens of Chapter 5 with it, requests to the admin screens can be blocked. If you use the admin screens, put bypass routes in the first generation (see section 4.6 and section 5.4).
- **Logs go to standard error, and also to a file if `records` is present**: the first lines of a start, written before the log file is opened, go only to standard error. The logs contain client addresses and paths, so keep the users who can read them to a minimum (see Chapter 7).
- **This chapter does not set up the admin screens or log shipping to a DB**: the admin process is covered in Chapter 5, and the records shipper in Chapter 7.
- **Names match the deployment example of Chapter 3**: the OS user, the directories, and the location of the executables.

Chapter 3 moves the proxy that you started by hand here into a systemd unit. It also explains the units for the admin process and the records shipper, the certificate renewal timer, the checks before start, and restricting the inspector processes.
