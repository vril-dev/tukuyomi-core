[English](binary-deployment.md) | [日本語](binary-deployment.ja.md)

# Build and Deployment

This document explains how to run the current implementation on a single Linux host. For the meaning and range of the setting keys, and for the commands, signals, logs, and monitoring, see the [operator reference](../operations/operator-reference.md); for the admin process settings and API, see the [admin reference](../operations/admin-reference.md).

The paths in this document (`/opt/tukuyomi-core`, `/etc/tukuyomi-core`, `/var/lib/tukuyomi-core`) and the OS user name (`tukuyomi`) are examples. Write every path in the configuration as an absolute path (a path that contains `.`, `..`, an empty element, or a trailing `/` is rejected).

## Components

| Component | Content |
|---|---|
| `tukuyomi-proxy` (Rust, `proxy/`) | Receives HTTP/HTTPS requests and forwards them. It embeds the inspection kernel (`kernel/`, a Rust library) and starts, stops, and restarts the inspector processes. The same executable also provides the rules store commands (`rules`), the certificate command (`acme renew`), the configuration check (`config check`), and the admin process (`admin`) |
| `tukuyomi-inspector` (Go, `inspector/`) | Inspects requests with Coraza. The proxy starts it as a child process, and the two communicate over an inherited pair of Unix domain sockets. It has no listening port. Specify it with `kernel.inspector` in the configuration |
| `tukuyomi-inspector-modsecurity` (Rust and C++, `inspector-modsecurity/`) | Inspects requests with ModSecurity v3 (libmodsecurity 3.0.17). It is needed only when you use a ModSecurity generation (`rules import --engine modsecurity`) or when you set `modsecurity` as the default engine or an upstream engine, and hosts that do not use it can omit it. The proxy starts it as a child process, and the two communicate over an inherited pair of Unix domain sockets. It has no listening port. Specify it with `kernel.engines.modsecurity.inspector` in the configuration |
| `tukuyomi-records-ship` (Rust, `records-ship/`) | The records shipper. It ships the lines of the proxy's log files to a PostgreSQL or MySQL table. It is needed only when you ship logs to a DB, and hosts that do not ship logs can omit it. It runs in a unit separate from the proxy and reads the same configuration file. It has no listening port |
| Admin process | `tukuyomi-proxy admin <config>`, the same executable. Run it in a unit separate from the proxy. It listens on a loopback address and provides the admin API and the admin screens (already embedded in the executable). It operates on rule generations and asks the proxy to switch them through the control socket |
| Configuration file | A single JSON file. Values have no defaults. Write every setting key except the optional ones (`acme`, `records`, `access`, `rate_limit`, `geo`, `admin`, and others). The proxy and the admin process read the same file |
| Rules store | The directory that holds the rule set generations (`rules.store.dir` in the configuration). `rules import` creates generations, and `rules activate` chooses the generation to use for each engine (Coraza or ModSecurity). The admin process performs the same operations |
| Inspector work directory | The parent directory in which a temporary directory is created at each start (`kernel.tmp_root` in the configuration) |
| Certificates and keys | Used by the TLS listeners. Either `acme renew` issues and renews them, or the operator places them |
| Log directory | The directory that holds copies of the logs written to standard error (`records.dir` in the configuration). The proxy writes to it, and the admin process and the records shipper read it. The records shipper also writes the shipped position (`ship.state`) here |
| Connection string file | A file that holds the string (including the password) that the records shipper uses to connect to the DB (`records.ship.db_dsn_file` in the configuration). Only the records shipper reads it |
| Admin store | The directory in which the admin process keeps users, API tokens, the audit log, and the switch history (`admin.store.dir` in the configuration) |
| Control socket | The Unix domain socket on which the proxy receives requests from the admin process (`admin.control` in the configuration) |
| Country database | A file in MaxMind DB format, used for country lists in access control (`access`) (`geo.country_db` in the configuration). The operator provides it |

The inspector processes, the admin process, and the records shipper run as the same OS user as the proxy.

## Requirements

- Linux. It has been tested on x86_64 only.
- Linux with Landlock enabled.
  - An inspector process restricts its own privileges with Landlock after it reads the rules (see "Restricting the Inspector Processes" below).
  - On a Linux without Landlock, the inspector process does not start (exit 14). The proxy does not start either (the log shows `stop: the kernel failed, engine <engine>: Exit(14)`). Both the `rules import` trial and the admin process's import trial fail. There is no setting to run without the restriction.
  - You need Linux 5.13 or later, which includes Landlock, and `landlock` must be in the LSM list (you can check it in `/sys/kernel/security/lsm`). We have not checked which distributions enable Landlock by default.
  - What can be restricted depends on the Linux version. You cannot tell from the outside which ABI version was used for the restriction.
    - Restricting TCP bind and connect requires Linux 6.7 or later (Landlock ABI 4 or later). On earlier versions, only file access is restricted.
    - On Linux earlier than 6.2 (ABI 1 and 2), truncating files cannot be prohibited. On Linux earlier than 6.10 (up to ABI 4), device ioctls cannot be prohibited.
- The only shared libraries needed on a host that runs the ModSecurity inspector process are libstdc++, libgcc_s, libc, and libm. libmodsecurity, YAJL, and PCRE2 are statically linked into the executable, so you do not need to install them.
- One proxy always runs, plus one inspector process for each started engine (the admin process and the records shipper are separate processes).
  - With Coraza only, there is one inspector process; if both Coraza and ModSecurity are started, there are two.
  - While an engine's generation is being switched, that engine temporarily has one more inspector process. Only one switch can run at a time across the whole proxy.
  - For each import trial, the admin process starts one inspector process (the `rules import` command does the same).
  - For memory estimates, see "Choosing the Inspection Engine" in the [operator reference](../operations/operator-reference.md).
- Needed for the build:
  - Rust 1.94.1 or later (`rust-version` in `proxy/Cargo.toml`)
  - A C compiler (aws-lc-rs, the TLS library, builds C code)
  - Go 1.27.2 (`inspector/go.mod`). The inspector process reports the Go version used for the build to the inspection kernel. The inspection kernel accepts only an inspector built with `go1.27.2`.
- You also need the following, but only to build the ModSecurity inspector process:
  - `rustc` exactly 1.94.1 (the `release:` line of `rustc -vV` is `1.94.1`). Unlike with the proxy, the inspection kernel rejects an inspector process built with a different version (see "ModSecurity Inspector" below).
  - C and C++ compilers, and make
  - libyajl-dev and libpcre2-dev (the static libraries `libyajl_s.a` and `libpcre2-8.a`)
  - bash, curl, sha256sum, and tar (used to fetch libmodsecurity; curl is not needed if you pass the archive with `BUILD_MODSECURITY_ARCHIVE_FILE`)
- Needed to fetch the CRS: bash, curl, sha256sum, and tar
- Needed only when you ship logs to a DB:
  - A PostgreSQL or MySQL server. It has been tested with PostgreSQL 16 and 18 and MySQL 8.0.
  - The file system that holds the log directory must report file creation times (the btime of `statx`). It has been tested on ext4 only.

## Release Tarball

Since 0.1.0, a tarball of executables for Linux x86_64 has been distributed through GitHub releases. Use it if you do not build from source. Since 0.2.1, each release also has the operations guide (the documentation rearranged as a book) as EPUB and PDF, in Japanese and English.

| File | Content |
|---|---|
| `tukuyomi-core_v0.2.1_linux_amd64.tar.gz` | In the directory `tukuyomi-core_v0.2.1_linux_amd64/`: the four executables (see "Components" above), `README.md`, `README.ja.md`, `LICENSE`, `NOTICE`, `THIRD-PARTY-LICENSES`, `docs/`, and `scripts/fetch-crs.sh` |
| `tukuyomi-core_v0.2.1_linux_amd64.tar.gz.sha256` | The SHA-256 of the tarball |
| `tukuyomi-core_v0.2.1_guide_ja.epub`, `tukuyomi-core_v0.2.1_guide_ja.pdf` | The operations guide, Japanese edition (EPUB and PDF) |
| `tukuyomi-core_v0.2.1_guide_en.epub`, `tukuyomi-core_v0.2.1_guide_en.pdf` | The operations guide, English edition (EPUB and PDF) |
| `tukuyomi-core_v0.2.1_SHA256SUMS` | The SHA-256 of the tarball and of the four books |

- After downloading, check the SHA-256 before extracting.

  ```bash
  sha256sum -c tukuyomi-core_v0.2.1_linux_amd64.tar.gz.sha256
  tar -xzf tukuyomi-core_v0.2.1_linux_amd64.tar.gz
  ```

- The books are not in the tarball. To check a downloaded book, use its line in `tukuyomi-core_v0.2.1_SHA256SUMS` (for example, `sha256sum -c --ignore-missing tukuyomi-core_v0.2.1_SHA256SUMS` in the directory of the downloaded files).
- The executables were built on Ubuntu 26.04.1 LTS (glibc 2.43, gcc 15.2.0) with `rustc` 1.94.1 and Go 1.27.2. They have been tested only on the host where they were built.
- The host that runs them needs glibc 2.39 or later (`tukuyomi-proxy` uses `GLIBC_2.39` symbols). The ModSecurity inspector process also needs the libstdc++ symbols `GLIBCXX_3.4.29` and `CXXABI_1.3.15`. They do not run on an older Linux, so build from source there (see "Building from Source" below).
- The inspector process (`tukuyomi-inspector`) is statically linked. The TLS library (aws-lc) is also statically linked into the executable.
- Place the executables in, for example, `/opt/tukuyomi-core/bin/`. From there, the steps are the same as for a build from source (see "OS User and Directories" and "First Start" below).

## Building from Source

Build the proxy in `proxy/`. The inspection kernel is built together with it.

```bash
cd proxy && cargo build --release --locked
```

The executable is produced at `proxy/target/release/tukuyomi-proxy`. This build embeds the admin screen files (`proxy/admin-ui/`) in the executable, so the screens need no separate build or distribution.

Build the inspector process in `inspector/` without cgo.

```bash
cd inspector && CGO_ENABLED=0 go build -mod=readonly -o tukuyomi-inspector .
```

Always specify `CGO_ENABLED=0`.

- The inspector process uses Go's `syscall.AllThreadsSyscall` to apply Landlock and the other restrictions to all threads. In an executable that uses cgo, this call returns `ENOTSUP`, so the inspector process does not start (exit 14).
- The reason it does not start (`the inspector is built with cgo and cannot restrict every thread`) does not appear on the standard output or standard error of the inspector process. It appears only in the `the inspector said:` line of `rules import`, and in the `reload: the inspector said:` line when a SIGUSR1 switch fails. At proxy start, only the line `stop: the kernel failed, engine <engine>: Exit(14)` appears.

### ModSecurity Inspector

Build it only when you use ModSecurity generations; hosts that use only Coraza generations do not need it. First build libmodsecurity (ModSecurity v3.0.17) as a static library in a new directory (the prefix), then build the inspector process against that prefix.

```bash
scripts/build-modsecurity.sh <new-dir>
cd inspector-modsecurity && TUKUYOMI_MODSECURITY_PREFIX=<new-dir> cargo build --release --locked
```

The executable is produced at `inspector-modsecurity/target/release/tukuyomi-inspector-modsecurity`.

`scripts/build-modsecurity.sh` behaves as follows:

- The version to fetch (3.0.17) and the sha256 of the distribution archive (`modsecurity-v3.0.17.tar.gz`) (`f283b33d5c21130fd3a15c84a93a1abe12bd1949edaf44288b12af571b671a50`) are pinned in the script. You cannot change them with arguments.
- The archive is fetched over https only, and its contents are read only after it matches the pinned sha256. On a host that cannot connect to GitHub, you can pass a copy of the pinned archive with `BUILD_MODSECURITY_ARCHIVE_FILE`. The same sha256 and other checks apply in that case.
- Give a path that does not exist yet. A relative path is resolved from the current directory, and the resulting absolute path may contain only letters, digits, `.`, `_`, `+`, and `-`; no name in it can start with `.`.
- The parent directory of the new directory must already exist and be writable by the OS user that runs the script. The script creates a temporary directory next to it and, at the end, puts the new directory in place with a single rename.
- It does not touch an existing directory. If it fails midway, nothing is left behind.
- It takes a few minutes.
- configure runs with flags that are hard-coded in this script. It does not use curl, Lua, MaxMind, GeoIP, libxml2, LMDB, or ssdeep, and uses only YAJL and PCRE2. If configure reports anything else, the script exits with an error. This is part of the protection that keeps rules from using features such as importing rules from outside, running scripts, referencing databases, and parsing XML, so do not change it.
- The prefix then contains `include/`, `lib/libmodsecurity.a`, `include-src/` (the internal headers of libmodsecurity), and `archive.sha256` (one line with the sha256 of the pinned archive).

Building the inspector process fails with an error in the following cases:

- `TUKUYOMI_MODSECURITY_PREFIX` is missing or is not an absolute path
- The prefix lacks any of `include/modsecurity/modsecurity.h`, `include-src/src/variables/variable.h`, and `lib/libmodsecurity.a`
- `archive.sha256` in the prefix cannot be read, or is not one line of 64 lowercase hexadecimal digits
- The C++ compiler cannot find `libpcre2-8.a` (libpcre2-dev) or `libyajl_s.a` (libyajl-dev)

In its first message at start (HELLO), the inspector process reports to the inspection kernel the compiler version used for the build, the libmodsecurity version, and the archive sha256. The inspection kernel accepts a ModSecurity inspector process only if all three of the following match:

| Field | Accepted value |
|---|---|
| The compiler used for the build | `rustc 1.94.1` |
| The libmodsecurity version | `v3.0.17` |
| The archive sha256 | `f283b33d…b671a50` above |

If they do not match, the inspection kernel writes one of `hello toolchain differs`, `hello engine version differs`, and `hello engine source differs`, rejects the inspector process, and does not restart it. At proxy start, the line `stop: the kernel failed, engine <engine>: Hello("<message>")` appears; with `rules import`, the line `rules import: the trial failed: the inspector could not be started (Hello("<message>"))` appears.

### Records Shipper

Build it only when you ship logs to a DB. Build it in `records-ship/`; the proxy library is built along with it.

```bash
cd records-ship && cargo build --release --locked
```

The executable is produced at `records-ship/target/release/tukuyomi-records-ship`. The requirements are the same as for the proxy (Rust 1.94.1 or later and a C compiler).

### Fetching the CRS

The CRS (OWASP Core Rule Set) is not bundled, so fetch it with `scripts/fetch-crs.sh`. Run the script as the OS user of the service. The CRS is distributed under the Apache License 2.0. The script extracts only the rule files and does not extract the `LICENSE` in the archive.

```bash
sudo -u tukuyomi scripts/fetch-crs.sh /var/lib/tukuyomi-core/crs-4.23.0
```

- The version to fetch (4.23.0) and the sha256 of the distribution archive are pinned in the script. You cannot change them with arguments.
- The archive is fetched over https only, and its contents are read only after it matches the pinned sha256. On a host that cannot connect to GitHub, you can pass a copy of the pinned archive with `FETCH_CRS_ARCHIVE_FILE`. The same sha256 and other checks apply in that case.
- The new directory contains only the following four entries:
  - `crs-setup.conf` (a copy of `crs-setup.conf.example`)
  - `crs-setup.conf.example`
  - `rules/*.conf`
  - `rules/*.data`
- The script runs with `umask 077`, so only the OS user that ran it can read the directory and files it creates. If you run it as root, `rules import`, which runs as the OS user of the service, cannot read them.
- The parent directory of the new directory must already exist and be writable by the OS user that runs the script. The script creates a temporary directory next to it.
- It does not touch an existing directory. If it fails midway, nothing is left behind.
- The operator can edit `crs-setup.conf` before the import, for example to add body types to accept (see "Rule Sets and Generations" in the [operator reference](../operations/operator-reference.md)).

## OS User and Directories

The proxy does not run as root. If any of the process's four user IDs (real, effective, saved, file system) is 0, the proxy start and every command write a `host check refused` line and refuse to run (exit 1).

- Create a dedicated OS user and run both the service and the commands as that OS user. For example, use `sudo -u tukuyomi tukuyomi-proxy ...`.
- `acme renew` also refuses to run as root, because the proxy, which runs as another OS user, cannot read keys created by root.
- Run the admin process (`admin`) and its short-lived commands (`admin bootstrap` and `admin reset`) as the same OS user, because only that OS user can use the rules store, the log directory, the control socket, and the managed store (0700). None of them can be used if you run as a different OS user.
- Run the records shipper as the same OS user too, because it reads the log directory and writes `ship.state` there. The records shipper does not run as root either.

Examples of directories and files:

| Example | Setting key | Owner and permissions |
|---|---|---|
| `/opt/tukuyomi-core/bin/tukuyomi-proxy`, `/opt/tukuyomi-core/bin/tukuyomi-inspector` | `kernel.inspector` (for the Coraza inspector process) | root. Place them where the OS user of the service cannot modify them |
| `/opt/tukuyomi-core/bin/tukuyomi-inspector-modsecurity` | `kernel.engines.modsecurity.inspector` (for the ModSecurity inspector process; optional) | root. Place it where the OS user of the service cannot modify it |
| `/opt/tukuyomi-core/bin/tukuyomi-records-ship` | (the records shipper unit; optional) | root. Place it where the OS user of the service cannot modify it |
| `/etc/tukuyomi-core/config.json` | (the start argument) | root. The OS user of the service must be able to read it. The size is up to 256 KiB |
| `/var/lib/tukuyomi-core/store` | `rules.store.dir` | The OS user of the service. Permissions 0700 |
| `/var/lib/tukuyomi-core/tmp` | `kernel.tmp_root` | The OS user of the service. Permissions 0700. Do not set setgid |
| `/var/lib/tukuyomi-core/managed` | `managed.dir` (when you use the managed configuration) | The OS user of the service. Permissions 0700. The commands, the admin process, and `acme renew` create `versions/`, `files/`, `acme/`, and so on inside it |
| `/var/lib/tukuyomi-core/tls/` | `cert_file` and `key_file` of the certificates used by the listeners and by the admin route (`admin.route`) | The OS user of the service (`acme renew` writes them). With the managed configuration, the certificates of ACME sites are in `acme/` in the managed store |
| `/var/lib/tukuyomi-core/acme/account.key` | `acme.account_key_file` | `acme renew` creates it on the first run (0600) |
| `/var/lib/tukuyomi-core/challenges` | `acme.challenge_dir` | The OS user of the service. Use a directory dedicated to challenges |
| `/var/lib/tukuyomi-core/records` | `records.dir` | The OS user of the service. Permissions 0700. The proxy creates `records.log` and the other files inside, and the records shipper creates `ship.state`, all with 0600 |
| `/etc/tukuyomi-core/records-db.dsn` | `records.ship.db_dsn_file` (when you use the records shipper) | The owner is the OS user of the service, and the permissions are 0600. Unlike the configuration file, the owner is not root (the records shipper checks the owner and permissions) |
| `/var/lib/tukuyomi-core/admin` | `admin.store.dir` (the admin store) | The OS user of the service. Permissions 0700. The admin process creates `users/`, `tokens/`, `audit/`, and the others inside |
| `/var/lib/tukuyomi-core/control` | The directory in which `admin.control` is placed (the example socket is `/var/lib/tukuyomi-core/control/proxy.sock`) | The OS user of the service. Permissions 0700. The proxy creates the socket with 0600. The socket path is up to 107 bytes |
| `/var/lib/tukuyomi-core/crs-4.23.0` | `admin.crs_dir` (when you import the CRS through the admin API) | The directory created in "Fetching the CRS". The OS user of the service must be able to read it |
| `/etc/tukuyomi-core/country.mmdb` | `geo.country_db` | root. Make it readable by the OS user of the service and not modifiable by it (0644). The proxy does not check the owner and permissions |

- Write `kernel.inspector` in the configuration even on a host that uses ModSecurity generations only (it is not an optional setting key). Write `kernel.engines` only when you use ModSecurity generations. Without it, a ModSecurity generation can be neither imported nor chosen, and the proxy rejects it at start as well (see "`kernel`" in the [operator reference](../operations/operator-reference.md)). When you set `kernel.default_engine` to `modsecurity`, you still write `kernel.inspector` (and `kernel.engines` is also needed).
- Create the directories in the table above beforehand. Neither the proxy nor the commands create them. The commands and the proxy create what is inside the rules store (`generations/`, `staging/`, `using/`, and so on); the commands, the admin process, and `acme renew` create what is inside the managed store; the admin process creates what is inside the admin store; and the proxy creates the log files and the control socket.
- Use separate directories for the rules store, the log directory, the admin store, the directory for the control socket, the managed store, and `challenge_dir`. They cannot be the same directory or be placed inside one another (the configuration is rejected). In the example in the table above, they are all separate directories under `/var/lib/tukuyomi-core`. Overlap is checked by comparing the paths as written, so do not use symbolic links.
- The example unit in "systemd" below uses `ReadWritePaths=/var/lib/tukuyomi-core` to make the directories under it writable. If you also place the managed store under it, you do not need to change the unit. If you place it elsewhere, add it to `ReadWritePaths`.
- For the rules store, the work directory, the log directory, the admin store, the directory for the control socket, and the managed store, the following are checked: it is a directory and not a symbolic link, it is owned by the OS user of the process, and it has no permissions for the group and other users. When the checks run differs from directory to directory.
  - The rules store is checked at proxy start, in `config check`, and in the `rules` commands, and also when the admin process opens it. If the conditions are not met, the operation is refused with exit 1.
  - The managed store is checked every time it is opened (proxy start and configuration reload, `config check`, the `managed` commands, `acme renew`, and the admin process). If the conditions are not met, it is rejected (proxy start and `config check` end with exit 1).
  - The work directory is checked every time an inspector process is started (proxy start, restart of an inspector process, a SIGUSR1 switch, and the `rules import` trial). If the conditions are not met, the inspector process does not start. At proxy start the proxy ends with exit 1, a SIGUSR1 switch keeps the current generation running, and on a restart of an inspector process the proxy stops.
  - The log directory is checked at proxy start. If the conditions are not met, the proxy does not start (exit 1). It is also checked before the log file is reopened and before rotation.
  - The directory for the control socket is checked at proxy start. If the conditions are not met, the proxy does not start (exit 1).
  - The admin store is checked at admin process start and in `admin bootstrap` and `admin reset`. If the conditions are not met, they refuse with exit 1.
  - `config check` and `acme renew` do not check the work directory. `config check` does not check the log directory, the directory for the control socket, or the admin store either.
- The parent directories of the directories above are not checked. It is the operator's responsibility to prevent other OS users from creating or replacing names inside them.
- If setgid is set on the work directory, the directories created inside it inherit that attribute and fail the permission check, so the inspector process cannot start.
- `acme renew` writes the certificate, key, and challenge files as temporary files in their own directories (for an ACME site, inside `acme/` in the managed store) and then replaces the targets, so the OS user of the service must be able to write to these directories.
- If you run a command as an OS user that cannot read the configuration file, the configuration is rejected when it is read. If you run it as an OS user other than the owner of the rules store or the managed store, it is rejected when that store is opened.

### Country Database

Needed only when you use country lists (`deny_countries` and `allow_countries` in the global `access`, in the `access` of `host_policies`, and in a route's `access`).

- The database is not bundled with the proxy, and the proxy does not fetch it. The operator provides a file in MaxMind DB format (version 2) and must follow the provider's license terms.
- Location and permissions: make the owner root, and make the file readable by the OS user of the service but not modifiable by it (0644). An example is `/etc/tukuyomi-core/country.mmdb`. The proxy does not check the owner or permissions; it verifies the contents against `geo.sha256`. Do not make it a symbolic link (it is rejected). The file can be up to 256 MiB.
- Every command that reads the whole configuration (proxy start and reload, `config check`, `acme renew`, `managed import`, and `managed activate`) reads all of this file as the OS user of the service. A command run as an OS user that cannot read this file rejects the configuration while reading it. The `rules` and `admin` commands, the admin process, and the records shipper do not read this file.
- When the configuration has country lists, the proxy keeps the whole verified file in memory. A command that reads the file verifies all of it each time, so a large file costs time and memory.
- Compute the SHA-256 of the file and write it in `geo.sha256` in the configuration. Every command rejects the configuration if the values do not match.

  ```bash
  sha256sum /etc/tukuyomi-core/country.mmdb
  ```

- To replace the database, place the new file under a different name, and change both `geo.country_db` and `geo.sha256` in one write of the configuration file. Check it with `config check`, and then reload the proxy (`systemctl reload`). The proxy reads the database at start and at every reload. The admin process does not read the database.
- For the setting keys and how the country is determined (a private address, or an IPv6 address with an IPv4-only database, is `UNKNOWN`), see "Access Control and Rate Limits" in the [operator reference](../operations/operator-reference.md).

## First Start

If you write `managed` in the configuration file (that is, you use the managed configuration), follow the procedure in "First Start with the Managed Configuration" in the [operator reference](../operations/operator-reference.md). To decide whether to use the managed configuration, see "Whether to Use the Managed Configuration" in the same document. That procedure uses steps 2 to 4 and 7 below as they are.

1. Write the configuration file. For the list of setting keys and an example, see the [operator reference](../operations/operator-reference.md). Create the directories in the table above first. If you use country lists, also place the country database and write its `sha256` (see "Country Database" above).
2. Fetch the CRS (see "Fetching the CRS" above).
3. Import the rule set.

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules import /etc/tukuyomi-core/config.json --crs /var/lib/tukuyomi-core/crs-4.23.0 --detect-only
   ```

   - The import starts one inspector process and inspects three fixed requests (the trial). Only if the trial passes is a generation created, and `<fingerprint> created` is written to standard output. If a generation with the same content already exists, `already exists` is written.
   - With `--detect-only`, the generation is in detect-only mode: requests that match rules are also let through and recorded in the log. We recommend running in this mode first, checking for false positives, and then switching to a generation in block mode.
   - With a generation in block mode, if even one of the trial requests is blocked, the trial fails and no generation is created. If that happens, for example because you made the settings in `crs-setup.conf` stricter, read the log and fix the settings, or add `--accept-block`.
   - To make a ModSecurity generation, add `--engine modsecurity`. `kernel.engines` in the configuration must specify its inspector process. The trial runs with that engine's inspector process.
4. Choose the generation.

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules activate /etc/tukuyomi-core/config.json <fingerprint>
   ```

   - Generations are chosen per engine, and the first to choose is the one for the default engine (`kernel.default_engine` in the configuration, or `coraza` if it is not written). If the default engine has no chosen generation, the proxy does not start.
   - To start with ModSecurity only, set `kernel.default_engine` in the configuration to `modsecurity` and choose a ModSecurity generation. If you choose only a ModSecurity generation without writing `kernel.default_engine`, `config check` and the proxy start refuse with `rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine` (exit 1).
   - For more on choosing per engine, see "Chosen Generation per Engine" in the [operator reference](../operations/operator-reference.md).
5. Check the configuration.

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
   ```

   - If it passes, `accepted` is written to standard output and it ends with exit 0.
   - If you run it before choosing a generation for the default engine, it is refused with `rules store refused: no generation is chosen` (exit 1). It is refused with the same message when an upstream engine has no chosen generation. An error in the configuration itself gives exit 2, so you can also run it after step 1.
   - It also checks the upstream server names and the TLS certificate and key files. A rejection there also ends with exit 1; the beginning of the line (`upstream refused`, `tls refused`) tells you which check failed.
   - It does not start an inspector process, so it does not check the work directory, the inspector executable, or Landlock.
6. Start the service (see "systemd" below).
7. If you use the admin process, also start its unit (see "Admin Process Unit" below) and create the first user.

   ```bash
   read -r -s -p 'password: ' PW; echo
   printf '%s\n' "$PW" | sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy admin bootstrap /etc/tukuyomi-core/config.json <name>
   unset PW
   ```

   - The password is read from the first line of standard input (12 to 128 bytes). Do not pass it as an argument. The name is 1 to 32 bytes of `a-z`, `0-9`, `.`, `_`, and `-`.
   - The user it creates has the `owner` role. On success, `created owner <name>` is written. If the admin store already has at least one user, the command is refused (exit 1).
   - You can run it before or after the admin process starts. For a user who has forgotten their password, use `admin reset`.
   - For the admin API, roles, and screens, see the [admin reference](../operations/admin-reference.md).
8. If you ship logs to a DB, prepare the DB user and the DB, and place the connection string file, owned by the OS user of the service, with permissions 0600. Write `records.ship` in the configuration and start the records shipper unit (see "Records Shipper Unit" below). The records shipper creates the table when it first connects. For the table permissions and the connection string format, see "Records Shipper" in the [operator reference](../operations/operator-reference.md).

## systemd

Here is an example service unit.

```ini
[Unit]
Description=tukuyomi-core WAF
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=tukuyomi
Group=tukuyomi
ExecStart=/opt/tukuyomi-core/bin/tukuyomi-proxy /etc/tukuyomi-core/config.json
ExecReload=/opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
KillSignal=SIGTERM
TimeoutStartSec=90
TimeoutStopSec=60
LogRateLimitIntervalSec=0
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/tukuyomi-core
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

- Use `KillMode=mixed`.
  - With the default `control-group`, the SIGTERM that stops the service also reaches the inspector processes.
  - An inspector process does not handle SIGTERM and exits immediately, so the proxy cannot stop the inspector processes in order (finishing the remaining inspections and receiving the termination notice).
  - With `mixed`, SIGTERM reaches only the proxy. The proxy stops the inspector processes itself and then exits.
- Use `Type=notify`. The proxy sends `READY=1` to systemd once the inspection kernels of all the engines it starts are ready and all the listeners are bound, and sends `STOPPING=1` when it begins to stop. `systemctl start`, and units ordered after this unit with `After=`, wait until then. With `Type=simple`, the service is considered started as soon as it is executed.
  - Only the main process of the proxy sends the notifications, so you can leave `NotifyAccess` at its default (`main`).
  - Make `TimeoutStartSec` longer than the sum of the upstream name resolution time (`resolve_timeout_ms`) and the time to wait for the inspection kernel to be ready (`ready_wait_ms`). If `READY=1` does not arrive within this time, systemd stops the proxy.
- Make `TimeoutStopSec` longer than the sum of `stop_wait_ms`, `kill_grace_ms`, and the 200 ms for writing out the logs. If it is shorter, systemd sends SIGKILL first. For the stop sequence, see "Stopping" in the [operator reference](../operations/operator-reference.md).
- Specify `LogRateLimitIntervalSec=0`. With journald's default rate limit, request logs are lost before they reach the journal when many requests arrive at once.
- Logs go to the journal. If the configuration has `records`, the same logs are also written to files (see "OS User and Directories" above). The retention period and size are set in the journald configuration (`SystemMaxUse`, `MaxRetentionSec`, and so on in `/etc/systemd/journald.conf`). The logs contain client addresses and paths, so keep the number of OS users in the groups that can read the journal (`adm` and `systemd-journal` on Ubuntu) to a minimum. For the log format, see "Logs" in the [operator reference](../operations/operator-reference.md).
- If you add a listener for monitoring (`status` in the configuration), a monitoring program on the same host can access `/healthz`, `/readyz`, and `/metrics`. Use `/readyz` for a load balancer's readiness check.
- Send signals only to the main process of the proxy (`$MAINPID` in `ExecReload`, or `systemctl kill --kill-whom=main`).
  - `systemctl kill` without `--kill-whom=main` also sends the signal to the inspector processes.
  - An inspector process ignores SIGUSR1 and SIGUSR2, but exits when SIGTERM, SIGINT, or SIGHUP arrives.
- `systemctl reload` runs the two `ExecReload` lines in order. It sends SIGHUP only if `config check` passes, and the proxy reloads the configuration file and switches to the new configuration without stopping (see "SIGHUP (Configuration Reload)" in the [operator reference](../operations/operator-reference.md)).
  - With a configuration that `config check` rejects, SIGHUP is not sent and `systemctl reload` returns a failure.
  - When `config check` passes, `systemctl reload` returns success as soon as it sends SIGHUP and does not wait for the reload to complete. When only the running proxy refuses the configuration (a difference in a setting key that cannot change while running, an upstream engine that is not running, or binding a new listener), `systemctl reload` still returns success. Check the result in the log lines `reload: configuration replaced <SHA-256>` (with a configuration that has `managed`, ` managed <version>` follows) and `reload: configuration refused: <reason>`, and in `tukuyomi_config_reloads_total` of `/metrics`.
  - While `config check` rejects the chosen generation, `systemctl reload` is also refused (the reload itself does not touch generations).
- To change the configuration: rewrite the file (write it under another name and rename it over the old file), run `systemctl reload tukuyomi-core.service`, and check the result in the log lines. If you changed a setting key that cannot change while running, restart with `systemctl restart`. The admin process and the records shipper do not reload the configuration, so restart them when you change a setting key that they read.
- Replacement order: when you replace an earlier version that stopped on SIGHUP, install the new executable and restart first, and then change `ExecReload` in the unit and run `systemctl daemon-reload` (you may also change both and then restart). If you run `systemctl reload` with the new unit while still on the earlier version, the earlier version stops on SIGHUP. It stops with exit 0, so `Restart=on-failure` does not restart it.
- When you replace an earlier version that does not support choosing per engine, put the admin process, the proxy, and the records shipper on the same build. For the procedure and the order of replacement, see "Version Updates" in the [operator reference](../operations/operator-reference.md).
- To reload only the certificates and keys (SIGUSR2), send the signal as follows:

  ```bash
  systemctl kill -s SIGUSR2 --kill-whom=main tukuyomi-core.service
  ```

- To switch the rule set generation (SIGUSR1), send the signal as follows:

  ```bash
  systemctl kill -s SIGUSR1 --kill-whom=main tukuyomi-core.service
  ```

  SIGUSR1 switches each engine to its chosen generation, one engine at a time, in order. An engine that has a chosen generation but is not running is started (see "SIGUSR1 (Generation Switch)" in the [operator reference](../operations/operator-reference.md)).

- Place the log directory, the directory for the control socket, the admin store, and the managed store inside `ReadWritePaths` (under `/var/lib/tukuyomi-core` in the example above). If you place them elsewhere, add them to `ReadWritePaths`.
- Listening on ports 80 and 443 requires `CAP_NET_BIND_SERVICE`. The ambient capability is inherited by the inspector processes too, but an inspector process discards all capabilities at start.
- Make `LimitNOFILE` larger than the sum of the accepted connections (`max_conns`) and the connections to upstreams. Each connection uses a file descriptor.
- When the start is refused because of a configuration error or a similar problem, `Restart=on-failure` restarts it every `RestartSec`. Check the configuration with `config check` before you change it.

### Admin Process Unit

Run the admin process in a unit separate from the proxy. It uses the same executable, configuration file, and OS user as the proxy. Here is an example unit.

```ini
# tukuyomi-core-admin.service
[Unit]
Description=tukuyomi-core admin
After=network.target

[Service]
Type=notify
User=tukuyomi
Group=tukuyomi
ExecStart=/opt/tukuyomi-core/bin/tukuyomi-proxy admin /etc/tukuyomi-core/config.json
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=60
LogRateLimitIntervalSec=0
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/tukuyomi-core

[Install]
WantedBy=multi-user.target
```

- Use `Type=notify`. The admin process sends `READY=1` after it binds the listener, and `STOPPING=1` when it begins to stop.
- Use `KillMode=mixed`. The admin process starts inspector processes for rule import trials. If the SIGTERM that stops it reaches only the main process, the admin process finishes the running trial and cleans up the inspector process and the work directory.
- When the admin process receives a stop signal (SIGTERM, SIGINT, or SIGHUP), it closes the listener and waits up to 10 seconds for requests in progress. Make `TimeoutStopSec` longer than these 10 seconds. In case an import trial is running, also add the time it takes to stop its inspector process (`proxy.stop_inspect_ms` and `kernel.kill_grace_ms`).
- Specify `LogRateLimitIntervalSec=0`. The audit log is also written to standard error (the journal), so this keeps it from being lost to journald's rate limit.
- Use the same inspector executable (`kernel.inspector`; `kernel.engines` for ModSecurity generations) and work directory (`kernel.tmp_root`) as the proxy. The inspector process started for an import trial also restricts its own privileges with Landlock, just as under the proxy.
- The admin process listens with plain HTTP on the loopback address in `admin.listen`. With a port of 1024 or higher, `AmbientCapabilities` is not needed.
- The admin process reads the configuration file only once, at start (unlike the proxy, it does not reload on SIGHUP). After you change the configuration, check it with `config check` and then restart with `systemctl restart`. Do not set `ExecReload` (for the admin process, SIGHUP is a stop signal).
- The admin process starts even if the proxy is not running. While the proxy is not running, it cannot ask for a generation switch or for the managed configuration to be applied.
- To use it from outside, forward from a route of the proxy's TLS listener to the address in `admin.listen`. `admin.listen` can be specified as an upstream server. With a configuration that has `managed`, forward with `admin.route` instead of a route, and `admin.listen` cannot be specified as an upstream server (see "`admin`" in the [operator reference](../operations/operator-reference.md)). For how to write the route, see "Access from Outside" in the [admin reference](../operations/admin-reference.md); the same document covers how to use the screens and the API.
- Logs go to the journal. The audit log is also written to `audit/` in the admin store.

### Records Shipper Unit

If you ship logs to a DB, run the records shipper in a unit separate from the proxy. It uses the same configuration file and OS user as the proxy. Here is an example unit.

```ini
# tukuyomi-core-records-ship.service
[Unit]
Description=tukuyomi-core records shipper
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=tukuyomi
Group=tukuyomi
ExecStart=/opt/tukuyomi-core/bin/tukuyomi-records-ship /etc/tukuyomi-core/config.json
KillSignal=SIGTERM
TimeoutStopSec=150
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/tukuyomi-core

[Install]
WantedBy=multi-user.target
```

- Use `Type=notify`. The records shipper sends `READY=1` after it finishes its checks at start, and `STOPPING=1` when it begins to stop. It connects to the DB after `READY=1`. When it cannot connect to the DB, it waits and retries, so you do not need to order it after the DB unit.
- Make `TimeoutStopSec` long. The stop signal is not handled until the DB call finishes, so stopping can take as long as 1 to 2 minutes. Even if the timeout is shorter and the process ends with SIGKILL, the lines and the position are written to the DB in the same transaction, so the next start continues from where it left off.
- Place the log directory (where `ship.state` is written) inside `ReadWritePaths`.
- If the DB refuses the login, the records shipper ends with exit 1, and `Restart=on-failure` restarts it every `RestartSec`. It repeats this until you fix the connection string.
- If the DB server's certificate was issued by your own certificate authority, pass a file that contains that authority's certificate with `Environment=SSL_CERT_FILE=<path>`.
- The records shipper reads the configuration file and the connection string file only once, at start (unlike the proxy, it does not reload on SIGHUP). After you change them, restart with `systemctl restart`. Do not set `ExecReload` (for the records shipper, SIGHUP is a stop signal).
- The records shipper reads the same configuration file as the proxy, and rejects a configuration file that contains an unknown setting key. Before you write a new setting key (`managed`, `host_policies`, `kernel.default_engine`, the upstream `engine`, and so on) in the configuration, replace the records shipper executable with the same build as the proxy. If it stays on the previous build, the records shipper rejects the configuration at the next start and does not start (see "Starting the Records Shipper" in the [operator reference](../operations/operator-reference.md)).
- The records shipper starts even if the proxy is not running, and ships the logs that are in the files. The proxy shows that the records shipper is not running (`ship.state` is older than 90 seconds) by refusing requests to `required` routes.
- The logs of the records shipper go to the journal.

### Certificate Renewal Timer

Here is an example that runs `acme renew` every day.

```ini
# tukuyomi-core-acme.service
[Unit]
Description=tukuyomi-core certificate renewal (ACME)
After=network-online.target tukuyomi-core.service
Wants=network-online.target

[Service]
Type=oneshot
User=tukuyomi
Group=tukuyomi
ExecStart=/opt/tukuyomi-core/bin/tukuyomi-proxy acme renew /etc/tukuyomi-core/config.json
ExecStopPost=+/bin/systemctl kill --kill-whom=main -s SIGUSR2 tukuyomi-core.service
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/tukuyomi-core
```

```ini
# tukuyomi-core-acme.timer
[Unit]
Description=Daily tukuyomi-core certificate renewal

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

- A running proxy does not notice that the command wrote certificates, so the unit sends SIGUSR2 after the command, and the proxy loads the new certificates.
  - `systemctl reload` is not used because SIGHUP loads the whole configuration file. The unit sends SIGUSR2 instead, which loads only the certificates and keys, so a timer run never loads a half-edited configuration.
- `ExecStopPost` runs even if the command fails. If even one certificate ends up `failed`, the command ends with exit 1, but SIGUSR2 is still sent, so the other certificates that were renewed go into use. The file of a `failed` certificate is left as it was, and SIGUSR2 replaces certificates only when all the certificates it loads pass the check, so it is safe to send it after a failure.
- The `+` at the start of `ExecStopPost` runs `systemctl kill` as root. The command itself runs as the OS user of the service.
- If you have a unit that sends SIGUSR2 with `ExecStartPost=+`, change that line to the `ExecStopPost=+` line above and run `systemctl daemon-reload`. `ExecStartPost` runs only when the command ends with exit 0, so a single `failed` certificate keeps the other renewed certificates out of use until SIGUSR2 or SIGHUP is next sent.
- Do not run two `acme renew` processes with the same configuration at the same time. Nothing prevents concurrent runs. systemd timers do not overlap, but if you run it from cron or a similar tool, make sure the runs do not overlap.
- When you apply a managed configuration version that changes the hosts of an ACME site, run this service with `systemctl start tukuyomi-core-acme.service` without waiting for the timer (see "ACME Sites" in the [operator reference](../operations/operator-reference.md)).
- For how to issue the first certificates, see "ACME" in the [operator reference](../operations/operator-reference.md).

## Restricting the Inspector Processes

At start, an inspector process restricts its own privileges in the following order. Every restriction applies to all threads of the process and cannot be undone.

1. It reads the rule set generation. If it cannot read it, it ends with exit 11. It cannot read the manifest of another engine's generation either, so in that case, too, it ends with exit 11.
   - The Coraza inspector process does not read files after this.
   - The ModSecurity inspector process copies the verified files into the per-start temporary directory (exit 14 if it cannot copy them). After the restriction is applied, it builds the rules from this copy and reads only this copy.
2. It builds the Landlock rule set.
   - It makes files outside the per-start temporary directory (which is created inside the work directory) inaccessible. Other directories inside the work directory are also inaccessible.
   - Inside the temporary directory, only creating, writing, reading, truncating, and deleting files are allowed. Creating and listing directories, renaming files out of the temporary directory, and running programs are not possible.
   - On Linux 6.7 or later (ABI 4 or later), TCP bind and connect are also prohibited.
3. It discards the capabilities (empties the ambient set and sets effective, permitted, and inheritable to 0).
4. It sets `no_new_privs`.
5. Finally, it enables Landlock. From this point on, the restrictions from step 2 take effect.

If any of steps 2 to 5 fails, the inspector process does not start (exit 14). After this, it checks and builds the rules with that generation's engine (Coraza or ModSecurity) and starts accepting requests. If checking or building the rules fails, it ends with exit 11. The ModSecurity inspector process ends with exit 14 on an environment problem such as the library not being ready.

Some things cannot be restricted.

- Landlock does not restrict UDP, Unix domain sockets, or MPTCP sockets (those created with `IPPROTO_MPTCP`), so the inspector process can still use them to send data to the outside and to listen on ports 1024 and above.
- On a host that does not use MPTCP, setting `net.mptcp.enabled=0` makes it impossible to create MPTCP sockets.
- Ports below 1024 cannot be used because the capabilities are discarded (when Linux's `net.ipv4.ip_unprivileged_port_start` is the default 1024).

The proxy itself is not restricted this way. It reads the configuration, the rules store, and the certificates and keys, and holds the listeners and the connections to upstreams. The admin process does not apply this restriction to itself either. Only the inspector process started for an import trial applies the restriction above.

## Checks Before Start

Proxy start, `rules import` (which starts an inspector process for the trial), and the admin process commands (`admin <config>`, `admin bootstrap`, and `admin reset`) also check the following conditions by reading `/proc`, and refuse if they are not met. `config check` and the other commands check only that the process is not root.

- SIGCHLD is not ignored. The inspection kernel itself waits for its child processes to exit.
- All file descriptors greater than 2 are close-on-exec. This keeps unnecessary descriptors from being passed to the inspector processes.

Both conditions are met when you start from systemd.
