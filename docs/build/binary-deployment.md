[English](binary-deployment.md) | [日本語](binary-deployment.ja.md)

# Build and Deployment

This document explains how to run the current implementation on a single Linux host. For the meaning and range of the setting keys, commands, signals, logs, and monitoring, see the [operator reference](../operations/operator-reference.md); for the settings and API of the admin process, see the [admin reference](../operations/admin-reference.md).

The paths in this document (`/opt/tukuyomi-core`, `/etc/tukuyomi-core`, `/var/lib/tukuyomi-core`) and the OS user name (`tukuyomi`) are examples. Write every path in the configuration as an absolute path (a path that contains `.`, `..`, an empty element, or a trailing `/` is rejected).

## Components

| Component | Content |
|---|---|
| `tukuyomi-proxy` (Rust, `proxy/`) | Receives HTTP/HTTPS requests and forwards them. It embeds the inspection kernel (`kernel/`, a Rust library) and starts, stops, and restarts the inspector processes. The same executable also provides the rules store commands (`rules`), the certificate command (`acme renew`), the configuration check (`config check`), and the admin process (`admin`) |
| `tukuyomi-inspector` (Go, `inspector/`) | Inspects requests with Coraza. The proxy starts it as a child process, and the two communicate over an inherited pair of Unix domain sockets. It has no listening port. Specify it with `kernel.inspector` in the configuration |
| `tukuyomi-inspector-modsecurity` (Rust and C++, `inspector-modsecurity/`) | Inspects requests with ModSecurity v3 (libmodsecurity 3.0.17). It is needed only when you use a ModSecurity generation (`rules import --engine modsecurity`) or when you set `modsecurity` as the default engine or an upstream engine, and hosts that do not use it can omit it. The proxy starts it as a child process, and the two communicate over an inherited pair of Unix domain sockets. It has no listening port. Specify it with `kernel.engines.modsecurity.inspector` in the configuration |
| `tukuyomi-records-ship` (Rust, `records-ship/`) | The records shipper. It ships the lines of the proxy's log files to a PostgreSQL or MySQL table. It is needed only when you ship logs to a DB, and hosts that do not ship logs can omit it. It runs in a unit separate from the proxy and reads the same configuration file. It has no listening port |
| Admin process | `tukuyomi-proxy admin <config>`, the same executable. Run it in a unit separate from the proxy. It listens on a loopback address and provides the admin API and the admin screens (already embedded in the executable). It operates on rule generations and asks the proxy to switch them through the control socket |
| Configuration file | A single JSON file. Values have no defaults. Write every setting key except those that are defined as omittable (`acme`, `records`, `access`, `rate_limit`, `geo`, `admin`, and others). The proxy and the admin process read the same file |
| Rules store | The directory that holds the generations of rule sets (`rules.store.dir` in the configuration). `rules import` creates generations, and `rules activate` chooses the generation to use for each engine (Coraza or ModSecurity). The admin process performs the same operations |
| Inspector work directory | The parent directory in which a temporary directory is created at each start (`kernel.tmp_root` in the configuration) |
| Certificates and keys | Used by the TLS listeners. Either issue and renew them with `acme renew` or have the operator place them |
| Log directory | The directory that holds copies of the logs written to standard error (`records.dir` in the configuration). The proxy writes to it, and the admin process and the records shipper read it. The records shipper also writes the shipped position (`ship.state`) here |
| Connection string file | A file that holds the string (including the password) that the records shipper uses to connect to the DB (`records.ship.db_dsn_file` in the configuration). Only the records shipper reads it |
| Admin store | The directory in which the admin process keeps users, API tokens, the audit log, and the switch history (`admin.store.dir` in the configuration) |
| Control socket | The Unix domain socket on which the proxy receives requests from the admin process (`admin.control` in the configuration) |
| Country database | A file in MaxMind DB format, used for the country lists of access control (`access`) (`geo.country_db` in the configuration). The operator provides it |

The inspector processes, the admin process, and the records shipper run as the same OS user as the proxy.

## Requirements

- Linux. Operation has been confirmed on x86_64 only.
- Linux with Landlock enabled.
  - An inspector process restricts its own privileges with Landlock after it reads the rules (see "Restricting the Inspector Processes" below).
  - On a Linux without Landlock, the inspector process does not start (exit 14). The proxy does not start either (the log shows `stop: the kernel failed: Exit(14)`), and the trial of `rules import` and the trial of an import by the admin process both fail. There is no setting that runs without the restriction.
  - You need Linux 5.13 or later, which includes Landlock, and `landlock` must be in the LSM list (you can check it in `/sys/kernel/security/lsm`). Which distributions enable Landlock by default has not been checked.
  - The range that can be restricted depends on the Linux version. You cannot tell from the outside which ABI version was used for the restriction.
    - Restricting TCP bind and connect requires Linux 6.7 or later (Landlock ABI 4 or later). On earlier versions, the process runs with a file-only restriction.
    - On Linux earlier than 6.2 (ABI 1 and 2), truncating files cannot be prohibited. On Linux earlier than 6.10 (up to ABI 4), device ioctls cannot be prohibited.
- The only shared libraries needed on a host that runs the ModSecurity inspector process are libstdc++, libgcc_s, libc, and libm. libmodsecurity, YAJL, and PCRE2 are statically linked into the executable, so you do not need to install them.
- At any time, one proxy and one inspector process for each started engine are running (the admin process and the records shipper are separate processes).
  - With Coraza only, there is one inspector process; if both Coraza and ModSecurity are started, there are two.
  - While the generation of an engine is being switched, the inspector processes of that engine temporarily increase by one. Only one switch can run at a time across the whole proxy.
  - For each import trial, the admin process starts one inspector process (the `rules import` command does the same).
  - For a guide to memory use, see "Choosing the Inspection Engine" in the [operator reference](../operations/operator-reference.md).
- What the build needs:
  - Rust 1.94.1 or later (`rust-version` in `proxy/Cargo.toml`)
  - A C compiler (aws-lc-rs, which is used for TLS, builds C code)
  - Go 1.27.2 (`inspector/go.mod`). The inspector process reports the Go version used for the build to the inspection kernel. The inspection kernel accepts only an inspector built with `go1.27.2`.
- Only when you build the ModSecurity inspector process, you also need the following:
  - `rustc` exactly 1.94.1 (the `release:` line of `rustc -vV` is `1.94.1`). Unlike the proxy, the inspection kernel rejects an inspector process built with a different version (see "ModSecurity Inspector" below).
  - C and C++ compilers, and make
  - libyajl-dev and libpcre2-dev (the static libraries `libyajl_s.a` and `libpcre2-8.a`)
  - bash, curl, sha256sum, and tar (used to fetch libmodsecurity; curl is not needed if you pass the archive with `BUILD_MODSECURITY_ARCHIVE_FILE`)
- What fetching the CRS needs: bash, curl, sha256sum, and tar
- Needed only when you ship logs to a DB:
  - A PostgreSQL or MySQL server. Operation has been confirmed with PostgreSQL 16 and 18 and MySQL 8.0.
  - The file system of the log directory must return the file creation time (btime of `statx`). Operation has been confirmed on ext4 only.

## Release Tarball

Since 0.1.0, GitHub releases have distributed a tarball of executables for Linux x86_64. Use it if you do not build from source.

| File | Content |
|---|---|
| `tukuyomi-core_v0.2.0_linux_amd64.tar.gz` | In the directory `tukuyomi-core_v0.2.0_linux_amd64/`: the four executables (see "Components" above), `README.md`, `README.ja.md`, `LICENSE`, `NOTICE`, `THIRD-PARTY-LICENSES`, `docs/`, and `scripts/fetch-crs.sh` |
| `tukuyomi-core_v0.2.0_linux_amd64.tar.gz.sha256` | The SHA-256 of the tarball |
| `tukuyomi-core_v0.2.0_SHA256SUMS` | The same line as the file above |

- After downloading, check the SHA-256 before extracting.

  ```bash
  sha256sum -c tukuyomi-core_v0.2.0_linux_amd64.tar.gz.sha256
  tar -xzf tukuyomi-core_v0.2.0_linux_amd64.tar.gz
  ```

- The executables were built on Ubuntu 26.04.1 LTS (glibc 2.43, gcc 15.2.0) with `rustc` 1.94.1 and Go 1.27.2. Operation has been confirmed only on the host where they were built.
- The host that runs them needs glibc 2.39 or later (`tukuyomi-proxy` uses `GLIBC_2.39` symbols). The ModSecurity inspector process also needs the libstdc++ symbols `GLIBCXX_3.4.29` and `CXXABI_1.3.15`. They do not run on an older Linux, so build from source (see "Building from Source" below).
- The inspector process (`tukuyomi-inspector`) is statically linked. The TLS library (aws-lc) is also statically linked into the executable.
- Place the executables in, for example, `/opt/tukuyomi-core/bin/`. The following steps are the same as for a build from source (see "OS User and Directories" and "First Start" below).

## Building from Source

Build the proxy in `proxy/`. The inspection kernel is built together with it.

```bash
cd proxy && cargo build --release --locked
```

The executable is produced at `proxy/target/release/tukuyomi-proxy`. This build embeds the files of the admin screens (`proxy/admin-ui/`) in the executable. No separate build or distribution is needed for the screens.

Build the inspector process in `inspector/` without cgo.

```bash
cd inspector && CGO_ENABLED=0 go build -mod=readonly -o tukuyomi-inspector .
```

Always specify `CGO_ENABLED=0`.

- To apply Landlock and other restrictions to all threads, the inspector process uses Go's `syscall.AllThreadsSyscall`. In an executable that uses cgo, this call returns `ENOTSUP`, so the inspector process does not start (exit 14).
- The reason it does not start (`the inspector is built with cgo and cannot restrict every thread`) does not appear in the standard output or standard error of the inspector process. It appears only in the `the inspector said:` line of `rules import` and in the `reload: the inspector said:` line when a SIGUSR1 switch fails. When the proxy starts, only the line `stop: the kernel failed: Exit(14)` appears.

### ModSecurity Inspector

Build it only when you use ModSecurity generations. Hosts that use only Coraza generations do not need it. First build libmodsecurity (ModSecurity v3.0.17) as a static library in a new directory (the prefix), then build the inspector process with that prefix specified.

```bash
scripts/build-modsecurity.sh <new-dir>
cd inspector-modsecurity && TUKUYOMI_MODSECURITY_PREFIX=<new-dir> cargo build --release --locked
```

The executable is produced at `inspector-modsecurity/target/release/tukuyomi-inspector-modsecurity`.

`scripts/build-modsecurity.sh` behaves as follows:

- The version to fetch (3.0.17) and the sha256 of the distribution archive (`modsecurity-v3.0.17.tar.gz`) (`f283b33d5c21130fd3a15c84a93a1abe12bd1949edaf44288b12af571b671a50`) are fixed inside the script. You cannot change them with arguments.
- The archive is fetched over https only, and its contents are read only after it matches the fixed sha256. On a host that cannot connect to GitHub, you can pass a copy of the fixed archive with `BUILD_MODSECURITY_ARCHIVE_FILE`. The sha256 and other checks are the same in that case.
- The new directory must be an absolute path that does not exist yet, written with only letters, digits, `.`, `_`, `+`, and `-`. A name that starts with `.` cannot be used. A relative path is treated as a path from the current directory.
- The parent directory of the new directory must already exist and be writable by the OS user that runs the script. The script creates a temporary directory next to it and places the new directory with a single rename at the end.
- It does not touch an existing directory. If it fails midway, nothing is left behind.
- It takes a few minutes.
- configure runs with flags that are fixed in this script. It does not use curl, Lua, MaxMind, GeoIP, libxml2, LMDB, or ssdeep, and uses only YAJL and PCRE2. If the result of configure is not so, the script exits with an error. This is part of the protection that keeps rules from using features such as importing rules from outside, running scripts, referencing databases, and parsing XML, so do not change it.
- The prefix gets `include/`, `lib/libmodsecurity.a`, `include-src/` (the internal headers of libmodsecurity), and `archive.sha256` (one line with the sha256 of the fixed archive).

In the following cases, building the inspector process ends with an error:

- `TUKUYOMI_MODSECURITY_PREFIX` is missing or is not an absolute path
- The prefix lacks any of `include/modsecurity/modsecurity.h`, `include-src/src/variables/variable.h`, and `lib/libmodsecurity.a`
- `archive.sha256` in the prefix cannot be read, or is not one line of 64 lowercase hexadecimal digits
- The C++ compiler cannot find `libpcre2-8.a` (libpcre2-dev) or `libyajl_s.a` (libyajl-dev)

The inspector process reports the version of the compiler used for the build, the libmodsecurity version, and the archive sha256 to the inspection kernel in the first message at start (HELLO). For a ModSecurity inspector process, the inspection kernel accepts only one in which all three of the following match:

| Field | Accepted value |
|---|---|
| The compiler used for the build | `rustc 1.94.1` |
| The libmodsecurity version | `v3.0.17` |
| The archive sha256 | `f283b33d…b671a50` above |

If they do not match, the inspection kernel writes one of `hello toolchain differs`, `hello engine version differs`, and `hello engine source differs`, rejects the inspector process, and does not restart it. At proxy start the line `stop: the kernel failed: Hello("<message>")` appears, and with `rules import` the line `rules import: the trial failed: the inspector could not be started (Hello("<message>"))` appears.

### Records Shipper

Build it only when you ship logs to a DB. Build it in `records-ship/`. The proxy library is built together with it.

```bash
cd records-ship && cargo build --release --locked
```

The executable is produced at `records-ship/target/release/tukuyomi-records-ship`. The requirements are the same as for the proxy (Rust 1.94.1 or later and a C compiler).

### Fetching the CRS

The CRS (OWASP Core Rule Set) is not bundled. Fetch it with `scripts/fetch-crs.sh`. Run it as the OS user of the service. The CRS is distributed under the Apache License 2.0. The script extracts only the rule files and does not extract the `LICENSE` of the archive.

```bash
sudo -u tukuyomi scripts/fetch-crs.sh /var/lib/tukuyomi-core/crs-4.23.0
```

- The version to fetch (4.23.0) and the sha256 of the distribution archive are fixed inside the script. You cannot change them with arguments.
- The archive is fetched over https only, and its contents are read only after it matches the fixed sha256. On a host that cannot connect to GitHub, you can pass a copy of the fixed archive with `FETCH_CRS_ARCHIVE_FILE`. The sha256 and other checks are the same in that case.
- The new directory contains only the following four:
  - `crs-setup.conf` (a copy of `crs-setup.conf.example`)
  - `crs-setup.conf.example`
  - `rules/*.conf`
  - `rules/*.data`
- The script runs with `umask 077`. The directory and files it creates can be read only by the OS user that ran it. If you run it as root, `rules import` run by the OS user of the service cannot read them.
- The parent directory of the new directory must already exist and be writable by the OS user that runs the script. The script creates a temporary directory next to it.
- It does not touch an existing directory. If it fails midway, nothing is left behind.
- The operator can edit `crs-setup.conf` before the import. For example, you can add the body types that are accepted (see "Rule Sets and Generations" in the [operator reference](../operations/operator-reference.md)).

## OS User and Directories

The proxy does not run as root. If any of the four user IDs of the process (real, effective, saved, file system) is 0, the proxy at start and every command write a `host check refused` line and refuse (exit 1).

- Create a dedicated OS user and run both the service and the commands as that OS user. For example, use `sudo -u tukuyomi tukuyomi-proxy ...`.
- `acme renew` run as root is also refused, because the proxy running as another OS user cannot read the keys it creates.
- Run the admin process (`admin`) and its short commands (`admin bootstrap` and `admin reset`) as the same OS user. This is because the rules store, the log directory, the control socket, and the managed store can be used only by that OS user (0700). None of them can be used if you run as a different OS user.
- Run the records shipper as the same OS user too, because it reads the log directory and writes `ship.state` there. The records shipper does not run as root either.

Examples of directories and files:

| Example | Setting key | Owner and permissions |
|---|---|---|
| `/opt/tukuyomi-core/bin/tukuyomi-proxy`, `/opt/tukuyomi-core/bin/tukuyomi-inspector` | `kernel.inspector` (for the Coraza inspector process) | root. Place them where the OS user of the service cannot modify them |
| `/opt/tukuyomi-core/bin/tukuyomi-inspector-modsecurity` | `kernel.engines.modsecurity.inspector` (for the ModSecurity inspector process; can be omitted) | root. Place it where the OS user of the service cannot modify it |
| `/opt/tukuyomi-core/bin/tukuyomi-records-ship` | (the records shipper unit; can be omitted) | root. Place it where the OS user of the service cannot modify it |
| `/etc/tukuyomi-core/config.json` | (the start argument) | root. The OS user of the service must be able to read it. The size is up to 256 KiB |
| `/var/lib/tukuyomi-core/store` | `rules.store.dir` | The OS user of the service. Permissions 0700 |
| `/var/lib/tukuyomi-core/tmp` | `kernel.tmp_root` | The OS user of the service. Permissions 0700. Do not set setgid |
| `/var/lib/tukuyomi-core/managed` | `managed.dir` (when you use the managed configuration) | The OS user of the service. Permissions 0700. The commands, the admin process, and `acme renew` create `versions/`, `files/`, `acme/`, and the others inside |
| `/var/lib/tukuyomi-core/tls/` | `cert_file` and `key_file` of the certificates used by the listeners and by the admin route (`admin.route`) | The OS user of the service (`acme renew` writes them). The certificates of the ACME sites of the managed configuration are in `acme/` of the managed store |
| `/var/lib/tukuyomi-core/acme/account.key` | `acme.account_key_file` | `acme renew` creates it on the first run (0600) |
| `/var/lib/tukuyomi-core/challenges` | `acme.challenge_dir` | The OS user of the service. Use a directory dedicated to challenges |
| `/var/lib/tukuyomi-core/records` | `records.dir` | The OS user of the service. Permissions 0700. The proxy creates `records.log` and the other files inside, and the records shipper creates `ship.state`, all with 0600 |
| `/etc/tukuyomi-core/records-db.dsn` | `records.ship.db_dsn_file` (when you use the records shipper) | The owner is the OS user of the service, and the permissions are 0600. Unlike the configuration file, the owner is not root (the records shipper checks the owner and permissions) |
| `/var/lib/tukuyomi-core/admin` | `admin.store.dir` (the admin store) | The OS user of the service. Permissions 0700. The admin process creates `users/`, `tokens/`, `audit/`, and the others inside |
| `/var/lib/tukuyomi-core/control` | The directory in which `admin.control` is placed (the example socket is `/var/lib/tukuyomi-core/control/proxy.sock`) | The OS user of the service. Permissions 0700. The proxy creates the socket with 0600. The socket path is up to 107 bytes |
| `/var/lib/tukuyomi-core/crs-4.23.0` | `admin.crs_dir` (when you import the CRS through the admin API) | The directory created in "Fetching the CRS". The OS user of the service must be able to read it |
| `/etc/tukuyomi-core/country.mmdb` | `geo.country_db` | root. Make it readable by the OS user of the service and not modifiable by it (0644). The proxy does not check the owner and permissions |

- Write `kernel.inspector` in the configuration even on a host that uses ModSecurity generations only (it is a setting key that cannot be omitted). Write `kernel.engines` only when you use ModSecurity generations. Without it, a ModSecurity generation can be neither imported nor chosen, and the proxy rejects it at start as well (see "`kernel`" in the [operator reference](../operations/operator-reference.md)). When you set `kernel.default_engine` to `modsecurity`, you still write `kernel.inspector` (and `kernel.engines` is also needed).
- Create the directories in the table above beforehand. Neither the proxy nor the commands create them. The commands and the proxy create what is inside the rules store (`generations/`, `staging/`, `using/`, and so on); the commands, the admin process, and `acme renew` create what is inside the managed store; the admin process creates what is inside the admin store; and the proxy creates the log files and the control socket.
- Use separate directories for the rules store, the log directory, the admin store, the directory for the control socket, the managed store, and `challenge_dir`. They cannot be the same directory or be placed inside one another (the configuration is rejected). In the example in the table above, they are all separate directories under `/var/lib/tukuyomi-core`. Overlap is judged by comparing the paths as written, so do not use symbolic links.
- The unit in the "systemd" example below makes the directories under it writable with `ReadWritePaths=/var/lib/tukuyomi-core`. If you also place the managed store under it, you do not need to change the unit. If you place it elsewhere, add it to `ReadWritePaths`.
- For the rules store, the work directory, the log directory, the admin store, the directory for the control socket, and the managed store, the following are checked: it is a directory and not a symbolic link, it is owned by the OS user of the process, and it has no permissions for the group and other users. The timing of the checks differs for each directory.
  - The rules store is checked at proxy start, in `config check` and in the `rules` commands. It is also checked when the admin process opens it. If the conditions are not met, the operation is refused with exit 1.
  - The managed store is checked every time it is opened (proxy start and configuration reload, `config check`, the `managed` commands, `acme renew`, and the admin process). If the conditions are not met, it is rejected (proxy start and `config check` end with exit 1).
  - The work directory is checked every time an inspector process is started (proxy start, restart of an inspector process, a SIGUSR1 switch, and the trial of `rules import`). If the conditions are not met, the inspector process does not start. At proxy start the proxy ends with exit 1, a SIGUSR1 switch keeps the current generation running, and on a restart the proxy stops.
  - The log directory is checked at proxy start. If the conditions are not met, the proxy does not start (exit 1). It is also checked before the log file is reopened and before rotation.
  - The directory for the control socket is checked at proxy start. If the conditions are not met, the proxy does not start (exit 1).
  - The admin store is checked at admin process start and in `admin bootstrap` and `admin reset`. If the conditions are not met, they refuse with exit 1.
  - `config check` and `acme renew` do not check the work directory. `config check` does not check the log directory, the directory for the control socket, or the admin store either.
- The parent directories of the directories above are not checked. It is the operator's responsibility to prevent other OS users from creating or replacing names inside them.
- If setgid is set on the work directory, the directories created inside it inherit that attribute and fail the permission check, so the inspector process cannot start.
- `acme renew` writes the certificate, key, and challenge files as temporary files in their respective directories (for an ACME site, inside `acme/` of the managed store) and then replaces the targets. The OS user of the service must be able to write to these directories.
- If you run a command as an OS user that cannot read the configuration file, the configuration is rejected at the stage of reading it. If you run it as an OS user different from the owner of the rules store or the managed store, it is rejected at the stage of opening each of them.

### Country Database

Needed only when you use country lists (`deny_countries` and `allow_countries` of the global `access`, of the `access` of `host_policies`, and of the `access` of a route).

- The database is not bundled with the proxy, and the proxy does not fetch it. The operator provides a file in MaxMind DB format (version 2). The operator must follow the license terms of the provider.
- Location and permissions: make the owner root, and make the file readable by the OS user of the service and not modifiable by it (0644). An example is `/etc/tukuyomi-core/country.mmdb`. The proxy does not check the owner and permissions, and verifies the contents with `geo.sha256`. Do not make it a symbolic link (it is rejected). The size is up to 256 MiB.
- Every command that reads the whole configuration (proxy start and reload, `config check`, `acme renew`, `managed import`, and `managed activate`) reads the whole of this file as the OS user of the service. A command run as an OS user that cannot read this file is rejected at the stage of reading the configuration. The `rules` and `admin` commands, the admin process, and the records shipper do not read this file.
- When country lists exist, the proxy keeps the whole verified file in memory. A command that reads it verifies the whole file each time, so a large file costs time and memory.
- Compute the SHA-256 of the file and write it in `geo.sha256` in the configuration. Every command rejects the configuration if the values do not match.

  ```bash
  sha256sum /etc/tukuyomi-core/country.mmdb
  ```

- To replace the database, place the new file under a different name, and rewrite `geo.country_db` and `geo.sha256` in the configuration in a single replacement. Check it with `config check`, and then have the proxy reload (`systemctl reload`). The proxy reads the database at start and at every reload. The admin process does not read the database.
- For the setting keys and how the country is determined (a private address, or an IPv6 address with an IPv4-only database, is `UNKNOWN`), see "Access Control and Rate Limits" in the [operator reference](../operations/operator-reference.md).

## First Start

If you write `managed` in the configuration file (you use the managed configuration), follow the procedure in "First Start with the Managed Configuration" in the [operator reference](../operations/operator-reference.md). For deciding whether to use the managed configuration, see "Whether to Use the Managed Configuration" in the same document. That procedure uses steps 2 to 4 and 7 below as they are.

1. Write the configuration file. For the list of setting keys and an example, see the [operator reference](../operations/operator-reference.md). Create the directories in the table above first. If you use country lists, also place the country database and write its `sha256` (see "Country Database" above).
2. Fetch the CRS (see "Fetching the CRS" above).
3. Import the rule set.

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules import /etc/tukuyomi-core/config.json --crs /var/lib/tukuyomi-core/crs-4.23.0 --detect-only
   ```

   - The import starts one inspector process and inspects three fixed requests (the trial). Only if the trial passes does it become a generation, and `<fingerprint> created` is written to standard output. If a generation with the same content already exists, `already exists` is written.
   - With `--detect-only`, the generation is in detect-only mode. Requests that match rules are also passed through and are recorded in the log. It is recommended to run in this mode first, check for false positives, and then switch to a generation in block mode.
   - With a generation in block mode, if even one of the trial requests is blocked, the trial fails and no generation is created. If you made the settings in `crs-setup.conf` stricter, for example, read the log and fix them, or add `--accept-block`.
   - To make a generation that is inspected by ModSecurity, add `--engine modsecurity`. You must specify the inspector process in `kernel.engines` in the configuration. The trial runs with the inspector process of that engine.
4. Choose the generation.

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules activate /etc/tukuyomi-core/config.json <fingerprint>
   ```

   - A generation is chosen for each engine. The first one to choose is the generation of the default engine (`kernel.default_engine` in the configuration; `coraza` if it is not written). If the default engine has no chosen generation, the proxy does not start.
   - To start with ModSecurity only, set `kernel.default_engine` in the configuration to `modsecurity` and choose a ModSecurity generation. If you choose only a ModSecurity generation without writing `kernel.default_engine`, `config check` and the proxy at start refuse with `rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine` (exit 1).
   - For the details of choosing per engine, see "Chosen Generation per Engine" in the [operator reference](../operations/operator-reference.md).
5. Check the configuration.

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
   ```

   - If it passes, `accepted` is written to standard output and it ends with exit 0.
   - If you run it before choosing a generation for the default engine, it is refused with `rules store refused: no generation is chosen` (exit 1). It is refused with the same message when an upstream engine has no chosen generation. An error in the configuration itself shows as exit 2, so you can also run it after step 1.
   - It also checks the upstream server names and the TLS certificate and key files. A rejection there also ends with exit 1, and you can tell the cases apart by the beginning of the line (`upstream refused`, `tls refused`).
   - It does not start an inspector process, so it does not check the work directory, the inspector executable, or Landlock.
6. Start the service (see "systemd" below).
7. If you use the admin process, also start its unit (see "Admin Process Unit" below) and create the first user.

   ```bash
   read -r -s -p 'password: ' PW; echo
   printf '%s\n' "$PW" | sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy admin bootstrap /etc/tukuyomi-core/config.json <name>
   unset PW
   ```

   - The password is read from the first line of standard input (12 to 128 bytes). Do not pass it as an argument. The name is 1 to 32 bytes of `a-z`, `0-9`, `.`, `_`, and `-`.
   - The role of the user it creates is `owner`. On success, `created owner <name>` is written. If the admin store already has even one user, it is refused (exit 1).
   - You can run it before or after the admin process starts. For a user who has forgotten the password, use `admin reset`.
   - For the admin API, roles and screens, see the [admin reference](../operations/admin-reference.md).
8. If you ship logs to a DB, prepare the DB user and the DB, and place the connection string file with the OS user of the service as its owner and with 0600. Write `records.ship` in the configuration and start the records shipper unit (see "Records Shipper Unit" below). The records shipper creates the table when it first connects. For the table permissions and the format of the connection string, see "Records Shipper" in the [operator reference](../operations/operator-reference.md).

## systemd

Here is an example of the service unit.

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
  - With the default `control-group`, the SIGTERM sent to stop also reaches the inspector processes.
  - An inspector process does not handle SIGTERM and exits on the spot. The proxy therefore cannot stop the inspector processes in order (finishing the remaining inspections and receiving the termination notice).
  - With `mixed`, SIGTERM reaches only the proxy. The proxy stops the inspector processes itself and then exits.
- Use `Type=notify`. The proxy sends `READY=1` to systemd after the inspection kernels of all the engines to be started are ready and all the listeners are bound, and sends `STOPPING=1` at the beginning of the stop. `systemctl start`, and units ordered after this unit with `After=`, wait until then. With `Type=simple`, the service is considered started as soon as it is executed.
  - Only the main process of the proxy sends the notifications. You can leave `NotifyAccess` at its default (`main`).
  - Make `TimeoutStartSec` longer than the sum of the upstream name resolution time (`resolve_timeout_ms`) and the time to wait for the inspection kernel to be ready (`ready_wait_ms`). If `READY=1` does not arrive, systemd stops the proxy after this time.
- Make `TimeoutStopSec` longer than the sum of `stop_wait_ms`, `kill_grace_ms`, and the 200 ms for writing out the logs. If it is shorter, systemd sends SIGKILL first. For the stop sequence, see "Stopping" in the [operator reference](../operations/operator-reference.md).
- Specify `LogRateLimitIntervalSec=0`. With the default rate limit of journald, request logs are lost without entering the journal when many requests arrive at once.
- Logs go to the journal. If the configuration has `records`, the same logs are also written to files (see "OS User and Directories" above). The retention period and size are set in the journald configuration (`SystemMaxUse`, `MaxRetentionSec`, and so on in `/etc/systemd/journald.conf`). The logs contain client addresses and paths, so keep the number of OS users in the groups that can read the journal (`adm` and `systemd-journal` on Ubuntu) to a minimum. For the log format, see "Logs" in the [operator reference](../operations/operator-reference.md).
- If you add a listener for monitoring (`status` in the configuration), a monitoring program on the same host can access `/healthz`, `/readyz`, and `/metrics`. Use `/readyz` for a load balancer's readiness check.
- Send signals only to the main process of the proxy (`$MAINPID` in `ExecReload`, or `systemctl kill --kill-whom=main`).
  - `systemctl kill` without `--kill-whom=main` also sends the signal to the inspector processes.
  - An inspector process ignores SIGUSR1 and SIGUSR2, but exits when SIGTERM, SIGINT, or SIGHUP arrives.
- `systemctl reload` runs the two `ExecReload` lines in order. It sends SIGHUP only if `config check` passes, and the proxy reloads the configuration file and switches to the new configuration without stopping (see "SIGHUP (Configuration Reload)" in the [operator reference](../operations/operator-reference.md)).
  - With a configuration that `config check` rejects, SIGHUP is not sent and `systemctl reload` returns a failure.
  - When `config check` passes, `systemctl reload` returns success at the moment it sends SIGHUP and does not wait for the reload to complete. When only the running proxy refuses the configuration (a difference in a setting key that cannot change while running, an upstream engine that is not running, or binding a new listener), `systemctl reload` still returns success. Check the result in the log lines `reload: configuration replaced <SHA-256>` (with a configuration that has `managed`, ` managed <version>` follows) and `reload: configuration refused: <reason>`, and in `tukuyomi_config_reloads_total` of `/metrics`.
  - While `config check` rejects the chosen generation, `systemctl reload` is also refused (the reload itself does not touch generations).
- To change the configuration: rewrite the file (write it under another name and swap it in with a single replacement), run `systemctl reload tukuyomi-core.service`, and check the result in the log lines. If you changed a setting key that cannot change while running, restart with `systemctl restart`. The admin process and the records shipper do not reload the configuration, so restart them when you change a setting key that they read.
- Order of replacement: when you replace an earlier version that stopped when it received SIGHUP, install the new executable and restart first, and then change `ExecReload` in the unit and run `systemctl daemon-reload` (you may also change both and then restart). If you run `systemctl reload` with the new unit while still on the earlier version, the earlier version stops on SIGHUP. It stops with exit 0, so `Restart=on-failure` does not restart it.
- When you replace an earlier version that does not support choosing per engine, bring the admin process, the proxy, and the records shipper to the same build. For the procedure and the order of replacement, see "Version Updates" in the [operator reference](../operations/operator-reference.md).
- To make it reload only the certificates and keys (SIGUSR2), send it as follows:

  ```bash
  systemctl kill -s SIGUSR2 --kill-whom=main tukuyomi-core.service
  ```

- To switch the generation of the rule set (SIGUSR1), send it as follows:

  ```bash
  systemctl kill -s SIGUSR1 --kill-whom=main tukuyomi-core.service
  ```

  SIGUSR1 switches to the chosen generation of each engine, one engine at a time in order. An engine that has a chosen generation but is not running is started (see "SIGUSR1 (Generation Switch)" in the [operator reference](../operations/operator-reference.md)).

- Place the log directory, the directory for the control socket, the admin store, and the managed store inside `ReadWritePaths` (under `/var/lib/tukuyomi-core` in the example above). If you place them elsewhere, add them to `ReadWritePaths`.
- Listening on ports 80 and 443 requires `CAP_NET_BIND_SERVICE`. The ambient capability is inherited by the inspector processes too, but an inspector process discards all capabilities at start.
- Make `LimitNOFILE` larger than the sum of the accepted connections (`max_conns`) and the connections to upstreams. Each connection uses a file descriptor.
- When the start is refused because of a configuration error or the like, `Restart=on-failure` restarts it every `RestartSec`. Check the configuration with `config check` before you change it.

### Admin Process Unit

Run the admin process in a unit separate from the proxy. The executable, the configuration file, and the OS user are the same as the proxy's. Here is an example of the unit.

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

- Use `Type=notify`. The admin process sends `READY=1` after it binds the listener and `STOPPING=1` at the beginning of the stop.
- Use `KillMode=mixed`. The admin process starts inspector processes for the trial of a rule import. If the SIGTERM sent to stop reaches only the main process, the admin process finishes the trial that is running and cleans up the inspector process and the work directory.
- When the admin process receives a stop signal (SIGTERM, SIGINT, or SIGHUP), it closes the listener and waits up to 10 seconds for requests in progress. Make `TimeoutStopSec` longer than these 10 seconds. To allow for an import trial that is running, also add the time to stop its inspector process (`proxy.stop_inspect_ms` and `kernel.kill_grace_ms`).
- Specify `LogRateLimitIntervalSec=0`. The audit log is also written to standard error (the journal), so this keeps it from being lost to the rate limit of journald.
- For the inspector executable (`kernel.inspector`; `kernel.engines` for ModSecurity generations) and the work directory (`kernel.tmp_root`), use the same ones as the proxy. The inspector process started for an import trial also restricts its own privileges with Landlock, as in the proxy's case.
- The admin process listens on the loopback address `admin.listen` with plain HTTP. With a port of 1024 or higher, `AmbientCapabilities` is not needed.
- The admin process reads the configuration file only once, at start (unlike the proxy, it does not reload on SIGHUP). After you change the configuration, check it with `config check` and then restart with `systemctl restart`. Do not set `ExecReload` (for the admin process, SIGHUP is a stop signal).
- The admin process starts even if the proxy is not running. In the meantime it cannot ask for a generation switch or for applying the managed configuration.
- To use it from outside, forward from a route of the proxy's TLS listener to the address in `admin.listen`. `admin.listen` can be specified as an upstream server. With a configuration that has `managed`, forward with `admin.route` instead of a route, and `admin.listen` cannot be specified as an upstream server (see "`admin`" in the [operator reference](../operations/operator-reference.md)). For how to write the route, see "Access from Outside" in the [admin reference](../operations/admin-reference.md); for how to use the screens and the API, see the same document.
- Logs go to the journal. The audit log is also written to `audit/` in the admin store.

### Records Shipper Unit

If you ship logs to a DB, run the records shipper in a unit separate from the proxy. The configuration file and the OS user are the same as the proxy's. Here is an example of the unit.

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

- Use `Type=notify`. The records shipper sends `READY=1` after it finishes its checks at start and `STOPPING=1` at the beginning of the stop. It connects to the DB after `READY=1`. It waits and retries when it cannot connect to the DB, so you do not need to order it after the DB unit.
- Make `TimeoutStopSec` long. The stop signal is not handled until the DB call finishes, so a stop can take 1 to 2 minutes at the longest. Even if the timeout is shorter and the process ends with SIGKILL, the lines and the position enter the DB in the same transaction, so the next start continues from where it left off.
- Place the log directory (where `ship.state` is written) inside `ReadWritePaths`.
- If the DB refuses the login, the records shipper ends with exit 1, and `Restart=on-failure` restarts it every `RestartSec`. It repeats this until you fix the connection string.
- If the certificate of the DB server was issued by your own certificate authority, pass the certificate file with `Environment=SSL_CERT_FILE=<path>`.
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

- The SIGUSR2 sent after the command makes the proxy load the new certificates. A running proxy does not detect that the command wrote certificates.
  - `systemctl reload` is not used because SIGHUP loads the whole configuration file. So that the timer does not load a configuration that is being edited when it runs, SIGUSR2, which loads only the certificates and keys, is sent.
- `ExecStopPost` runs even if the command fails. If even one certificate becomes `failed`, the command ends with exit 1, but SIGUSR2 is still sent, so the other certificates that were renewed start to be used. The file of a `failed` certificate stays as it was, and SIGUSR2 replaces certificates only when all the certificates it loaded pass the check, so there is no problem in sending it on a failure.
- The `+` at the beginning of `ExecStopPost` is a specification to run `systemctl kill` as root. The command itself runs as the OS user of the service.
- If you have a unit that sends SIGUSR2 with `ExecStartPost=+`, change that line to the `ExecStopPost=+` line above and run `systemctl daemon-reload`. `ExecStartPost` runs only when the command ends with exit 0, so with a single `failed`, the other certificates that were renewed are not used until the next time SIGUSR2 or SIGHUP is sent.
- Do not run two `acme renew` with the same configuration at the same time. There is no mechanism to prevent concurrent runs. systemd timers do not overlap, but if you run it from cron or the like, make sure the runs do not overlap.
- When you apply a version of the managed configuration in which the combination of hosts of an ACME site was changed, run this service with `systemctl start tukuyomi-core-acme.service` without waiting for the timer (see "ACME Sites" in the [operator reference](../operations/operator-reference.md)).
- For the procedure of the first issue, see "ACME" in the [operator reference](../operations/operator-reference.md).

## Restricting the Inspector Processes

At start, an inspector process restricts its own privileges in the following order. Every restriction is applied to all threads of the process in a form that cannot be undone.

1. It reads the generation of the rule set. If it cannot read it, it ends with exit 11. It cannot read the manifest of a generation of another engine either, so it likewise ends with exit 11.
   - The Coraza inspector process does not read files after this.
   - The ModSecurity inspector process copies the verified files into the temporary directory created for each start (if it cannot copy them, exit 14). After the restriction is applied, it builds the rules from this copy and reads only this copy.
2. It builds the Landlock rule set.
   - It makes the files outside the temporary directory created for each start (created inside the work directory) inaccessible. Other directories inside the work directory are also inaccessible.
   - What is allowed inside the temporary directory is only creating, writing, reading, truncating, and deleting files. Creating and listing directories, renaming to outside the temporary directory, and running programs are not possible.
   - On Linux 6.7 or later (ABI 4 or later), TCP bind and connect are also prohibited.
3. It discards the capabilities (empties the ambient set and sets effective, permitted, and inheritable to 0).
4. It sets `no_new_privs`.
5. Finally, it enables Landlock. From this point, the restrictions of step 2 take effect.

If any of steps 2 to 5 fails, the inspector process does not start (exit 14). After this, it checks and builds the rules with the engine of that generation (Coraza or ModSecurity) and starts accepting requests. If checking or building the rules fails, it ends with exit 11. The ModSecurity inspector process ends with exit 14 on an environment problem such as the library not being ready.

Some things cannot be restricted.

- Landlock does not restrict UDP, Unix domain sockets, or MPTCP sockets (those created with `IPPROTO_MPTCP`). The inspector process can therefore still use them to send data to the outside and to listen on ports 1024 and above.
- On a host that does not use MPTCP, setting `net.mptcp.enabled=0` makes it impossible to create MPTCP sockets.
- Ports below 1024 cannot be used because the capabilities are discarded (when Linux's `net.ipv4.ip_unprivileged_port_start` is the default 1024).

The proxy side is not subject to this restriction. The proxy reads the configuration, the rules store, and the certificates and keys, and holds the listeners and the connections to upstreams. The admin process also does not apply this restriction to itself. Only the inspector process started for an import trial applies the restriction above.

## Checks Before Start

Proxy start, `rules import` (which starts an inspector process for the trial) and the commands of the admin process (`admin <config>`, `admin bootstrap`, and `admin reset`) also check the following conditions by reading `/proc`. If the conditions are not met, they refuse. `config check` and the other commands check only that the process is not root.

- SIGCHLD is not ignored. The inspection kernel waits for the exit of its child processes itself.
- All file descriptors greater than 2 are close-on-exec. This keeps unnecessary descriptors from being passed to the inspector processes.

Both conditions are met when you start from systemd.
