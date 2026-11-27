# Chapter 3. Deployment with systemd

In Chapter 2, you started tukuyomi core by hand from a terminal. This chapter describes how to deploy it so that it keeps running as a systemd service on a single Linux host. For the steps of the first start, see Chapter 2.

This chapter covers the following:

- The requirements, and where to place the executables
- The OS user and the directories
- The four kinds of units (the proxy, the admin process, the records shipper, and the certificate renewal timer)
- The checks before start
- `systemctl reload`, and how to send signals
- How the inspector process restricts its own privileges

## 3.1 Deployment Overview

tukuyomi core runs as several processes with different roles. Under systemd, the proxy, the admin process, and the records shipper each run in their own unit. The inspector processes have no unit, because the proxy starts them as child processes.

| Component | Executable | When it is needed |
|---|---|---|
| Proxy | `tukuyomi-proxy` | Always |
| Inspector process (Coraza) | `tukuyomi-inspector` | Specify it with `kernel.inspector` in the configuration. This setting key cannot be omitted, so write it even on a host that uses ModSecurity generations only |
| Inspector process (ModSecurity) | `tukuyomi-inspector-modsecurity` | When you use a ModSecurity generation, or when you set `modsecurity` as the default engine or an upstream engine |
| Admin process | `tukuyomi-proxy admin <config>` | When you use the admin API and the admin screens |
| Records shipper | `tukuyomi-records-ship` | When you ship logs to PostgreSQL or MySQL |

- The proxy, the admin process, and the records shipper read the same configuration file (a single JSON file). Run all three as the same OS user. The inspector processes also run as the same OS user as the proxy.
- The admin process uses the same executable as the proxy, `tukuyomi-proxy`.
- For the role of each component, see Chapter 1.

## 3.2 Requirements

The requirements are as follows.

- **Linux**: tested on x86_64 only.
- **Linux with Landlock enabled**: an inspector process restricts its own privileges with Landlock after it reads the rules (see section 3.8).
  - On a Linux without Landlock, the inspector process does not start (exit 14). The proxy does not start either, and the log shows `stop: the kernel failed, engine <engine>: Exit(14)`. Both the `rules import` trial and the admin process's import trial fail. No setting lets it run without the restriction.
  - You need Linux 5.13 or later, with `landlock` in the LSM list, which you can check in `/sys/kernel/security/lsm`. Which distributions enable Landlock by default has not been checked.
  - What can be restricted depends on the Linux version. Restricting TCP bind and connect requires Linux 6.7 or later (Landlock ABI 4 or later). On earlier versions, only files are restricted.
- **glibc and libstdc++**: the release executables need glibc 2.39 or later. The ModSecurity inspector process also needs the libstdc++ symbols `GLIBCXX_3.4.29` and `CXXABI_1.3.15`. On an older Linux, build from source.
- **Shared libraries of the ModSecurity inspector process**: the host that runs it needs only libstdc++, libgcc_s, libc, and libm. libmodsecurity, YAJL, and PCRE2 are statically linked into the executable.
- **Processes and memory**: one proxy always runs, plus one inspector process for each started engine. More inspector processes run during a generation switch and during an import trial. For a guide to memory use, see "Choosing the Inspection Engine" in Appendix A (Operator Reference).
- **Shipping logs to a DB**: you need a PostgreSQL or MySQL server. Shipping has been tested with PostgreSQL 16 and 18 and MySQL 8.0. The file system of the log directory must also return the file creation time (btime of `statx`), and only ext4 has been tested.
- **Building from source**: what the build needs (Rust, a C compiler, Go, and others) is listed in "Requirements" in Build and Deployment (`docs/build/binary-deployment.md`), which is part of the documentation in the repository (`docs/`; English in `foo.md`, Japanese in `foo.ja.md`).

## 3.3 Where to Place the Executables

For downloading the release tarball, checking its SHA-256, extracting it, and placing the executables, see section 2.3. The CRS (OWASP Core Rule Set) is not bundled, so fetch it with the steps in section 2.6. This section covers what to decide for a production deployment.

- Place the executables in a directory that the OS user of the service cannot modify (owned by root), for example `/opt/tukuyomi-core/bin/`. When you use the ModSecurity inspector process (`tukuyomi-inspector-modsecurity`) and the records shipper (`tukuyomi-records-ship`), place them in the same directory.
- The executables were built on Ubuntu 26.04.1 LTS (glibc 2.43, gcc 15.2.0) with `rustc` 1.94.1 and Go 1.27.2, and have been tested only on the host where they were built.
- The inspector process (`tukuyomi-inspector`) and the TLS library (aws-lc) are statically linked.
- For the steps to build from source, see "Building from Source" in Build and Deployment. Always build the inspector process with `CGO_ENABLED=0`. The ModSecurity inspector process must also be built with a specific compiler version.
- Fetch the CRS as the OS user of the service. If you fetch it as root, `rules import` run as the OS user of the service cannot read the files.

## 3.4 OS User and Directories

### OS User

The proxy does not run as root. If any of the four user IDs of the process (real, effective, saved, file system) is 0, the proxy refuses to start and every command refuses to run, writing a `host check refused` line and ending with exit 1.

- Create a dedicated OS user and run both the service and the commands as that OS user, for example with `sudo -u tukuyomi tukuyomi-proxy ...`.
- Run the admin process (`admin`) and its short-lived commands (`admin bootstrap` and `admin reset`) as the same OS user, because the rules store, the log directory, the control socket, and the managed store can be used only by that OS user (0700). If you run them as a different OS user, none of these can be used.
- Run the records shipper as the same OS user too, because it reads the log directory and writes `ship.state` there. The records shipper does not run as root either.
- `acme renew` also refuses to run as root, because the proxy, which runs as another OS user, cannot read keys created by root.

### Directories and Files

The following table shows example directories and files. The paths and the OS user name are examples. Write every path in the configuration as an absolute path.

| Example | Setting key | Owner and permissions |
|---|---|---|
| The executables in `/opt/tukuyomi-core/bin/` | `kernel.inspector`, `kernel.engines.modsecurity.inspector` (can be omitted) | root. A place that the OS user of the service cannot modify |
| `/etc/tukuyomi-core/config.json` | (the start argument) | root. The OS user of the service must be able to read it. Up to 256 KiB |
| `/var/lib/tukuyomi-core/store` | `rules.store.dir` | The OS user of the service. Permissions 0700 |
| `/var/lib/tukuyomi-core/tmp` | `kernel.tmp_root` | The OS user of the service. Permissions 0700. Do not set setgid |
| `/var/lib/tukuyomi-core/managed` | `managed.dir` (when you use the managed configuration) | The OS user of the service. Permissions 0700 |
| `/var/lib/tukuyomi-core/tls/` | `cert_file` and `key_file` | The OS user of the service (`acme renew` writes them) |
| `/var/lib/tukuyomi-core/acme/account.key` | `acme.account_key_file` | `acme renew` creates it on the first run (0600) |
| `/var/lib/tukuyomi-core/challenges` | `acme.challenge_dir` | The OS user of the service. A directory dedicated to challenges |
| `/var/lib/tukuyomi-core/records` | `records.dir` | The OS user of the service. Permissions 0700 |
| `/etc/tukuyomi-core/records-db.dsn` | `records.ship.db_dsn_file` (when you use the records shipper) | The OS user of the service. Permissions 0600. Not owned by root |
| `/var/lib/tukuyomi-core/admin` | `admin.store.dir` | The OS user of the service. Permissions 0700 |
| `/var/lib/tukuyomi-core/control` | The directory in which `admin.control` is placed | The OS user of the service. Permissions 0700. The socket path is up to 107 bytes |
| `/var/lib/tukuyomi-core/crs-4.23.0` | `admin.crs_dir` (when you import the CRS through the admin API) | The directory created in section 2.6. The OS user of the service must be able to read it |
| `/etc/tukuyomi-core/country.mmdb` | `geo.country_db` | root. Permissions 0644 |

- Neither the proxy nor the commands create the directories in the table, so create them beforehand. The contents of each directory are created as follows:
  - `generations/`, `staging/`, `using/`, and so on inside the rules store: the commands and the proxy
  - The log files and the control socket: the proxy
  - What is inside the admin store: the admin process
- Use separate directories for the rules store, the log directory, the admin store, the directory for the control socket, the managed store, and `challenge_dir`. A configuration that makes any two of them the same directory, or places one inside another, is rejected. Overlap is judged by comparing the paths as written, so do not use symbolic links.
- Each of the rules store, the work directory, the log directory, the admin store, the directory for the control socket, and the managed store is checked: it must not be a symbolic link, must be owned by the OS user of the process, and must have no permissions for the group and other users. The checks are made at different times for each directory, and what happens when a condition is not met also differs (some refuse the proxy start, some keep the inspector process from starting, and so on). For details, see "OS User and Directories" in Build and Deployment.
- The parent directories of these directories are not checked. It is the operator's responsibility to keep other OS users from creating or replacing names inside them.
- If setgid is set on the work directory, the directories created inside it inherit that attribute and fail the permission check, so the inspector process cannot start.
- Write `kernel.inspector` in the configuration even on a host that uses ModSecurity generations only. Write `kernel.engines` only when you use ModSecurity generations (see "`kernel`" in Appendix A (Operator Reference)).

### Country Database

You need the country database only when you use country lists (`deny_countries` and `allow_countries` of `access`). The database is not bundled with the proxy, and the proxy does not fetch it. The operator provides a file in MaxMind DB format (version 2) and places it as in the table above. Its contents are verified against the SHA-256 written in `geo.sha256` in the configuration. For where to place it, how to replace it, and how the country is determined, see Chapter 6.

## 3.5 systemd Units

At the first start, you write the configuration file, fetch the CRS, import a rule set and choose its generation, check with `config check`, and then start the service (see Chapter 2).

This section shows the units for running as a service. If you use the admin process, also start its unit and create the first user (see Chapter 5). If you ship logs to a DB, prepare the DB user and the DB, place the connection string file, write `records.ship` in the configuration, and then start the records shipper unit (see Chapter 7).

The unit examples are in this order: the proxy, the admin process, the records shipper, and the certificate renewal timer. In the rest of this chapter, the proxy unit is named `tukuyomi-core.service`.

### Proxy Unit

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

- Use `Type=notify`. The proxy sends `READY=1` to systemd after the inspection kernels of all the engines to be started are ready and all the listeners are bound. It sends `STOPPING=1` at the beginning of the stop. `systemctl start`, and units ordered after this unit with `After=`, wait until `READY=1` arrives. With `Type=simple`, the service is considered started as soon as the process is launched.
  - Make `TimeoutStartSec` longer than the sum of the upstream name resolution time (`resolve_timeout_ms`) and the time to wait for the inspection kernel to be ready (`ready_wait_ms`). If `READY=1` does not arrive within this time, systemd stops the proxy.
- Use `KillMode=mixed`. With the default `control-group`, the SIGTERM sent to stop the service also reaches the inspector processes. An inspector process does not handle SIGTERM and exits at once, so the proxy cannot stop the inspector processes in order (finishing the remaining inspections and receiving the termination notice). With `mixed`, SIGTERM reaches only the proxy, and the proxy stops the inspector processes itself before it exits.
- Make `TimeoutStopSec` longer than the sum of `stop_wait_ms`, `kill_grace_ms`, and the 200 ms for writing out the logs. If it is shorter, systemd sends SIGKILL before the stop finishes. For the stop sequence, see "Stopping" in Appendix A (Operator Reference).
- Specify `LogRateLimitIntervalSec=0`. With journald's default rate limit, request logs are lost before they reach the journal when many requests arrive at once.
- Logs go to the journal. If the configuration has `records`, the same logs are also written to files. The retention period and size are set in the journald configuration (`SystemMaxUse`, `MaxRetentionSec`, and so on in `/etc/systemd/journald.conf`). The logs contain client addresses and paths, so keep the number of OS users in the groups that can read the journal (`adm` and `systemd-journal` on Ubuntu) to a minimum. For the log format, see Chapter 7.
- Listening on ports 80 and 443 requires `CAP_NET_BIND_SERVICE`. The ambient capability is inherited by the inspector processes too, but an inspector process discards all capabilities at start.
- Make `LimitNOFILE` larger than the sum of the accepted connections (`max_conns`) and the connections to upstreams, because each connection uses a file descriptor.
- Place the log directory, the directory for the control socket, the admin store, and the managed store inside `ReadWritePaths` (under `/var/lib/tukuyomi-core` in the example above). If you place them elsewhere, add them to `ReadWritePaths`.
- When the start is refused because of a configuration error or the like, `Restart=on-failure` restarts the proxy every `RestartSec`.

### Admin Process Unit

Run the admin process in a unit separate from the proxy. The executable, the configuration file, and the OS user are the same as the proxy's.

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
- Use `KillMode=mixed`. The admin process starts inspector processes for rule import trials. When the SIGTERM sent to stop it reaches only the main process, the admin process finishes the trial that is running and cleans up the inspector process and the work directory.
- When the admin process receives a stop signal (SIGTERM, SIGINT, or SIGHUP), it closes the listener and waits up to 10 seconds for requests in progress. Make `TimeoutStopSec` longer than these 10 seconds. In case an import trial is running, also add the time to stop its inspector process (`proxy.stop_inspect_ms` and `kernel.kill_grace_ms`).
- Specify `LogRateLimitIntervalSec=0`. The audit log is also written to standard error (the journal), so this keeps it from being lost to the rate limit of journald.
- Use the same inspector executable and work directory as the proxy. The inspector process started for an import trial also restricts its own privileges with Landlock, as in the proxy's case.
- The admin process listens on the loopback address `admin.listen` with plain HTTP. With a port of 1024 or higher, `AmbientCapabilities` is not needed.
- The admin process reads the configuration file only once, at start. Unlike the proxy, it does not reload on SIGHUP (for the admin process, SIGHUP is a stop signal). After you change the configuration, check it with `config check` and then restart with `systemctl restart`. Do not set `ExecReload`.
- The admin process starts even if the proxy is not running, but while the proxy is not running, it cannot ask for a generation switch or for applying the managed configuration.
- To use it from outside, forward from the proxy's TLS listener to the admin process. For how to write the route, see "Access from Outside" in Appendix B (Admin Reference). The admin screens and the managed configuration are covered in Chapter 5.

### Records Shipper Unit

If you ship logs to a DB, run the records shipper in a unit separate from the proxy. The configuration file and the OS user are the same as the proxy's.

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
- Make `TimeoutStopSec` long. The stop signal is not handled until the DB call finishes, so a stop can take as long as 1 to 2 minutes. Even if `TimeoutStopSec` is shorter and the process ends with SIGKILL, the lines and the position enter the DB in the same transaction, so the next start continues from where it left off.
- Place the log directory (where `ship.state` is written) inside `ReadWritePaths`.
- If the DB refuses the login, the records shipper ends with exit 1. `Restart=on-failure` then restarts it every `RestartSec`, and this repeats until you fix the connection string.
- If the DB server's certificate was issued by your own certificate authority, pass a file that contains that certificate authority's certificate with `Environment=SSL_CERT_FILE=<path>`.
- The records shipper reads the configuration file and the connection string file only once, at start (it does not reload on SIGHUP). After you change them, restart with `systemctl restart`. Do not set `ExecReload`.
- The records shipper reads the same configuration file as the proxy, and rejects a configuration file that contains an unknown setting key. Before you write a new setting key (`managed`, `host_policies`, `kernel.default_engine`, the upstream `engine`, and so on) in the configuration, replace the records shipper executable with the same build as the proxy.
- The records shipper starts even if the proxy is not running, and ships the logs that are in the files.
- For the table permissions, the format of the connection string, and how shipping works, see Chapter 7.

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
- `ExecStopPost` runs even if the command fails. If even one certificate becomes `failed`, the command ends with exit 1, but SIGUSR2 is still sent, so the other certificates that were renewed go into use. The files of a `failed` certificate stay as they were, and SIGUSR2 replaces certificates only when all the certificates it loaded pass the checks, so sending it after a failure causes no problem.
- The `+` at the beginning of `ExecStopPost` makes `systemctl kill` run as root. `acme renew` itself runs as the OS user of the service.
- Do not run two `acme renew` commands with the same configuration at the same time; nothing prevents concurrent runs. systemd timers do not overlap, but if you run it from cron or the like, make sure the runs do not overlap.
- When you apply a managed configuration version that changes the hosts of an ACME site, run this service with `systemctl start tukuyomi-core-acme.service` without waiting for the timer.
- For the steps of the first issue, see Chapter 8.

## 3.6 Checks Before Start

Two kinds of checks are made before start. Their names are similar, so do not confuse them.

### Configuration Check (`config check`)

`config check` checks the configuration file and the chosen generations in the same way as a start does. Run it as the same OS user as the service.

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
```

- If there is no problem, `accepted` is written to standard output and the command ends with exit 0.
- If you run it before choosing a generation for the default engine, it is refused with `rules store refused: no generation is chosen` (exit 1). It is refused with the same message when an upstream engine has no chosen generation. An error in the configuration file itself gives exit 2.
- It also checks the upstream server names and the TLS certificate and key files. A rejection there also ends with exit 1. You can tell which check refused by the beginning of the line (`upstream refused`, `tls refused`).
- `config check` does not start an inspector process, so it does not check the work directory, the inspector executable, or Landlock. Problems with these show up at start.
- The `ExecReload` of the unit also uses this `config check`.

For details, see "`config check`" in Appendix A (Operator Reference).

### Checks Before Start (SIGCHLD and File Descriptors)

The proxy start, `rules import` (which starts an inspector process for the trial), and the admin process commands (`admin <config>`, `admin bootstrap`, and `admin reset`) also check the following conditions by reading `/proc`, and refuse to run if they are not met. `config check` and the other commands check only that the process is not root.

- **SIGCHLD is not ignored**: the inspection kernel waits for the exit of its child processes itself.
- **All file descriptors greater than 2 are close-on-exec**: this keeps unnecessary descriptors from being passed to the inspector processes.

Both conditions are met when you start from systemd.

## 3.7 Configuration Reload and Signals

Send signals for the proxy to its main process only. In the unit's `ExecReload` this is `$MAINPID`, and with `systemctl kill` it is `--kill-whom=main`. `systemctl kill` without `--kill-whom=main` also sends the signal to the inspector processes. An inspector process ignores SIGUSR1 and SIGUSR2, but exits when SIGTERM, SIGINT, or SIGHUP arrives.

### `systemctl reload`

`systemctl reload` runs the two `ExecReload` lines of the unit above in order. It sends SIGHUP only if `config check` passes. On SIGHUP, the proxy reloads the configuration file and switches to the new configuration without stopping.

- With a configuration that `config check` rejects, SIGHUP is not sent and `systemctl reload` returns a failure. While `config check` rejects the chosen generation, `systemctl reload` is refused too (the reload itself does not touch generations).
- When `config check` passes, `systemctl reload` returns success at the moment it sends SIGHUP and does not wait for the reload to finish. When only the running proxy refuses the configuration (a difference in a setting key that cannot change while running, an upstream engine that is not running, or binding a new listener), `systemctl reload` still returns success. A success does not mean that the configuration was switched.
- Check the result in the log lines and in `/metrics`. In the log, look for the `reload: configuration replaced <sha256>` and `reload: configuration refused: <reason>` lines (with a configuration that has `managed`, ` managed <version>` follows the former). In `/metrics`, look at `tukuyomi_config_reloads_total`.
- To change the configuration, rewrite the file (write it under another name and rename it over the old file), run `systemctl reload tukuyomi-core.service`, and check the result in the log lines. If you changed a setting key that cannot change while running, restart with `systemctl restart`. The admin process and the records shipper do not reload the configuration, so restart them when you change a setting key that they read.
- The setting keys that can and cannot change while running are listed in "SIGHUP (Configuration Reload)" in Appendix A (Operator Reference).
- For the order of the steps when you update from 0.1.0, see section 9.4.

### SIGUSR2 and SIGUSR1

To make the proxy reload only the certificates and keys, send SIGUSR2 as follows. The ACME renewal timer in section 3.5 sends the same SIGUSR2 after a renewal.

```bash
systemctl kill -s SIGUSR2 --kill-whom=main tukuyomi-core.service
```

To switch the generation of the rule set, send SIGUSR1 as follows.

```bash
systemctl kill -s SIGUSR1 --kill-whom=main tukuyomi-core.service
```

On SIGUSR1, the proxy switches each engine to its chosen generation, one engine at a time. An engine that has a chosen generation but is not running is started at this point (see "SIGUSR1 (Generation Switch)" in Appendix A (Operator Reference)). For how generations are handled, see Chapter 4.

## 3.8 Restricting the Inspector Processes

At start, an inspector process restricts its own privileges in the following order. Every restriction applies to all threads of the process and cannot be undone.

1. It reads the rule set generation. If it cannot read it, it ends with exit 11. It also cannot read the manifest of another engine's generation, and likewise ends with exit 11.
   - The Coraza inspector process does not read files after this.
   - The ModSecurity inspector process copies the verified files into the temporary directory created for each start (exit 14 if it cannot copy them). After the restriction is applied, it builds the rules from this copy and reads only this copy.
2. It builds the Landlock rule set.
   - It blocks access to files outside the temporary directory created for each start (which is inside the work directory). Other directories inside the work directory are also inaccessible.
   - Inside the temporary directory, only creating, writing, reading, truncating, and deleting files are allowed. Creating and listing directories, renaming to outside the temporary directory, and running programs are not possible.
   - On Linux 6.7 or later (ABI 4 or later), TCP bind and connect are also prohibited.
3. It discards the capabilities (empties the ambient set and sets effective, permitted, and inheritable to 0).
4. It sets `no_new_privs`.
5. Finally, it enables Landlock. From this point, the restrictions of step 2 take effect.

If any of steps 2 to 5 fails, the inspector process does not start (exit 14). Once the restrictions are in place, it checks and builds the rules with the engine of that generation and starts accepting requests. If checking or building the rules fails, it ends with exit 11.

Some things cannot be restricted:

- Landlock does not restrict UDP, Unix domain sockets, or MPTCP sockets (those created with `IPPROTO_MPTCP`), so even after the restriction the inspector process can use them to send data to the outside and to listen on ports 1024 and above.
- On a host that does not use MPTCP, setting `net.mptcp.enabled=0` makes it impossible to create MPTCP sockets.
- Ports below 1024 cannot be used because the capabilities are discarded (when Linux's `net.ipv4.ip_unprivileged_port_start` is the default 1024).

The proxy is not subject to this restriction. The proxy reads the configuration, the rules store, and the certificates and keys, and holds the listeners and the connections to upstreams. The admin process does not apply this restriction to itself either; only the inspector process that it starts for an import trial applies it.

## 3.9 Operational Notes

To close the chapter, here are the points to watch when you deploy and run the proxy.

- **Run the service and the commands as a dedicated OS user**: they do not run as root. Create the directories in the table in section 3.4 before the start.
- **Check a changed configuration with `config check` first**: a successful `systemctl reload` does not mean that the configuration was switched, so check the result in the log lines.
- **Send signals only to the main process of the proxy**: with `systemctl kill`, add `--kill-whom=main`.
- **The admin process and the records shipper do not reload the configuration**: restart them when you change a setting key that they read.
- **On a Linux without Landlock, neither the inspector process nor the proxy starts**: check the conditions in section 3.2 before you deploy.
