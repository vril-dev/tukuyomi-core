# Chapter 9. Operations

This chapter covers operating a running proxy: monitoring (`/readyz`, `/metrics`, notifications to systemd), configuration reloads by signals, stopping, version updates, and going back to the previous version. You check the results of these operations with log lines and metrics.

## 9.1 Monitoring

### Monitoring Listener

When you write `status` in the configuration, a listener on a loopback address responds to health checks and metrics requests. If `status` is omitted, there is no monitoring listener. Here is an example.

```json
"status": {"listen": "127.0.0.1:9101"}
```

In `listen`, write a loopback IP (`127.0.0.0/8` or `::1`) and a port. The responses are not authenticated, so query them from a monitoring program on the same host. This address cannot overlap any address in `proxy.listeners` or `admin.listen`, and cannot be used as an upstream server address. Change the example port to one that does not overlap other listeners.

| Request | Response |
|---|---|
| `GET /healthz` | 200 `ok`. It shows only that the proxy can respond |
| `GET /readyz` | 200 `ready` if the proxy is ready. Otherwise 503 and a word giving the reason (`starting`, `inspector down`, `stopping`) |
| `GET /metrics` | 200 and the metrics in Prometheus text format |

`/readyz` returns 200 when all of the following hold.

- The inspector processes of all started engines are running
- All the listeners are bound
- A stop has not begun

During a generation switch, the old generation keeps answering, so the proxy stays ready. To check readiness from a load balancer, use `/readyz`.

- Monitoring requests are neither inspected nor forwarded, and are not recorded in the logs. The global `access` and `rate_limit` and the host policies do not apply to them either.
- The monitoring listener is bound before the inspector processes and is closed partway through a stop. Until it is closed, `/healthz` returns 200.
- For the detailed rules, such as the number of connections that are answered at the same time, see "Monitoring" in Appendix A (Operator Reference).

### Metrics

The `/metrics` values are held in the proxy's memory, so they start again from 0 after a restart. Label values are only fixed words or names from the configuration; values that come from requests are not used as labels. The metrics fall into the following groups by what they watch.

- **Request results**: `tukuyomi_requests_total` (the `class` label has the same 7 values as `class` in the request log), `tukuyomi_waf_rule_hits_total` (`decision` is `block` or `detect`), `tukuyomi_uninspectable_total` (requests that could not be inspected), `tukuyomi_policy_refusals_total` (requests refused by the access control and the rate limit)
- **Inspector processes and rule generations**: `tukuyomi_inspector_up` (1 if the inspection kernels of all started engines are ready, 0 otherwise), `tukuyomi_inspector_restarts_total`, `tukuyomi_inspector_engine_up` and `tukuyomi_inspector_engine_restarts_total` for each engine, and `tukuyomi_rules_generation_info`, which shows the generation that is receiving requests
- **Results of operations (the `result` label)**: `tukuyomi_rules_switches_total` (generation switches by SIGUSR1 and by the control socket), `tukuyomi_certificate_reloads_total` (SIGUSR2), `tukuyomi_config_reloads_total` (SIGHUP and `reload` on the control socket)
- **Logs**: `tukuyomi_records_dropped_total`, `tukuyomi_record_write_errors_total`, `tukuyomi_record_file_errors_total`, `tukuyomi_records_refused_total`, `tukuyomi_records_healthy`, `tukuyomi_records_admitting`, `tukuyomi_records_unshipped_bytes` (see Chapter 7)
- **Connections and upstreams**: `tukuyomi_connections_open`, `tukuyomi_tls_handshake_failures_total`, `tukuyomi_upstream_failures_total` (reset to 0 on a configuration reload), and others

For the names, types, and labels of all metrics, see "Metrics (`/metrics`)" in Appendix A (Operator Reference).

### Notifications to systemd

If the environment variable `NOTIFY_SOCKET` is set, the proxy sends notifications to that socket. It sends `READY=1` once after all the listeners are bound, and `STOPPING=1` once when a stop begins.

- If you make the unit `Type=notify`, `systemctl start` waits until the inspection kernels are ready and the listeners are bound (for an example unit, see section 3.5).
- If a notification cannot be sent, the proxy only writes one `notify:` line, and its behavior does not change. If `NOTIFY_SOCKET` is neither an absolute path nor a name that starts with `@`, the proxy writes one `start:` line and runs without sending notifications.
- The inspector processes run with an empty environment, so they never send notifications.

## 9.2 Signals and Configuration Reloads

### Signals

Send signals only to the proxy's main process. For how to send them (`systemctl reload` and `systemctl kill --kill-whom=main`), see section 3.7.

| Signal | What it does |
|---|---|
| SIGTERM, SIGINT | Stops the proxy (see section 9.3) |
| SIGHUP | Reloads the configuration file and switches to the new configuration without stopping |
| SIGUSR1 | Switches each engine to the generation chosen for it in the rules store, one engine at a time (see Chapter 4) |
| SIGUSR2 | Reloads the certificate and key files of all TLS listeners (see Chapter 8) |

### How a Configuration Reload Proceeds

When the proxy receives SIGHUP, it reads the configuration file from the same path as at start, in a separate thread. If `managed` is present, it also reads the version selected at that moment (`current`).

It then runs the start stages that come before the rules store (the configuration file and the version, the name resolution of the upstream servers and `ca_file`, the certificates and keys of the listeners, the ACME challenges, and the country database of `geo`), with the same checks as at start.

- If everything passes and every setting key that cannot change while running (described below) is the same as at start, the proxy switches to the new configuration all at once.
- If anything is refused, the proxy changes nothing and writes a line with the reason.
- Check the result with the log lines and with `tukuyomi_config_reloads_total` (`replaced`, `refused`) in `/metrics`. A success reported by `systemctl reload` does not necessarily mean that the configuration was switched (see section 3.7).

| Log line | Meaning |
|---|---|
| `reload: configuration replaced <sha256>` | Switched. In a configuration with `managed`, the line is `reload: configuration replaced <sha256> managed <version>`. Use this value to check which file and version are in effect |
| `reload: configuration refused: <reason>` | Refused. Other refusal lines include `reload: upstream refused: <reason>` and `reload: tls refused: <reason>`. A refusal line does not contain values from the file |

When the admin process applies a managed configuration version, it sends a `reload` request on the control socket, and the proxy reloads the configuration in the same way (see Chapter 5). Only one reload runs at a time, so a SIGHUP received during a reload only writes a `reload: a configuration reload is in progress, ignored` line.

### What Can Change and What Cannot

A configuration reload can change the following.

- The setting keys of `proxy` (except the setting keys that cannot change, listed below), and the listeners (adding, removing, reordering, TLS and certificates, `http2`, `redirect`)
- `forward` (the upstreams and the routes; with `managed`, the sites, upstreams, routes, and default upstream of the version). The `engine` of an upstream can change if the new engine is running.
- The `ca_file` of an upstream, the certificates and keys of the listeners, and the ACME challenges
- The global `access` and `rate_limit`, `host_policies`, and `geo`
- The certificate and `access` of the admin route
- `records.keep`

The setting keys that cannot change while running are as follows. If any of them differs from start, the whole configuration is refused (`reload: configuration refused: <key> cannot change while running`). To change them, restart with `systemctl restart`.

- `proxy.max_conns`, `max_buffered_bytes`, `drive_slice_ms`, `ready_wait_ms`, `stop_inspect_ms`, `stop_wait_ms`
- `records` (everything except `keep`, and whether it is present), `status`, `admin`, `admin.route.host`
- `rules.store`, `managed` (whether it is present, and `dir`), `kernel` (everything, including `default_engine`)

### Connections and Listeners

Connections accepted after the switch use the new configuration. Open connections keep using the configuration they were accepted with, and are closed without their requests being refused.

- HTTP/1.1: a connection waiting for its next request after a response is closed at once. A connection in the middle of a response gets `Connection: close` on that response and is then closed.
- HTTP/2: the proxy sends `GOAWAY` and closes the connection after the open streams end.
- WebSocket tunnels and responses of routes with `stream` continue with the previous configuration, up to their own timeouts.

When the listeners change, the proxy first binds every address in the new configuration that it is not listening on now, and then switches. If even one cannot be bound, the whole configuration is refused (`reload: configuration refused: listener <number> cannot be bound`).

An address that overlaps one that is being listened on now (for example, `127.0.0.1:8080` while `0.0.0.0:8080` is being listened on) cannot be bound, so the whole configuration is refused. In that case, split the change into one reload that removes the listener and another that adds the new one, or restart.

### What Is Carried Over and What Is Left Alone

- Each rate limit table is carried over when its settings have not changed. A table that cannot be carried over is replaced with a new table that counts from 0, and the proxy writes a `reload: rate limit table started anew` line. For the conditions for carrying a table over, see Chapter 6 and "Host Policies (`host_policies`)" in Appendix A (Operator Reference).
- The proxy resets which upstream servers are marked as failed and the failure counts, and creates the idle connections to the upstreams and the TLS sessions of the listeners anew. It does this even when the file content and the version are the same as before, and it closes the idle connections.
- A reload leaves the rule generations alone: the running generation stays as it is, and the rules store is not read (SIGUSR1 is what switches generations). A reload does not start inspector processes either, so if an upstream in the new configuration uses an engine that is not running, the reload is refused (`reload: configuration refused: the engine of an upstream is not ready (upstream <name>)`). Start that engine with SIGUSR1 first (see Chapter 4).

### What Is Not Reloaded

The setting keys that cannot change while running, listed above, are read at start and stay as they are until the proxy is restarted.

The admin process and the records shipper do not reload the configuration. For both, SIGHUP is a stop signal, so do not put `ExecReload` in their units, and restart these processes after you change the configuration.

## 9.3 Stopping

The proxy stops when it receives SIGTERM or SIGINT. Let t0 be the time when the first reason to stop occurs (a signal, or a failure at start or in the driver). The stop proceeds in the following order.

1. The proxy closes the listeners and refuses new requests. It also closes the control socket and deletes its file, and closes the connections that are waiting for the next request. `/readyz` starts returning 503 `stopping`, and if `NOTIFY_SOCKET` is set, the proxy sends `STOPPING=1`.
2. Inspection ends by `t0 + stop_inspect`.
3. The proxy waits for connections until `t0 + stop_wait` and then cuts off any that remain. WebSocket tunnels do not end when a stop begins; they are cut off at this point. The proxy then closes the monitoring listener.
4. It waits until `t0 + stop_wait + kill_grace` for the inspection kernels of all the running engines to end.
5. It spends at most 200 ms flushing the logs, and exits.

The log has a `driver: stop, engine <engine>, records <count>, held <count>, waiting <count>` line for each running engine. At the end, a `stop: kernel ..., engine <engine>, bye ..., exit_confirmed ..., dir_removed ..., held_left ..., waiting_left ..., results ..., retired_clean ...` line is written.

The exit code is 0 only when both of the following hold.

- The reason to stop is not a failure
- For every stopped inspection kernel, the end of its inspector process and the removal of its work directory were confirmed

Set the unit's `TimeoutStopSec` longer than the sum of `stop_wait_ms`, `kill_grace_ms`, and the 200 ms log flush. If it is shorter, systemd sends SIGKILL before the proxy exits (see section 3.5).

The admin process and the records shipper stop differently from the proxy.

- When the admin process receives a stop signal (SIGTERM, SIGINT, or SIGHUP), it closes the listener and waits up to 10 seconds for requests in progress.
- The records shipper finishes the round in progress, then stops and sends `STOPPING=1`. The stop signal is not handled while a DB call is in progress, so a stop can take 1 to 2 minutes in the worst case. Even if it is stopped with SIGKILL, the next start continues from the position left in the DB (see Chapter 7).

For the detailed order of the stop and the meaning of each item, see "Stopping" in Appendix A (Operator Reference).

## 9.4 Version Updates

Until 1.0, only updates from the previous release are supported. To move up two or more releases, update one release at a time, in order. To go back to the previous version, restore the backup taken before the update. For getting and verifying the executables of a new release, see section 3.3.

### Backup Before an Update

Before an update, back up the configuration file, the rules store (`rules.store.dir`), the managed store (`managed.dir`), and the admin store (`admin.store.dir`), leaving out any that you do not use.

While you take the backup, keep the admin process, the proxy, the records shipper, and the certificate renewal timer stopped. Keep the owners and permissions as they are. The backup also holds password hashes, API tokens, private keys, and so on, so put it in a directory that only root can read. With the example directories and units from Chapter 3, the commands are as follows.

```bash
sudo systemctl stop tukuyomi-core-admin.service tukuyomi-core.service tukuyomi-core-records-ship.service tukuyomi-core-acme.timer
sudo install -d -m 0700 /var/backups/tukuyomi-core
sudo tar -C / -cpf /var/backups/tukuyomi-core/before-update.tar etc/tukuyomi-core/config.json var/lib/tukuyomi-core/store var/lib/tukuyomi-core/managed var/lib/tukuyomi-core/admin
```

The log directory (`records.dir`), the certificates and keys, and the work directory (`kernel.tmp_root`) are not included in the backup.

### Updating from 0.1.0

In 0.2.0, you can choose the inspection engine for each upstream (see Chapter 4). To update, take the backup described above, and then replace the executables. Once the executables are replaced, the 0.1.0 configuration file, rules store, and managed store are read as they are. If you do not write the new setting keys (`kernel.default_engine`, the `engine` of an upstream), the proxy runs with only one engine, as in 0.1.0.

- **If you had chosen a Coraza generation in 0.1.0**: you do not need to write `kernel.default_engine`. The `current` written by 0.1.0 is read as Coraza's chosen generation. `config check` writes `accepted`, and at start only one `start: rules engine coraza` line appears. `current` is not rewritten, and no `current.*` is added.
- **If you had chosen a ModSecurity generation in 0.1.0**: set `kernel.default_engine` to `modsecurity`. Without it, both `config check` and start write the line `rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine` and are refused (exit 1). The rules store does not change.

Use the same build for the admin process, the proxy, and the records shipper. Note the following.

- The updated admin process does not choose generations or roll back for an earlier version of the proxy (409).
- The records shipper rejects unknown setting keys in the configuration file, so before you write `kernel.default_engine` or the `engine` of an upstream, replace the records shipper with the same build. The 0.1.0 proxy also rejects a configuration file that has `kernel.default_engine`, with `configuration has an unknown key` (exit 2).
- Replace all the executables with those of the same release, and then restart the admin process, the proxy, and the records shipper, in that order. With the admin process restarted first, the updated admin process refuses generation choices and rollbacks for the earlier proxy with 409 during the changeover. It only refuses them, so the rules store and the switch history do not change.

### Going Back to the Previous Version

To go back to the previous version, restore the backup taken before the update and start the executables of the previous version. The steps are the same for every version.

1. Stop the admin process, the proxy, the records shipper, and the certificate renewal timer.
2. Move the current configuration file and the directories you backed up aside under other names (keep them; do not delete them).
3. Restore the backup.
4. Put back the executables of the previous version, and confirm that `config check` of the previous version writes `accepted`.
5. Start the admin process, the proxy, and the records shipper in this order, and start the certificate renewal timer.

For the backup taken in the example above, steps 2 and 3 are as follows.

```bash
sudo mv /etc/tukuyomi-core/config.json /etc/tukuyomi-core/config.json.after-update
sudo mv /var/lib/tukuyomi-core/store /var/lib/tukuyomi-core/store.after-update
sudo mv /var/lib/tukuyomi-core/managed /var/lib/tukuyomi-core/managed.after-update
sudo mv /var/lib/tukuyomi-core/admin /var/lib/tukuyomi-core/admin.after-update
sudo tar -C / -xpf /var/backups/tukuyomi-core/before-update.tar
```

The following changes made after the update are lost.

- The generations you imported or chose
- The versions and applies of the managed configuration
- The users, API tokens, and sessions you made
- Audit log lines in the admin store

The log directory is not restored, so the logs written after the update remain. For other notes, see "Going Back to the Previous Version" in Appendix A (Operator Reference).

## 9.5 Operational Notes

To close the chapter, here are the points to watch in day-to-day operation.

- **Results of configuration changes**: even when `systemctl reload` reports success, check the result with the `reload: configuration replaced` or `reload: configuration refused` line in the log.
- **Setting keys that cannot change while running**: change them by restarting with `systemctl restart`. When you change setting keys that the admin process and the records shipper read, restart those processes too.
- **Rule generations**: a configuration reload does not switch them. Switch generations with SIGUSR1 or in the admin screens.
- **Reloading only certificates and keys**: send SIGUSR2, not SIGHUP. SIGHUP reads the whole configuration file, so it can pick up a configuration that is only half written.
- **Builds of the executables**: use the same build for the admin process, the proxy, and the records shipper.
- **Backups and going back**: take a backup before an update, and restore it to go back to the previous version.
