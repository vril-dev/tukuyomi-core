# Chapter 5. Managed Configuration and the Admin Screens

This chapter starts with preparing the admin process, and then covers users and roles, login and two-factor authentication, API tokens, and the audit log.

The second half is about the managed configuration, which keeps part of the configuration outside the configuration file so that you can change it from the admin screens and apply it to the running proxy. It goes through deciding whether to use it, the first start, and applying. The last section introduces each of the admin screens.

The exact forms of the API and the description of each screen are in Appendix B (Admin Reference), so this chapter refers you there.

## 5.1 The Admin Process and the Managed Configuration

This section describes the role of the admin process and how to decide whether to use it.

The admin process is a separate process from the proxy, started with `tukuyomi-proxy admin <config>`. It serves the admin screens, which you open in a browser, and the admin API, which programs use. It uses the same executable and configuration file as the proxy, and runs as the same OS user.

It listens on the loopback address in `admin.listen` and responds with HTTP/1.1, without TLS. Each connection carries one request and is closed after the response. Up to 32 connections are handled at the same time, and a connection over the limit is accepted and closed at once.

The admin process keeps the users, API tokens, audit log, switch history, and configuration history in the admin store (`admin.store.dir` in the configuration). It keeps the managed configuration versions in the managed store (`managed.dir` in the configuration).

It talks to the proxy over a Unix domain socket that the proxy creates (the control socket, `admin.control` in the configuration). Over this socket, the admin process asks for the proxy's state and requests generation switches and configuration reloads.

With the admin process, you can do the following.

- Operations on rule generations (Chapter 4)
- Searching the logs (Chapter 7)
- Managing users, API tokens, and the audit log
- Editing and applying the managed configuration

The configuration file itself cannot be edited from the admin screens or the admin API. The screens only show its values.

There are two things to decide.

- **Whether to use the admin process**: write `admin` in the configuration file to use it. Without `admin`, the admin process does not start (exit 2), and the proxy does not create the control socket. The admin process keeps working while the proxy is stopped, but it then refuses generation switches and applying the managed configuration, because both are requests to the proxy.
- **Whether to use the managed configuration**: write `managed` in the configuration file to use it (see section 5.9). You can also use the admin process without the managed configuration.

## 5.2 Preparing the Admin Process

First, write `admin` at the top level of the configuration file. For example:

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

When you write `admin`, write all of its setting keys except `crs_dir` and `route`. The main ones are as follows.

- `listen`: a loopback address. It cannot overlap `proxy.listeners` or `status.listen`.
- `control`: the path of the control socket. The proxy creates the socket.
- `origin`: the origin of the URL at which you open the admin screens.
- `crs_dir`: the CRS directory, used when an import from the admin screens uses the CRS.
- `route`: the admin route. It is required in a configuration with `managed`, and cannot be written in a configuration without `managed` (see section 5.3).

For the range of each setting key, see "Setting Key `admin`" in Appendix B (Admin Reference).

Create `admin.store.dir` and the directory that holds `admin.control` beforehand. Neither can be a symbolic link. Make the proxy's OS user their owner, and give no permissions to the group or other users (0700). They cannot be the same directory as the rules store, `records.dir`, `managed.dir`, or similar directories, and none of these can be inside another. See "Relations Between Values" in Appendix A (Operator Reference).

Run the admin process in a unit separate from the proxy. Chapter 3 has an example of the unit. In the unit, set `Type=notify`, `KillMode=mixed`, and `LogRateLimitIntervalSec=0`.

- `KillMode=mixed` lets the admin process stop the inspector process that it started for a rule import trial in an orderly way.
- `LogRateLimitIntervalSec=0` keeps the journald rate limit from dropping audit log lines, which are also written to standard error (the journal).

Do not set `ExecReload`, because SIGHUP is a stop signal for the admin process.

The admin process reads values such as `admin` only once, at start. After you change a setting key of `admin`, check the configuration with `config check`, and then restart the admin process and the proxy.

Create the first user with `admin bootstrap`. This user has the `owner` role. The password is not passed as an argument; the command reads it from the first line of standard input.

```bash
read -r -s -p 'password: ' PW; echo
printf '%s\n' "$PW" | sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy admin bootstrap /etc/tukuyomi-core/config.json alice
unset PW
```

- **Name and password**: the name is 1 to 32 bytes of lowercase letters, digits, `.`, `_`, and `-`, and the password is 12 to 128 bytes of UTF-8.
- **Result**: on success, the command writes `created owner <name>` to standard output and exits with 0. It cannot create the user if the admin store already has any user (exit 1). It can run while the admin process is not running.
- **When a user is locked out**: use `admin reset`, for example for the only owner who has lost both the password and two-factor authentication. It sets a new password, disables two-factor authentication, invalidates the API tokens, and requires a password change at the next login.

## 5.3 Access from Outside

The admin process does not use TLS, so use it through a TLS listener of the proxy. Cookies are sent with `Secure`, so the admin screens can be used only over https.

How you route to it depends on whether the configuration file has `managed`.

In a configuration without `managed`, write a route for an admin host in `forward.routes`. For example:

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

The other setting keys of `forward` are omitted in this example, and `admin.listen` is `127.0.0.1:9100`.

- **Certificate and allowed addresses**: put a certificate that has `admin.example.com` in its `hosts` on the TLS listener. In the `allow_cidrs` of `access`, allow only the addresses of the people who use the admin screens.
- **Plaintext listeners**: do not route this host through a plaintext listener. A route is chosen regardless of the listener, so if there is a plaintext listener that is not `redirect`, the password may flow unencrypted.
- **Policies that apply**: the global settings (the global access control and rate limits) and the host policies also apply to requests for this host (see Chapter 6).

In a configuration with `managed`, write the route of the admin screens in `admin.route`. The proxy creates this route itself. It has `host` (the host name of the admin screens), `certificate`, and `access`. The `allow_cidrs` of `access` is required and cannot be empty. Neither the global settings nor the host policies apply to this route (see section 5.9; section 5.11 has an example).

Write the following two in either configuration.

- **`admin.trusted_proxies`**: the address from which the proxy connects to the admin process (`127.0.0.1/32` if it is the same host). Without it, every client is treated as having the proxy's address, so the limit on login attempts (per client) is shared by everyone, and `client` in the audit log is the proxy's address on every line.
- **`admin.origin`**: make it exactly the same as the origin of the URL that you open in the browser (do not write the port when it is 443). If it differs, changes (login included) get 403.

For details, see "Access from Outside" in Appendix B (Admin Reference).

## 5.4 Requests to the Admin Screens and WAF Inspection

Requests to the admin screens also go through the WAF inspection. The engine that inspects them depends on the configuration.

- A configuration with `managed`: the default engine (`kernel.default_engine` in the configuration file; Coraza if it is not written)
- A configuration without `managed`: the engine of the upstream that forwards to the admin process

The thing to watch is large request bodies. A rule import, or a check or save of the managed configuration, sends a large JSON body that holds rule files or PEM certificates, up to 12 MiB. If such a body is inspected, a rule may block it, so make the following paths bypass routes in the generations (see Chapter 4).

The following example is for a configuration with `managed`, with the routes written in one `--routes` file.

```json
[
  {"host": "admin.example.com", "path": "/api/generations", "action": "bypass"},
  {"host": "admin.example.com", "path": "/api/managed/check", "action": "bypass"},
  {"host": "admin.example.com", "path": "/api/managed/apply", "action": "bypass"}
]
```

- **Path matching**: `path` does not end with `/`, so it matches only that path.
- **Routes in every generation**: bypass routes are part of a generation, so keep putting the same routes into every generation of the engine that inspects requests to the admin screens. If you choose a generation that lacks them, these requests are inspected from that generation on.
- **First generation**: the routes take effect only after a generation that holds them is in use. Import the first generation that holds them with the command (`rules import ... --routes <file>`).
- **`proxy.max_body`**: set it to 12 MiB (12582912) or more. The admin route has no `max_body`, so `proxy.max_body` is its limit.
- **Message when blocked**: if a rule blocks a request to `check` or `apply` with 403 in a generation that has no bypass routes, the admin screens show "The proxy or the WAF refused the request. A body with PEM files or many routes can be blocked by the WAF. Check that /api/managed/check and /api/managed/apply are left out of the inspection."

If the admin host is inspected with the CRS, the PUT and DELETE methods and the password fields also need tuning. Without it, a new user cannot make the first password change and cannot finish logging in. See "CRS Tuning for the Admin Host" in Appendix B (Admin Reference).

## 5.5 Users and Roles

There are three roles, `viewer`, `operator`, and `owner`, and each can do more than the one before it.

- **`viewer`**: can read the state, the list and contents of generations, the switch history, and the logs, as well as the state of the managed configuration, the list of versions, and the configuration history. A viewer can also manage their own password, two-factor authentication, and API tokens.
- **`operator`**: everything a viewer can do, plus reading the audit log, importing rules, choosing generations, rolling back, and removing generations. For the managed configuration, an operator can check, save and apply, apply by name, roll back, and remove versions.
- **`owner`**: everything an operator can do, plus creating users and changing their roles and whether they are enabled. An owner can also reset other users' passwords and two-factor authentication, and view and remove everyone's API tokens.

Users are handled as follows.

- **Creating users**: create the first owner with `admin bootstrap`. After that, an owner creates users on the Users screen. A user that an owner created, or whose password an owner set, cannot use other APIs at the next login until they change the password to their own.
- **Removing users**: there is no API for it, so disable users that are no longer used. Enabling a user again does not bring back API tokens that were deleted.
- **Refused changes**: an owner's operations on themselves (lowering their own role, disabling themselves, resetting their own password and two-factor authentication) are refused. So is any change that would leave no enabled owner.

## 5.6 Login and Two-Factor Authentication

When a login succeeds, the admin process creates a session and returns the cookie `tukuyomi_admin`. A session ends in cases such as these:

- It was not used for `admin.session_idle_ms`
- `admin.session_total_ms` has passed since it was created
- The user logged out

Two-factor authentication (MFA) uses time-based one-time passwords (RFC 6238). Codes have 6 digits and are made with HMAC-SHA1 over 30-second time windows. When `admin.mfa` is `required`, a user who has not set up two-factor authentication can do nothing else until they set it up.

- **Setup**: start it from the Account screen. The admin process returns the secret, and a verification code from the authenticator app confirms the setup. At the confirmation, the admin process returns 10 recovery codes, only this once. Each recovery code is 16 characters long and can be used once.
- **Disabling with `required`**: users cannot disable two-factor authentication themselves, so an owner disables it for them. An owner asks another owner to disable theirs, or uses `admin reset`.
- **Lockout and attempts**: after 5 failures in a row, a user is locked out for 15 minutes. Each client can make up to 30 attempts per minute.

Requests that change something are checked in two ways.

- If there is an `Origin` header, it is exactly the same as `admin.origin`
- For a session request, `X-CSRF-Token` is correct

A request that has both the session cookie and an `Authorization` header gets 400. So if you put HTTP authentication such as Basic authentication in front of the admin screens, requests after login get 400.

For details, see "Login and Two-Factor Authentication", "Lockout and Attempt Limits", "Sessions", and "CSRF and Origin" in Appendix B (Admin Reference).

## 5.7 API Tokens

API tokens are for programs that use the admin API. Create and remove them on the Account screen.

- **Form and storage**: a token has the form `tkc_<16-hex-digits>_<43-characters>`. The whole token is returned only once, when it is created. Only the SHA-256 of the secret is kept in the admin store.
- **Creating**: give a name, a role, the number of days it is valid (1 to 365), and the current password. The role can be your own role or lower. One user can have up to 50 tokens, and expired tokens count toward the 50.
- **Using**: send it as `Authorization: Bearer <token>`. It cannot be sent together with the session cookie, and it cannot be used for the account APIs and the APIs for managing users.
- **Changes to the token's owner**: a token also becomes invalid when its owner is disabled, when their role is lowered, and when their password is changed.

For example, with the token in `$TOKEN`, run `curl -sS -H "Authorization: Bearer $TOKEN" https://admin.example.com/api/status`. For the APIs that can be used, see "API Paths" in Appendix B (Admin Reference).

## 5.8 Audit Log

The admin process records logins, changes, and refused requests as lines in the audit log. Passwords, API tokens, verification codes, recovery codes, two-factor authentication secrets, and cookies are not written to it.

- **Writing before the change**: a change is made after its audit log line is written. If the line cannot be written, for example because the disk is full, the change is not made and the request is refused with 503 `unavailable`. The exception is logout, which ends the session even if the line cannot be written.
- **`ok` lines**: for choosing a generation, a rollback, and changes to the managed configuration, the `ok` line is written before the change, so it does not mean success. To see how the operation ended, check the lines that follow and the switch history or the configuration history.
- **Where it is stored**: `audit/audit.log` in `admin.store.dir`, as one JSON object per line. When a file goes over 16 MiB, writing moves on to the next file, and 8 files are kept. The same lines are also written to standard error (the journal).
- **Reading it**: the Audit log screen (operator or above) and `GET /api/audit` show the newest 200 lines, newest first. `audit` lines do not go into the proxy's log files (`records.dir`), so a log search with `type=audit` does not find them.

For the fields of a line and the list of `action` values, see "Audit Log" in Appendix B (Admin Reference).

## 5.9 Whether to Use the Managed Configuration

The managed configuration stores part of the configuration as versions in the managed store, outside the configuration file. It covers the following settings.

- Sites (hosts and certificates)
- Upstreams
- Routes
- The default upstream
- The global access control and rate limits
- Host policies

To start using it, write `managed` in the configuration file. A configuration file without `managed` is read as before. This section lists what you can do with it and what you need in exchange.

With the managed configuration, you can do the following.

- **Editing and applying from the admin screens**: you can edit the settings above in the admin screens and the admin API, check them, save them, and apply them to the running proxy. Applying advances the selected version only after the proxy has passed a configuration reload with that version, so a version that the proxy refused is never used at the next start.
- **Earlier versions**: saved versions remain, so you can go back to an earlier version (rollback, apply by name).
- **History**: an apply from the admin screens or the admin API is recorded in the admin process's configuration history, and the operations in the audit log. Changes made with commands are recorded in neither.

In exchange, you need the following.

- **Setting keys the configuration file can no longer have**: `forward` is limited to `resolve_timeout_ms`. `certificates` of a TLS listener, the global `access` and `rate_limit`, and `host_policies` cannot be written either. Write these in a version.
- **Admin route**: if the configuration has `admin`, `admin.route` is required. The only network restriction that applies to it is `allow_cidrs` of `admin.route.access`.
- **Adding and removing `managed`**: whether `managed` is present, and `managed.dir`, cannot change while running, so restart the proxy and the admin process. A configuration reload cannot change them (it is refused).
- **A generation with the bypass routes**: the admin route also goes through WAF inspection by the default engine, so use a generation that has the bypass routes from section 5.4 for the default engine. When you change the default engine, put the same routes into the generation of the new default engine as well.
- **ACME certificates**: the site certificates that ACME issues are placed in `acme/` of the managed store (see Chapter 8).
- **Build of the records shipper**: if you use the records shipper, replace it with the same build as the proxy before you write `managed` in the configuration file. An earlier build that does not know `managed` rejects a configuration file with unknown setting keys and does not start.

If you manage the configuration with the file only and do not change it from the admin screens, you do not need `managed`.

## 5.10 Managed Store and Versions

The setting key `managed` has only `{"dir"}`. `dir` is the directory of the managed store. Neither the proxy nor the commands create it, so create it first. It must not be a symbolic link, must be owned by the proxy's OS user, and must have the permissions 0700.

The managed store holds the following.

- Versions (`versions/<version>.json`)
- The certificate chains, private keys, and upstream CA files that versions point to (`files/<sha256>`)
- The certificates of ACME sites (`acme/`)
- `current`, which shows the selected version

The names of versions and files are the SHA-256 of their contents, and they do not change after they are created. Do not write a version by hand; create it with `managed import` or in the admin screens.

A version is JSON with `sites`, `upstreams`, `routes`, and `default_upstream`. It can also have the optional `access`, `rate_limit`, and `host_policies`.

`upstreams`, `routes`, `default_upstream`, `access`, `rate_limit`, and `host_policies` are written in the same form as `forward` in a configuration file without `managed` and as in Chapter 6. The only difference is `ca` in the `tls` of an upstream, which holds the SHA-256 of a file in `files/` of the managed store.

A site in `sites` is written as `{"name", "hosts", "certificate"}`. `certificate` is either `{"chain", "key"}` or `{"acme": {"renew_before_days"}}`. For the whole form and its rules, see "Managed Store and Versions" in Appendix A (Operator Reference).

The `managed` commands do not send requests to the running proxy.

- `managed import <config> <document>` builds a version from a document and puts it in the managed store. It does not select the version.
- `managed activate <config> <version>` runs the same checks as start, and selects the version only if they pass (it changes `current`).
- There are also `managed remove` and `managed list`.

A document has the same form as a version, except that files are written as paths instead of SHA-256 (`chain_file`, `key_file`, `ca_file`). After the import, the files that the document points to are not used. See "`managed`" in Appendix A (Operator Reference).

## 5.11 First Start with the Managed Configuration

With a configuration that has `managed`, both start and `config check` refuse when no version is selected (`config check: managed store refused: no managed version is chosen`, exit 1). The first version is created and selected with commands (`managed import` and `managed activate`), so import and select a version before you start. The other steps are the same as the first-start steps in Chapter 2.

The example has the following.

- A redirect listener and a TLS listener
- One site with a certificate in files
- One upstream
- The admin route

1. Create the directories. In addition to the directories of Chapter 3, create the managed store directory with 0700.

   ```bash
   sudo install -d -m 0700 -o tukuyomi -g tukuyomi /var/lib/tukuyomi-core/managed
   ```

2. Place the certificate files: the certificate and private key of the admin route (for example, `/var/lib/tukuyomi-core/tls/admin.pem` and `admin.key`), and the certificate chain and private key of the site (for example, `/var/lib/tukuyomi-core/import/www.pem` and `www.key`). The site files are input to the import, so place them where the OS user of the service can read them.
3. Write the configuration file. The excerpt below shows the differences from a configuration file without `managed`. `proxy` omits the setting keys other than `listeners`, and `admin` omits the setting keys other than `route`. Write the omitted setting keys as in the example of section 5.2 and in "Example" in Appendix A (Operator Reference). Do not write `certificates` in the TLS listener.

   ```json
   "proxy": {
     "listeners": [
       {"address": "0.0.0.0:80", "redirect": {"https_port": 443}},
       {"address": "0.0.0.0:443", "tls": {"min_version": "1.2"}}
     ]
   },
   "forward": {"resolve_timeout_ms": 5000},
   "managed": {"dir": "/var/lib/tukuyomi-core/managed"},
   "admin": {
     "route": {
       "host": "admin.example.com",
       "certificate": {
         "cert_file": "/var/lib/tukuyomi-core/tls/admin.pem",
         "key_file": "/var/lib/tukuyomi-core/tls/admin.key"
       },
       "access": {"allow_cidrs": ["203.0.113.0/24"]}
     }
   }
   ```

4. Write the version document (for example, `/etc/tukuyomi-core/managed-import.json`). Place it where the OS user of the service can read it.

   ```json
   {
     "sites": [
       {
         "name": "www",
         "hosts": ["www.example.com"],
         "certificate": {
           "chain_file": "/var/lib/tukuyomi-core/import/www.pem",
           "key_file": "/var/lib/tukuyomi-core/import/www.key"
         }
       }
     ],
     "upstreams": {
       "web": {"servers": [{"address": "127.0.0.1:8080", "weight": 1, "max_fails": 0, "fail_timeout_ms": 10000, "backup": false}]}
     },
     "routes": [],
     "default_upstream": "web"
   }
   ```

5. Import the rule set and choose a generation (see Chapter 2 and Chapter 4). `managed activate`, which selects the version, checks that the engines used by the upstreams of the version have a chosen generation, so do this step before step 7.
6. Import the version. A `<version> created` line is written. The command only places the version and does not select it.

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy managed import /etc/tukuyomi-core/config.json /etc/tukuyomi-core/managed-import.json
   ```

7. Select the version. The command runs the same checks as start and selects the version only if they pass. A `<version> current` line is written.

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy managed activate /etc/tukuyomi-core/config.json <version>
   ```

8. Check the configuration. If it passes, `accepted` is written to standard output, and a `config check: managed version <version>` line to standard error.

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
   ```

9. Start the service (see Chapter 3). A `start: managed version <version>` line appears in the log.
10. Start the admin process and create the first user (see section 5.2). Open the admin screens at the host name in `admin.route.host`, from a network that `admin.route.access` allows. After this, make changes in the admin screens or the admin API (see section 5.13).

For an ACME site, see "ACME Sites" in Appendix A (Operator Reference).

## 5.12 Moving to the Managed Configuration

A proxy and an admin process that run with a configuration file without `managed` can move to the managed configuration. There is no conversion command, so write the configuration file and the version document by hand. The table of what moves where and the steps are in "Moving to the Managed Configuration" in Appendix A (Operator Reference). This section lists only the points where mistakes are likely.

- **Admin route**: remove the route for the host of the admin screens from `forward.routes`, and copy its `access` to `admin.route.access`. The global settings do not apply to the admin route, so if you forget to copy it, who can reach the admin screens changes.
- **ACME sites**: copy the current certificate chain and private key to `acme/<hosts-sha256>/` of the managed store. If you do not, TLS connections to the hosts of that site fail until after `acme renew` and SIGUSR2.
- **Configuration before the move**: keep the original configuration file, executables, and units, and then put the new configuration file at the original path.
- **Order of restarts**: restart the admin process, the proxy, and the records shipper, in this order (`systemctl restart`). `admin.route.host` and `managed` cannot change while running, so `systemctl reload` is refused. From the restart of the admin process until the restart of the proxy, requests to change the managed configuration are refused with 409 (nothing is changed).

## 5.13 Applying a Version

There are two ways to make the running proxy use another version: applying from the admin screens and the admin API, and using commands and SIGHUP.

### Applying from the Admin Screens and the Admin API

The admin screens and the admin API apply a version with the following operations.

- **Save and apply**: saves a version made from the draft on the screens, and applies it.
- **Apply by name**: applies a version in the managed store, given by its name (SHA-256).
- **Rollback**: goes back to the previous version. The rollback target is the `from` of the newest line in the configuration history whose result is `applied` and whose `from` and `to` differ. Rollback works only when the `to` of that line is the version selected now. After an apply that did not end in `applied`, or after a version was selected with a command, you cannot roll back (409 `the history does not end at the chosen version`). If you roll back again right after a rollback, it goes back to the original version.

In each operation, the admin process sends a `reload` request over the control socket, and the proxy reloads the configuration with that version. The admin process sets `current` to that version only after the proxy's configuration has switched, so a version that the proxy refused does not become `current`.

- **Overwriting from an old screen**: the selected version that you saw on the screen is sent as `expect`. If another user or a command has selected a version since you saw the screen, the request is refused with 409.
- **Apply job**: an apply is answered with 202 and then continues inside the admin process as an apply job. The admin screens show "Applying" until it ends, and then the result ("Applied", "Refused", "Busy", and so on). An apply job cannot be cancelled.
- **Managed store lock**: the admin process holds this lock during an apply, and `managed import`, `managed activate`, and `managed remove` are refused meanwhile (`the managed store is in use by another command`).
- **Adding or changing an ACME site**: when you apply a version that adds an ACME site or changes the hosts of a site, the managed store has no certificate yet for the new set of hosts. TLS connections to all the hosts of that site then fail until `acme renew` issues the certificate, so run `acme renew` and SIGUSR2 right after the apply (see Chapter 8). The confirmation of "Save and apply" also shows this warning.
- **Rewriting the configuration file**: a reload reads the configuration file together with the version. If you have rewritten the configuration file and have not yet sent SIGHUP, an apply from the admin screens also puts that rewrite into effect. If the configuration file has an error, the apply is refused too.

### Commands and SIGHUP

`managed activate` runs the same checks as start and changes `current`. The command does not send a request to the proxy, so the running proxy reads the `current` version at the next SIGHUP (`systemctl reload`) or start (see Chapter 9).

If SIGHUP is refused, `current` stays at the version that the running proxy refused, and that version is used at the next start.

To change the version of the running proxy, use the admin screens or the admin API. When you change it with a command, run `systemctl reload` right away and check for the `reload: configuration replaced <sha256> managed <version>` line.

### When an Apply Stops Halfway

When an apply stops halfway, the selected version (`current`) and the running version may differ. In `GET /api/managed`, `serving` shows the running version and `current` shows the selected version.

The Configuration versions screen also shows a notice when the two differ, together with two operations that make them the same ("Apply the selected version again" and "Select the running version"). The proxy and the admin process do not fix this mismatch automatically. For the table of states and how to fix them, see "Applying" in Appendix A (Operator Reference).

## 5.14 The Admin Screens

Open the admin screens at `https://admin.example.com/` (`admin.origin`) in a browser. The files of the screens are built into the executable, so the admin process and the admin screens are always the same version.

From the bar at the top of the screen, you can switch the following.

- Language (Japanese and English)
- Theme (Auto, Light, Dark)
- How times are shown (Local or UTC)

Which screens you can use depends on the role, and the menu shows only the screens that the role can use.

| Menu | Screen (role) | Content |
|---|---|---|
| (no name) | Overview (viewer or above) | The numbers and state of the proxy, the state of the generations for each engine, and the SHA-256 of the configuration file. When the managed configuration is used, the selected and running versions |
| WAF | Rule generations (viewer or above), Rule import (operator or above), Switch history (viewer or above) | The list and detail of generations, import, choosing, switching the proxy, starting an engine, removal, and rollback (operator or above) |
| Logs | Access log (viewer or above), Audit log (operator or above) | Searching the logs with conditions. The newest 200 lines of the audit log |
| Proxy | Sites, Upstreams, Routes (operator or above) | Editing the draft of the managed configuration |
| Policy | Access control and rate limits (operator or above) | Editing the global settings and the host policies of the draft (see Chapter 6) |
| Configuration | Configuration versions, Configuration history (viewer or above), Configuration file (operator or above) | The selected and running versions, the contents of a version, apply by name, and removal. The configuration history and rollback. The values of the configuration file (they cannot be changed) |
| Admin | Account (viewer or above), Users (owner) | Password, two-factor authentication, and API tokens. Creating and managing users |

For what each screen shows, see "Admin Screens" in Appendix B (Admin Reference).

The four screens (Sites, Upstreams, Routes, and Access control and rate limits) share one draft of the managed configuration.

- **Source of the draft**: the selected version. From the Configuration versions screen, you can also start from another version. A change made here has no effect until you press "Save and apply".
- **Page memory**: the draft exists only in this page's memory and is lost when you log out, when the session ends, and when you close the tab.
- **Check and save**: "Check" in the bar checks the draft without saving it and, if it is refused, shows the error in its field. "Save and apply" checks the draft, shows a confirmation, and then saves and applies it. A draft with "No changes" cannot be saved.
- **Confirmation**: it lists the changes to save by name and does not show their values, because a rewritten route can contain a secret.

The following operations show a confirmation first.

- Choosing, rolling back, and removing a generation
- Applying a version by name, rolling back, and removing a version

When the admin process was started without the managed configuration, the Configuration versions screen and the editing screens show what the managed configuration can do and the main steps to start using it.

## 5.15 Operational Notes

- **Builds of the admin process and the proxy**: use the same build for both. If the proxy is an earlier build that does not return the state of each engine, the admin screens do not show the buttons for choosing a generation, applying to the proxy, starting an engine, and rolling back.
- **Restarting the admin process**: a restart loses the sessions, the lockout states, two-factor authentication secrets that are still being set up, and the apply job, so everyone must log in again. API tokens, users, the audit log, and the histories stay in the store.
- **Users who can read the logs**: the log files hold client addresses and paths. The admin API lets a viewer or above read the logs, so decide carefully who gets the viewer role.
- **Versions you no longer need**: remove them with `managed remove` or on the Configuration versions screen. The selected version and versions in use cannot be removed.
