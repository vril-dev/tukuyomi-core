# Chapter 8. Certificates with ACME

There are two ways to provide TLS certificates: the operator places the files, or the command `acme renew` issues and renews them. This chapter covers the second.

It covers, in order, how ACME works and the settings it needs, the steps for the first issue, the timer that runs the renewal every day, certificates for sites in the managed configuration, and the points to watch when you run ACME.

## 8.1 How ACME Works

`acme renew` issues and renews certificates using HTTP-01 challenges only (RFC 8555). The `acme renew` command talks to the CA, and the proxy answers the challenge requests that the CA sends.

A certificate is issued as follows.

1. **Write the configuration file**: include `acme` and a certificate that has `acme`. The certificate files need not exist yet.
2. **Start the proxy**: a certificate that has no files yet is left out of the handshake.
3. **Run `acme renew`**: run it as the OS user of the service. The command places an order with the CA and puts the challenge files in `challenge_dir`. When the CA sends the challenge requests to port 80, the proxy answers them with those files.
4. **The command writes the certificate and key files**
5. **Send SIGUSR2 to the proxy**: the proxy then starts using the new certificate.

A running proxy does not notice that the command has written a certificate, so always send SIGUSR2 after the command. To renew, run the same command every day; section 8.4 describes the systemd timer for this.

With the managed configuration, site certificates are kept in the managed store rather than at paths in the configuration file, and you write `acme` in a site's `certificate` (see section 8.5).

## 8.2 Requirements

### Port 80

The CA sends challenge requests over plaintext HTTP to port 80 of the certificate's host, so you need a normal listener or a redirect listener on port 80. The proxy does not check port numbers. TLS listeners do not respond to challenges.

Normal and redirect listeners answer requests of the following form ahead of the admin route, the policies (the global settings and the host policies), routes, a route's `access`, inspection, forwarding, and redirects.

- The method is `GET` or `HEAD`.
- The request target is `/.well-known/acme-challenge/<token>` with nothing after it.
- The `Host` is the host of a certificate that has `acme`.

A request that does not match this form is not treated as a challenge; it goes through routes and inspection like any other request.

The response to a challenge is either 200, whose body is the file `<token>` in `challenge_dir`, or 404. The request log of a challenge has `class` `answered` (see Chapter 7). For the detailed conditions, see "ACME" in Appendix A (Operator Reference).

### Configuration

In the configuration file, write `acme` and a certificate that has `acme`. The following example has a listener that redirects to https and a TLS listener with a certificate issued by ACME.

```json
{
  "proxy": {
    "listeners": [
      {"address": "0.0.0.0:80", "redirect": {"https_port": 443}},
      {
        "address": "0.0.0.0:443",
        "tls": {
          "min_version": "1.2",
          "certificates": [
            {
              "cert_file": "/var/lib/tukuyomi-core/tls/www.pem",
              "key_file": "/var/lib/tukuyomi-core/tls/www.key",
              "hosts": ["www.example.com"],
              "acme": {"renew_before_days": 30}
            }
          ]
        }
      }
    ]
  },
  "acme": {
    "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "contact_email": "admin@example.com",
    "account_key_file": "/var/lib/tukuyomi-core/acme/account.key",
    "challenge_dir": "/var/lib/tukuyomi-core/challenges",
    "ca_file": "/etc/tukuyomi-core/acme-roots.pem",
    "timeout_ms": 300000
  }
}
```

This example is an excerpt of a configuration file. It leaves out the `proxy` setting keys other than `listeners`, as well as `forward`, `kernel`, `rules`, and so on. Settings have no default values, so a real configuration file must have every setting key except those defined as optional. For the list of setting keys, see "Configuration File" in Appendix A (Operator Reference).

- A certificate's `acme` has the form `{"renew_before_days"}` (1 to 60) and marks it as a certificate that `acme renew` issues and renews. The hosts of this certificate cannot have `*.`.
- In a configuration without `managed`, write the top-level `acme` only when some certificate has `acme`. When you write it, include all six of these setting keys.
  - `directory_url`: the CA's ACME directory. For testing, use the CA's test ACME directory (staging, for Let's Encrypt). The value in the example is that staging directory.
  - `contact_email`: the contact passed to the CA. Only the format is checked.
  - `account_key_file`: the ACME account key. If the file does not exist, the command creates it (0600).
  - `challenge_dir`: the directory for the challenge files.
  - `ca_file`: a file that holds only the root certificates that issued the server certificate of the CA's API. It can hold at most 100 certificates, so the OS root certificate bundle cannot be used as it is.
  - `timeout_ms`: the timeout for the whole command.
- For the value ranges and how these keys relate to other setting keys, see "`acme`" in Appendix A (Operator Reference).

### Directories and Users

- Run `acme renew` as the OS user of the service, the same user as the proxy. Keys created by root could not be read by the proxy, which runs as another OS user, so running the command as root is refused.
- The OS user of the service must be able to write to the directories that hold `cert_file`, `key_file`, and `challenge_dir`. The command writes the certificate, key, and challenge files to temporary files and then replaces the old files with them.
- Use `challenge_dir` for challenges only, and do not put other files in it (`account_key_file`, `ca_file`, the certificate and key files, and so on). It cannot be the same directory as the rules store, the log directory, the admin store, and so on, and none of these directories can be inside another.

For the list of directories and their permissions, see Chapter 3.

## 8.3 First Issue

For the first issue, check first that the test CA can issue a certificate, and then switch to the production CA.

1. Write `acme` and a certificate that has `acme` in the configuration. The certificate files need not exist yet.
   - In a configuration without `managed`, put `acme` on a listener's certificate. In a configuration with `managed`, put it on the admin route's certificate (`admin.route.certificate`) and on a site in a version (see section 8.5).
   - The proxy writes a `start: tls certificate not issued yet (<place>)` line and starts with that certificate left out of the handshake.
   - For testing, set `directory_url` to the CA's test ACME directory (staging, for Let's Encrypt).
2. Start the proxy.
3. Run `acme renew` as the OS user of the service.

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy acme renew /etc/tukuyomi-core/config.json
   ```

   It writes lines such as `2.1 renewed`. With `managed`, the lines look like `admin route renewed` and `site www renewed`.
4. Send SIGUSR2 with `systemctl kill -s SIGUSR2 --kill-whom=main tukuyomi-core.service`; the proxy starts using the certificate.
5. When the test CA has issued the certificate, switch to the production CA.
   - The certificate from the test CA has not expired, so `acme renew` leaves it as it is (`valid`). Delete that certificate's files: `cert_file` and `key_file` for listener and admin route certificates, and `chain` and `key` in `acme/<hosts-sha256>/` of the managed store for an ACME site.
   - Change `directory_url` to the production CA's. If the server certificate of the production CA's API was issued by a different root certificate, change `ca_file` too.
   - Run `acme renew` again, and then send SIGUSR2. If you send SIGUSR2 after deleting the files but before `acme renew` finishes, that certificate drops out of the handshake (a configuration reload, which also reads certificates, has the same effect). If you keep to this order, the proxy keeps using the certificate it has already loaded in the meantime.
   - Most `acme` setting keys, such as `directory_url`, `ca_file`, and `contact_email`, are read only by the command, so the proxy needs no restart. The proxy also reads `challenge_dir` and the hosts of a certificate that has `acme`, so when you change them, reload the proxy's configuration (SIGHUP, `systemctl reload`). The hosts of an ACME site change when a version is applied.
6. Set up the timer that runs every day (see section 8.4).

## 8.4 `acme renew` and the Renewal Timer

### What the Command Does

`acme renew` checks the certificates that have `acme`, in the order they appear in the configuration. A certificate needs renewal if any of the following is true, and the command then places a new order with a new key.

- The certificate or key file cannot be read
- The key does not match the certificate
- The certificate does not contain all the hosts
- The time until the end of the validity period is shorter than `renew_before_days` days (exactly that number of days is not shorter)

A certificate that needs no renewal is `valid`. The command writes one result line to standard output for each certificate that has `acme`. In a configuration without `managed`, the form is `<listener>.<certificate> renewed|valid|failed`, and both numbers count from 1. The listener number is the position in `proxy.listeners`, and listeners without TLS are counted too. The files of a `failed` certificate are left as they were.

The exit codes are as follows.

- 0: every certificate is `renewed` or `valid`
- 1: at least one is `failed`, the command was stopped, it could not run, or it was run as root
- 2: an argument error, a configuration file that was rejected, or a configuration file without `acme`

The whole command, including the CA's responses and the waits, takes at most `timeout_ms`. For the other conditions, and for how a configuration with `managed` is handled, see "`acme renew`" in Appendix A (Operator Reference).

### Renewal Timer

To renew certificates, run `acme renew` every day. The example systemd units (the service `tukuyomi-core-acme.service` and the timer `tukuyomi-core-acme.timer`) and the reason for sending SIGUSR2 with `ExecStopPost` are in "Certificate Renewal Timer" in section 3.5. Two points matter for ACME renewal.

- **Send SIGUSR2 after the command**: use `ExecStopPost`, so that the certificates that were renewed are used even when the command fails (when any certificate is `failed`). Do not use SIGHUP (`systemctl reload`), because it loads the whole configuration file.
- **Change a unit that sends SIGUSR2 with `ExecStartPost=+`**: replace that line with an `ExecStopPost=+` line and run `systemctl daemon-reload`. `ExecStartPost` runs only when the command exits with 0, so a single `failed` keeps the other renewed certificates out of use until SIGUSR2 or SIGHUP is next sent.

## 8.5 ACME Sites (Managed Configuration)

In the managed configuration, when you set the `certificate` of a site in a version to `{"acme": {"renew_before_days": 30}}` (1 to 60), `acme renew` issues and renews that site's certificate. The site's `hosts` can only be names; `*.` cannot be written.

The following example is one entry of a version's `sites`. Use the same form in the document for `managed import` as well.

```json
{"name": "www", "hosts": ["www.example.com"], "certificate": {"acme": {"renew_before_days": 30}}}
```

To use ACME sites, the configuration file needs `acme`. In a configuration file with `managed`, the ACME sites are in the version, so you can write `acme` even if no certificate in the configuration file has `acme`. For the managed configuration itself, see Chapter 5.

### Where the Certificates Are Kept

An ACME site's certificate chain and private key are not at paths in the configuration file; they are in `acme/<hosts-sha256>/chain` and `key` in the managed store.

`<hosts-sha256>` is the SHA-256 of the byte sequence you get by sorting the site's `hosts` in byte order and joining them, each followed by a newline. The site name is not part of it, so the same set of hosts uses the same directory even after you rename the site, and in other versions too. For example, the following command computes it.

```bash
printf '%s\n' www.example.com app.example.com | LC_ALL=C sort | sha256sum | cut -d' ' -f1
```

If `acme/` and the directories in it do not exist, `acme renew` creates them (0700).

### What `acme renew` Covers

`acme renew` reads the `current` version and processes the admin route that has `acme` and then the sites of the version. The result lines have the forms `admin route renewed|valid|failed` and `site <name> renewed|valid|failed`. If there is neither an admin route that has `acme` nor an ACME site, the command writes no result line; it writes one line to standard error and exits with 0, so that the timer does not fail.

When the admin route's certificate has `acme`, its certificate files are written to the `cert_file` and `key_file` paths in the configuration file. Until the files exist, handshakes for the admin route are refused. The first issue follows the same steps as in section 8.3.

The proxy answers challenges for the host of the admin route that has `acme` and for the hosts of the ACME sites in the running version. The CA can connect from any address, so `admin.route.access` does not apply to challenges.

### Sites Without a Certificate Yet

A site whose certificate files do not exist yet is treated as having a certificate that has not been issued. Start, configuration reload, `config check`, and `managed activate` do not refuse such a site. They write a `tls certificate not issued yet (site <name>)` line and refuse handshakes for the hosts of that site. Once the files exist, send SIGUSR2 and the proxy starts using the certificate.

### When You Change Versions

Issuing a version's ACME certificates before the version is applied is not implemented.

When you apply a version that changes a site's set of hosts (a host was added to the site or changed, `{"chain", "key"}` was changed to `acme`, and so on), the new directory has no certificate yet, so TLS connections to all the hosts of that site fail, including hosts that worked before.

Right after applying, run `acme renew` and send SIGUSR2: start the renewal service from section 3.5 with `systemctl start tukuyomi-core-acme.service`. If you leave it to the timer, connections fail until the timer next runs.

- When you press "Save and apply" in the admin screens and a site needs a new ACME certificate, the confirmation shows this message: "Sites that need a new certificate: {n}. Their hosts cannot be reached over TLS until acme renew issues the certificate (at most a little over a day if you leave this to the renewal timer)." `{n}` is the number of those sites.
- When you go back to an earlier version (rollback, or applying by name) and the previous certificate is still in the directory for that set of hosts, it is used without being issued again. The proxy does not check certificate expiry, so it uses even an expired certificate as it is. After going back, run `acme renew` (it issues the certificate again if expiry is near).
- If you run the `managed activate` command and then run `acme renew` before sending SIGHUP, the hosts that are only in the new version are `failed`, because the proxy does not answer challenges for them. After `managed activate`, reload the configuration right away (see Chapter 5 and Chapter 9).

When you remove a version, the `acme/` directories for sets of hosts that no site in the remaining versions uses are removed too. If you later use an ACME site with the same set of hosts, the certificate is issued again, and this issuance also counts toward the number of issuances at the CA.

## 8.6 Operational Notes

To close the chapter, here are the points to watch when you run ACME.

- Do not run two `acme renew` commands at the same time with the same configuration. Nothing prevents concurrent runs (see section 3.5).
- The key and the certificate are each written to a separate file and synced, and then replaced, key first. If the command stops between the two replacements, a key that does not match the certificate is left behind. The running proxy refuses that pair even on SIGUSR2 and keeps using the current one, and the next run of the command recreates them. However, if you start the proxy before then, it refuses that pair and does not start (exit 1).
- If a configuration reload (SIGHUP, `reload` on the control socket), `managed activate`, `config check`, or a start happens between the two replacements, the certificate check can be refused (`tls refused`). If that happens, run it again. For how applying from the admin screens and the admin API handles this, see "Control Socket" in Appendix B (Admin Reference).
- The key is written with 0600 and the certificate with 0644 (minus the umask).
- Do not use symbolic links for `acme.challenge_dir` or the managed store, because the check for overlapping directories compares the paths as written.
- Do not place `acme.account_key_file`, or the certificate and private key files that the admin route uses, inside the rules store, `records.dir`, the admin store, or the managed store. `acme renew` rewrites these files.

For the conditions not covered here, see "ACME" and "ACME Sites" in Appendix A (Operator Reference).
