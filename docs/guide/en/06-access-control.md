# Chapter 6. Access Control and Rate Limiting

This chapter describes the policies that refuse requests before a route is chosen: the global access control (`access`), the global rate limit (`rate_limit`), the host policies (`host_policies`), and the country database (`geo`).

It first shows where the policies take effect in the order of request checks. It then goes through the setting keys one by one and shows how the host policies combine with the global settings. The full rules for the setting keys are in Appendix A (Operator Reference), so this chapter refers you there.

## 6.1 Overview

The top-level `access`, `rate_limit`, `host_policies`, and `geo` of the configuration file define the policies that refuse requests before a route is looked up.

| Setting key | Content |
|---|---|
| `access` | The global access control. It refuses clients by network and by country |
| `rate_limit` | The global rate limit. It sets the number of requests per second that one client may keep making |
| `host_policies` | The host policies. They apply to each host instead of the global settings |
| `geo` | The country database. It determines the country of the client address when a country list is used |

- **Omitting**: a policy that is omitted is not applied; all four are optional.
- **A configuration with `managed`**: `access`, `rate_limit`, and `host_policies` are written in the version, not in the configuration file (see Chapter 5). `geo` is written in the configuration file.
- **Loading**: the values are read at start and at a configuration reload (see Chapter 9).
- **`access` of a route**: a separate setting that takes effect after a route is chosen. Its form and its rules for refusing are the same as those of the global `access`. See "`forward`" in Appendix A (Operator Reference).
- **Admin route**: `admin.route` gets none of these policies. The only network restriction that applies to it is `admin.route.access`.

## 6.2 Order of Request Checks

To see where the policies take effect, start with the order of the checks. The proxy checks a request in the following order, and the first check that refuses the request decides its response.

| Order | Check | Response | `reason` in the log |
|---|---|---|---|
| 1 | Header section checks | 400, 414, 431, and so on | A fixed phrase for each violation of the header section |
| 2 | ACME challenge (on a normal listener and a redirect listener, when there is a certificate that has `acme`) | 200 with the challenge file as the body, or 404 | `acme challenge` |
| 3 | Admin route (in a configuration with `managed`, when `Host` is `admin.route.host`). Whether a TLS connection used the certificate of the admin route in the handshake, whether the connection is not plain, and whether `admin.route.access` allows it | 421, 404, 403 | `admin host on another certificate`, `admin host over plain http`, `denied by route access` |
| 4 | The access control that applies to the request (the `access` of the host policy whose hosts match the `Host`, or the global `access` if there is none) | 403 | `denied by access` |
| 5 | The rate limit that applies to the request (likewise, the `rate_limit` of the host policy or the global one) | 429 (`Retry-After: 1`) | `too many requests` |
| 6 | Whether the `Host` of a TLS connection is among the hosts of the certificate used in the handshake | 421 | `host not covered by the certificate` |
| 7 | Route (the default upstream if there is none) | 404 | `no route matches` |
| 8 | The `access` of the route | 403 | `denied by route access` |
| 9 | `Content-Length` and the `max_body` of the route | 413 | `body over the limit of the route` |
| 10 | Body type | 415 | `body type not supported` |

This chapter is about checks 4 and 5. A request that falls under check 3 does not go through checks 4 to 9 and is forwarded to the admin process. The redirect listener responds with a redirect or 404 after check 5, and does not read the body.

- **Settings that apply in checks 4 and 5**: the `Host` of the request decides them (see section 6.6).
- **Where they apply**: checks 4 and 5 apply in the same way to requests that match a bypass route and to the redirect listener. Even if the inspector process is stopped, the refusing response does not change. They do not apply to the monitoring listener.
- **What is not counted**: a request refused in check 1 and a challenge answered in check 2 are not counted by the access control or the rate limit.
- **Body and connection**: a request refused in checks 3 to 9 gets its response before the body is read. On an HTTP/1.1 connection, when a request with a body is refused, the connection is closed after the response.
- **Logs and metrics**: a refused request appears in the log (`class` is `rejected`). A request refused in check 4 or 5 is counted in `tukuyomi_policy_refusals_total` in `/metrics`, whether the global settings or a host policy refused it (see Chapter 9).

## 6.3 Client and Country

The global `access` and `rate_limit`, the host policies, the `access` of a route, and `admin.route.access` all look at the same client address. The country is also determined from that address.

How the client address is decided depends on the peer that sent the request.

- For a request from a peer in `trusted_proxies`, it is decided from `X-Forwarded-For`.
- For a request from a peer that is not trusted, that peer is the client. What that peer claims in `X-Forwarded-For` and similar headers is discarded.

For the full rules, see "Client Address" in Appendix A (Operator Reference).

The case that needs care is an intermediary placed in front of the proxy.

- **An intermediary that does not add an `X-Forwarded-For` line**: it is the client, whether or not it is in `trusted_proxies`.
- **An intermediary that does not pass on the client address**: the clients behind it cannot be told apart. The country is decided by the address of the intermediary, and the rate limit counts them as one client.

## 6.4 Access Control (`access`)

Write the global access control in `access`. It has the same form as the `access` of a route and refuses by the same rules.

```text
{"deny_cidrs"?, "allow_cidrs"?, "deny_countries"?, "allow_countries"?}
```

| Setting key | Content |
|---|---|
| `deny_cidrs`, `allow_cidrs` | A list of networks. Written in the same way as `trusted_proxies` |
| `deny_countries`, `allow_countries` | A country list. A country is two uppercase letters of ISO 3166-1 alpha-2 (such as `JP`) or `UNKNOWN` |

For the range of each setting key, see "`access`" in Appendix A (Operator Reference).

- **Omitting**: all four are optional. An omitted setting key is an empty list, and if all four are empty, nobody is refused.
- **Refused clients**: a client is refused if any of the following applies.
  - It is in `deny_cidrs`
  - Its country is in `deny_countries`
  - `allow_cidrs` is not empty and the client is not in it
  - `allow_countries` is not empty and the country of the client is not in it
- **Both `allow_cidrs` and `allow_countries`**: only the clients that are in both pass. There is no way to let a network through regardless of its country.
- **Refusing response**: 403 with an empty body, without `Retry-After`.
- **Country lists and `geo`**: a country list needs `geo` (see section 6.7).

For example:

```json
"access": {
  "deny_cidrs": ["198.51.100.0/24"],
  "allow_countries": ["JP", "UNKNOWN"]
}
```

This example refuses clients of `198.51.100.0/24` and clients of countries other than `JP` and `UNKNOWN`.

The global `access` applies to requests that passed the header section checks (except ACME challenges and the admin route). If a host policy has its own `access`, though, requests to the hosts of that policy get that `access` instead of the global one (see section 6.6).

## 6.5 Rate Limits (`rate_limit`)

Write the global rate limit in `rate_limit`.

```text
{"rate", "burst", "keys", "exempt_cidrs"?}
```

| Setting key | Meaning |
|---|---|
| `rate` | The number of requests per second that one client may keep making |
| `burst` | The burst allowance: the number of requests let through back to back after an idle period. Up to `burst + 1` requests in a row pass, and refusal starts from the next one |
| `keys` | The maximum number of clients tracked |
| `exempt_cidrs` | Clients that are not counted (excluded networks). Written in the same way as `trusted_proxies`. Empty if omitted |

For the range of each setting key, see "Rate Limits (`rate_limit`)" in Appendix A (Operator Reference).

For example:

```json
"rate_limit": {
  "rate": 50,
  "burst": 100,
  "keys": 65536,
  "exempt_cidrs": ["192.0.2.0/24"]
}
```

This example lets one client make up to 50 requests per second. A client that has been idle gets up to 101 requests (`burst + 1`) through back to back. Up to 65536 clients are tracked, and clients in `192.0.2.0/24` are not counted.

Counting works as follows.

- **Unit of counting**: requests are counted one by one, not connections. In HTTP/2, each stream is counted.
- **Requests that pass**: a client that has been idle gets up to `burst + 1` requests through back to back, and the next one is refused. After that, one more request passes for each 1/`rate` seconds of waiting. A refused request does not change that client's count.
- **Unit of a client**: clients are counted per address for IPv4 and per upper 64 bits (/64) for IPv6. Changing the address within the same /64 does not increase the count.
- **Refusing response**: 429 with an empty body and a `Retry-After` whose value is always `1`.
- **Clients that are not counted**: the clients in `exempt_cidrs`, such as monitoring programs. They are not excluded from the access control, which applies before the rate limit.

Note the following about the size of the table that counts clients.

- **`keys` and memory**: `keys` is the maximum number of clients counted at the same time. One client takes about 100 bytes, so a `keys` of 1048576 takes about 100 MB. The total of the global `keys` and the `keys` of the host policies that have their own table also has a maximum.
- **When the table is full**: if the oldest client still has a count in the table, that client is removed to make room for the new one. A new client is never refused for lack of room. A removed client starts as a new client the next time it comes and again passes up to `burst + 1` requests, so the limit for that client is loosened once.
- **Number of removed clients**: it appears in `tukuyomi_rate_limit_evicted_total`. If requests come from many addresses, real clients are removed from the table and the limit is loosened, so make `keys` sufficiently larger than the number of clients that come at the same time.
- **Restart and reload**: the table is in the proxy's memory and is emptied by a restart. At a configuration reload, the global table continues if both the old and the new configuration have the global `rate_limit` and `keys`, `rate`, and `burst` are all the same. If any of them differs, or one of the two has no global `rate_limit`, counting starts from 0 in a new table, and the proxy writes a `reload: rate limit table started anew` line.

## 6.6 Host Policies (`host_policies`)

Write the host policies in `host_policies`. They are per-host settings that apply in place of the global access control and rate limit.

```text
[{"name", "hosts", "access"?, "rate_limit"?}, ..]
```

| Setting key | Meaning |
|---|---|
| `name` | The name. Two entries cannot have the same name. It is used to carry over rate limit tables |
| `hosts` | The hosts to apply to. The same form as the `host` of a route, without a port (a lowercase name, or `*.` and a name) |
| `access` | The access control for these hosts. The same form as the global `access` |
| `rate_limit` | The rate limit for these hosts. The same form as the global `rate_limit` with all of `rate`, `burst`, and `keys` written, or `{}` |

- **Hosts that cannot be written**: the same host cannot be written twice, not even in different entries, and the host of the admin route (`admin.route.host`) cannot be written. The number of entries and the number of hosts each have a maximum.
- **Empty entries**: an entry with neither `access` nor `rate_limit` is rejected.
- **How an entry is chosen**: by the `Host` of the request, in the same way as for routes. Case is ignored, one trailing `.` is dropped, and the port is not looked at. A named host matches before a `*.` host, and a longer `*.` host before a shorter one. The global settings apply to a request that matches no entry.

Access control and rate limiting each take one of the following three forms. The table also shows the wording on the admin screens.

| How to write | Admin screen wording | Access control | Rate limit |
|---|---|---|---|
| Do not write the setting key | Inherit | The global `access` applies | Counted in the global table. Requests from the same client are counted together with those to other hosts |
| Write a value | Settings for this host | This `access` applies instead of the global one | Counted in the table of this host policy instead of the global one |
| `{}` | Not used | Nobody is refused | Not counted |

For example:

```json
"host_policies": [
  {"name": "app", "hosts": ["app.example.com"], "access": {"allow_cidrs": ["203.0.113.0/24"]}},
  {"name": "api", "hosts": ["api.example.com", "*.api.example.com"], "rate_limit": {"rate": 20, "burst": 40, "keys": 65536}},
  {"name": "status", "hosts": ["status.example.com"], "access": {}, "rate_limit": {}}
]
```

In this example, the hosts are handled as follows.

- `app.example.com`: only clients in `203.0.113.0/24` can use it (the global `access` does not apply). Its rate limit is counted in the global table.
- `api.example.com` and `*.api.example.com`: the global `access` applies. Their rate limit is counted in the table of this entry.
- `status.example.com`: neither access control nor a rate limit applies.

Two points need care.

- **Hosts with "Settings for this host" and "Not used"**: refusals by the global settings (including a `deny_cidrs` added in a hurry) do not take effect for them. When you change the global settings, also review the host policies that do not inherit them.
- **Requests that arrive with another `Host`**: a host policy applies only to requests that arrive with its `Host`. Requests with another `Host` (a `Host` that is an IP address, or a name that is in no entry) may reach the same upstream through the default upstream, a route without `host`, or a `*.` route, and only the global settings apply to them. Writing a route for each host and leaving the default upstream empty avoids this.

Each entry has its own rate limit table, so one client can get through up to the global `rate` plus the `rate` of each entry.

At a configuration reload, a table is carried over when an entry with the same `name` has its own table both before and after, and `keys`, `rate`, and `burst` are all the same. Other entries start counting from empty.

For the detailed rules, such as how a `Host` that is an IPv6 address is handled, see "Host Policies (`host_policies`)" in Appendix A (Operator Reference).

## 6.7 Country Database (`geo`)

`geo` is the database that determines the country of the client address when you use a country list (`deny_countries` and `allow_countries`). Write both of its setting keys, `country_db` and `sha256`.

```text
{"country_db", "sha256"}
```

For example (the value of `sha256` is an example; write the value that `sha256sum` prints for your file):

```json
"geo": {
  "country_db": "/etc/tukuyomi-core/country.mmdb",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

- **Setting keys**: `country_db` is the absolute path of the country database file. `sha256` is the SHA-256 of that file (64 lowercase hexadecimal digits).
- **Preparing the file**: the file is in the MaxMind DB format (version 2). The proxy does not include a database and does not download one; the operator prepares it and places it. The operator is responsible for following the license terms of the database's provider.
- **How the country is decided**: by `country.iso_code` of the address record (`registered_country.iso_code` if that is missing). If neither exists, or if the code is not two uppercase letters, the country is `UNKNOWN`.
- **Addresses that become `UNKNOWN`**: loopback, private, link-local, and unspecified addresses, and addresses that the database does not know. With a database that has only IPv4 addresses, all IPv6 clients become `UNKNOWN`.
- **Whether to write `UNKNOWN`**: if you do not write `UNKNOWN` in `allow_countries`, clients with private addresses (such as monitoring on the same network) and IPv6 clients with an IPv4-only database are all refused. If you write `UNKNOWN` in `deny_countries`, those clients are refused.
- **Without `geo`**: a configuration with a country list (in the global `access`, the `access` of `host_policies`, or the `access` of a route) is rejected (`access has a list of countries while geo is left out`).

The proxy checks and loads the whole file at start and at every reload. The commands that read the whole configuration (`config check`, `acme renew`, `managed import`, `managed activate`) do the same, so the OS user of the service must be able to read the file. The admin process does not read the database.

Replace the database with these steps.

1. Place the new file under another name.
2. Change `country_db` and `sha256` together, in one write of the configuration file.
3. Check with `config check`.
4. Reload the proxy (SIGHUP, `systemctl reload`).

If you replace only the file, under the same name, then as long as `sha256` does not match it, the commands that read the whole configuration reject the configuration. A proxy that restarts also rejects it, and a reload of the proxy is refused. For all the checks, see "Country Database (`geo`)" in Appendix A (Operator Reference).

## 6.8 Editing in the Admin Screens

When you use the managed configuration, edit the global access control and rate limits and the host policies in the admin screens. Use the Access control and rate limits screen in the Policy menu, which an operator or above can use.

This screen shares one draft of the managed configuration with the Sites, Upstreams, and Routes screens. A change has no effect until you press "Save and apply" (see Chapter 5).

From the top, the screen has the following.

1. The notice "The global settings and the per-host settings do not apply to the admin route."
2. The panel for the global access control and rate limits
3. The list of host policies, with "Add a per-host setting"
4. The panel for editing the host policy that is open

In the editing panel, write a name and the hosts (one per line). For access control and for rate limiting, choose "Inherit", "Settings for this host", or "Not used". These correspond to the three forms in the table in section 6.6. Your input stays in the draft when you switch.

The screen shows the following.

- **When you change the global settings**: in a draft that changes the global access control or rate limit, the panel of the global settings and the confirmation of "Save and apply" show "This change does not apply to the {n} per-host setting(s) that do not inherit the global access control ({names})." (`{n}` is the number and `{names}` are the names; rate limits use the same form). This is because global changes (including an urgent denial) do not take effect for hosts with "Settings for this host" or "Not used".
- **List of host policies**: the list shows "A per-host setting applies only to requests whose Host header is one of its hosts. Only the global settings apply to requests for other hosts that reach the same upstream through the default upstream, a route whose host starts with *., or a route without a host. We recommend writing a route for each host and setting the default upstream to 'None'."
- **Where check errors point**: if you write a country list while the configuration file has no `geo`, the `at` of the check points to the access control of that host policy. If you write the same host as the admin route, the `at` of the check points to that row.

For the setting keys of a host policy, the rules for comparing hosts, and how the policies are layered, see "Host Policies (`host_policies`)" in Appendix A (Operator Reference). For the description of the screen, see "Admin Screens" in Appendix B (Admin Reference).

## 6.9 Operational Notes

- **Changing the global settings**: also review the host policies that do not inherit them ("Settings for this host" and "Not used"), because global refusals do not take effect for those hosts.
- **`allow_countries` and `UNKNOWN`**: when you write `allow_countries`, consider whether `UNKNOWN` is needed. Without `UNKNOWN`, clients with private addresses (such as monitoring on the same network) are refused.
- **Size of `keys`**: make `keys` of `rate_limit` sufficiently larger than the number of clients that come at the same time. If it is too small, real clients are removed from the table and the limit is loosened. The memory is about 100 bytes per client.
- **Finding the cause of a refusal**: the `reason` (`denied by access`, `too many requests`) and `host` in the log show the cause. Check the number of refusals with `tukuyomi_policy_refusals_total` in `/metrics` (see Chapter 7 and Chapter 9).
- **Admin screens without `managed`**: the global settings and the host policies apply to the host that forwards to the admin screens (see section 5.3). Set them to suit how many people use the admin screens and how often they send requests.
- **Combination with an earlier build**: an earlier build that does not know the setting key `host_policies` rejects a configuration file or a version that has it, as having an unknown setting key. The records shipper also reads the configuration file, so before you write `host_policies` in the configuration file, replace the records shipper with the same build as the proxy.
