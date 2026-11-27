# tukuyomi-core

WAF reverse proxy with Coraza / ModSecurity

[English](README.md) | [日本語](README.ja.md)

## Overview

`tukuyomi-core` is an HTTP/HTTPS reverse proxy with a built-in WAF (Web Application Firewall). It inspects incoming requests with Coraza or ModSecurity v3 and forwards them to upstreams. Inspection uses rule sets such as the OWASP Core Rule Set (CRS). It is derived from [tukuyomi](https://github.com/vril-dev/tukuyomi) and aims to be a product focused on the WAF.

Main features:

- Receiving HTTP/1.1 and HTTP/2 (over TLS) requests and forwarding them to upstreams
- Request inspection with Coraza or ModSecurity v3 (rule set generations and a detect-only mode)
- Access control by IP address and country, and rate limiting (global and per host)
- Certificate issuance and renewal with ACME (HTTP-01)
- Admin API and admin UI (editing the managed configuration and applying it without stopping the proxy, rule set generations, log search, audit log)
- Log files, and log shipping to PostgreSQL / MySQL

For what is and is not implemented, see "Current Status" in the [system overview](docs/detailed-design/00_overview/system-overview.md).

> The product as a whole has not had a security review yet.

## Installation

It has been tested only on Linux x86_64 with Landlock enabled.

Requirements:

- Linux 5.13 or later, with Landlock enabled
- glibc 2.39 or later (for the release binaries; the ModSecurity inspector also needs libstdc++)

Download the tarball and its checksum file from the [GitHub releases](https://github.com/vril-dev/tukuyomi-core/releases), verify the checksum, and extract the tarball.

```bash
sha256sum -c tukuyomi-core_v0.2.2_linux_amd64.tar.gz.sha256
tar -xzf tukuyomi-core_v0.2.2_linux_amd64.tar.gz
```

The CRS is not bundled. Fetch it with `scripts/fetch-crs.sh`.

For deployment, the first start, and building from source (which requires Rust 1.94.1 and Go 1.27.2), see [docs/build/binary-deployment.md](docs/build/binary-deployment.md).

## Documentation

The documentation is available in English and Japanese.

- Documentation index: [docs/README.md](docs/README.md)
- Build and deployment: [docs/build/binary-deployment.md](docs/build/binary-deployment.md)
- Operator reference: [docs/operations/operator-reference.md](docs/operations/operator-reference.md)
- Admin reference: [docs/operations/admin-reference.md](docs/operations/admin-reference.md)
- System overview: [docs/detailed-design/00_overview/system-overview.md](docs/detailed-design/00_overview/system-overview.md)

## License

tukuyomi-core is released under the BSD 2-Clause License. See [LICENSE](LICENSE).

The executables include third-party software. Its licenses and copyright notices are in [NOTICE](NOTICE) and [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES).
