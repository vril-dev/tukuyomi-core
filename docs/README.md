[English](README.md) | [日本語](README.ja.md)

# Documentation Index

This is the list of tukuyomi-core documentation. tukuyomi-core is derived from tukuyomi (the tukuyomi WAF) and aims to be a product focused on the WAF.

The main features implemented today are request inspection by the WAF, receiving and forwarding HTTP/HTTPS, access control and rate limits by IP address and country, the admin process (admin API and admin screens), the managed configuration, and the records shipper. The source is in the following directories:

- [`kernel/`](../kernel/): a Rust library that starts and monitors the inspector processes and hands requests over for inspection
- [`inspector/`](../inspector/): the inspector process written in Go, which uses Coraza
- [`inspector-modsecurity/`](../inspector-modsecurity/): the inspector process that uses ModSecurity v3
- [`proxy/`](../proxy/): the proxy (including the admin process and the admin screens in [`proxy/admin-ui/`](../proxy/admin-ui/))
- [`records-ship/`](../records-ship/): the records shipper

Since 0.1.0, the four executables for Linux x86_64 have been bundled into one tarball and distributed through GitHub releases (see "Release Tarball" in the [build and deployment guide](build/binary-deployment.md)).

The documents in `build/` and `operations/` explain how to use the current implementation. The documents in `detailed-design/` are initial drafts that record goals, assumptions, candidates, and open points. For the implemented scope, see "Current Status" in the [system overview](detailed-design/00_overview/system-overview.md).

## Documents

| Document | Content |
|---|---|
| [System Overview](detailed-design/00_overview/system-overview.md) | The purpose of the product, the current status (the implemented scope and the features not implemented), the distinction between assumptions, candidates, and open points, the scope under study, and terms |
| [Architecture Overview](detailed-design/00_overview/architecture.md) | The candidate structure, privilege and resource boundaries, failure scope, an example of the request flow, design obligations, combinations of states and operations, and the candidate checks needed for the decision |
| [Design Principles and Constraints](detailed-design/00_overview/design-principles.md) | The design principles and how they apply, the distinction between inspection modes and technical failures, where fail-closed applies, how logs and management functions are handled, how porting and precedents are handled, versions of dependencies, rules, and configuration, and code structure |
| [Build and Deployment](build/binary-deployment.md) | Components, requirements, the release tarball, building from source, fetching the CRS, the OS user and directories, the country database, the first start, example systemd unit files (including the admin process, the records shipper, and the certificate renewal timer), restricting the inspector processes with Landlock and other mechanisms, and checks before start |
| [Operator Reference](operations/operator-reference.md) | Commands, signals, stopping, the setting keys of the configuration file and the relations between values, request body limits and the inspected length, rule sets and generations (choosing the inspection engine, the chosen generation per engine), the managed configuration (deciding whether to use it, the managed store and versions, the first start, moving from a configuration file, applying), request handling, access control and rate limits by IP address and country (global and per host), log lines and log files, the records shipper (PostgreSQL and MySQL), monitoring, ACME, and version updates |
| [Admin Reference](operations/admin-reference.md) | The commands and listener of the admin process, the setting key `admin`, access from outside (including the admin route when the managed configuration is used), users and roles, login and two-factor authentication, lockout and attempt limits, sessions, CSRF protection and Origin checks, API tokens, the audit log, generation operations, managed configuration operations, the switch history, the configuration history, reading logs, the admin screens, and the list of API paths and the response format |

Open points are collected in a table at the end of each design document, with IDs that do not overlap across documents (OV- for the system overview, AR- for the architecture overview, DP- for the design principles and constraints).

Each document is available in English (`.md`) and Japanese (`.ja.md`).

## Planned Structure

The following tree is the planned structure of the documents. The only documents created so far are the six in the table above. The other files and directories in the tree (including `detailed-design/README.md`) have not been created yet. They will be created when their content is written.

```text
docs/
├── build/                              # Build and Deployment
│   └── binary-deployment.md            # Build and Deployment
│
├── operations/                         # Operations
│   ├── operator-reference.md           # Operator Reference
│   └── admin-reference.md              # Admin Reference
│
└── detailed-design/                    # Detailed Design
    ├── 00_overview/                    # Overview and General Policy
    │   ├── system-overview.md          # System Overview
    │   ├── architecture.md             # Architecture Overview
    │   └── design-principles.md        # Design Principles and Constraints
    │
    ├── 01_requirements/                # Traceability to Requirements
    │   ├── functional-requirements.md  # Mapping to Functional Requirements
    │   └── non-functional.md           # Mapping to Non-Functional Requirements
    │
    ├── 02_architecture/                # Architecture Design
    │   ├── high-level.md               # Overall Structure
    │   ├── component-diagram.md        # Component Diagram
    │   ├── sequence-diagrams/          # Sequence Diagrams
    │   ├── data-flow.md                # Data Flow
    │   └── deployment.md               # Deployment Structure
    │
    ├── 03_modules/                     # Module and Component Details
    │
    ├── 04_data/                        # Data Design
    │   ├── er-diagram.md               # ER Diagram
    │   ├── table-definitions.md        # Table Definitions
    │   ├── data-dictionary.md          # Data Dictionary
    │   └── file-formats.md             # File and External Data Formats
    │
    ├── 05_api/                         # API Design
    │   ├── rest-api.md                 # REST API Specification
    │   ├── internal-api.md             # Internal API
    │   └── message-formats.md          # Message and Event Formats
    │
    ├── 06_ui/                          # UI Design (If Needed)
    │   ├── screen-list.md              # Screen List
    │   ├── screen-transitions.md       # Screen Transitions
    │   └── components.md               # UI Components
    │
    ├── 07_security/                    # Security Design
    │   ├── authentication.md
    │   ├── authorization.md
    │   └── data-protection.md
    │
    ├── 08_error-handling/              # Error Handling and Exception Design
    │   └── error-codes.md
    │
    ├── 09_performance/                 # Performance and Scalability
    │   └── performance-design.md
    │
    ├── 10_ops/                         # Operations and Monitoring Design
    │   ├── logging.md
    │   ├── monitoring.md
    │   └── backup-recovery.md
    │
    ├── appendices/                     # Appendices
    │   ├── glossary.md                 # Glossary
    │   ├── references.md               # References
    │   └── change-history.md           # Change History
    │
    └── README.md                       # Description and Reading Guide for This Directory
```
