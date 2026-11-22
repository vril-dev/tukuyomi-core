# Preface

This book is an English guide to deploying and operating **tukuyomi core** yourself. tukuyomi core is an HTTP/HTTPS reverse proxy with a built-in WAF (Web Application Firewall).

tukuyomi core inspects incoming requests with Coraza or ModSecurity v3 and forwards them to upstreams. Inspection uses rule sets such as the OWASP Core Rule Set (CRS).

The book starts with getting a release and starting it for the first time, and goes on to rule set management, the admin screens, logs, certificates, and day-to-day operations. It is meant to be read from start to finish.

## Scope of This Book

This book covers only the features that tukuyomi core 0.2.0 implements. What is not implemented or not decided is marked as such, and is summarized in section 1.7 ("What Is Implemented and What Is Not").

As the repository's README notes, the product as a whole has not had a security review yet.

## Who This Book Is For

- Engineers who deploy and operate a reverse proxy with a built-in WAF in front of a web service (infrastructure, SRE, and platform teams)

The book assumes that you know the basic concepts of Linux, HTTP/HTTPS, TLS, and systemd.

## Version Covered by This Book

This book is written for **tukuyomi core 0.2.0**. The release file names in the procedures are those of `v0.2.0`.

If a later release changes setting keys, commands, log lines, or the like, check the following first; they take precedence over this book:

- The documentation in the repository
- The release notes of each version, published with the GitHub releases

## How to Read This Book

Read in order, the book takes you all the way from getting the release and starting it for the first time to a production deployment and day-to-day operations.

- **Chapter 1** explains what tukuyomi core does and which processes it consists of. It also lists what 0.2.0 implements and what it does not.
- **Chapter 2** shows, step by step, how to start tukuyomi core by hand from the release tarball and confirm that an SQL injection request is blocked.
- **Chapter 3** explains a production deployment with systemd.
- **Chapters 4 to 9** cover rule sets and generations, the managed configuration and the admin screens, access control and rate limiting, logs and the records shipper, certificates with ACME, and day-to-day operations, one topic per chapter. If you already run tukuyomi core, you can go straight to the chapter you need from the table of contents.
- **Appendix A. Operator Reference** and **Appendix B. Admin Reference** at the end of the book contain the text of the operator reference and the admin reference from the documentation in the repository. Only the heading levels and the links between documents are changed to fit the book.
- **Appendix C. Release Notes** contains the release notes of 0.2.0 and 0.1.0.

Each chapter follows the same order: overview, how it works, configuration examples, and operational notes. Each one opens with what it covers, and can be read on its own.

The chapters are written as a guide. They explain why a step is taken, where to start, and where readers tend to get stuck, and leave the lists of setting keys, the ranges of values, and the detailed notes to the appendices. To check a specific setting key or behavior, open the section of the appendix that the text points to. Where the text says see "…" in Appendix A (Operator Reference), it means the section with that heading in Appendix A.

## Conventions

- The text follows the style of the English documentation.
- Setting keys, commands, and log lines are spelled as in the documentation and set as `code`, for example `proxy.max_body`, `rules import`, and `start: listening`. Log lines are quoted exactly as the product writes them.
- Terms used on the admin screens are also spelled as in the documentation.
- Technical terms are the same as in the documentation, and common terms such as request, log, block, upstream, route, and listener have their usual meaning.
- The product name is written tukuyomi core in the text. Executable names (`tukuyomi-proxy` and others), directory names, and file names are spelled as they are, including those that contain `tukuyomi-core`. The product that tukuyomi core is derived from is called upstream tukuyomi.
- Commands are shown in code blocks like the following. tukuyomi core does not run as root, so commands are written to run as `tukuyomi`, the OS user of the service (`sudo -u tukuyomi ...`).

  ```bash
  sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
  ```

- A word between `<` and `>` stands for a part that you replace with an actual value. For example:
  - `<config>`: the path of the configuration file
  - `<fingerprint>`: the fingerprint of a rule set generation
  - `<version>`: a version of the managed configuration
  - `<engine>`: the name of an inspection engine (`coraza` or `modsecurity`)
- Paths and names follow the examples in the documentation, and every path in the configuration is an absolute path. All of the following are examples; change them to fit your environment.
  - Executables: `/opt/tukuyomi-core/bin/`
  - Configuration file: `/etc/tukuyomi-core/config.json`
  - Directories for state: under `/var/lib/tukuyomi-core`
  - OS user: `tukuyomi`
  - Host name: `example.com`
  - Network: `192.0.2.0/24`

## Relation to the Documentation

The documentation in the repository (`docs/`; English in `foo.md`, Japanese in `foo.ja.md`) is the authoritative source for how setting keys, commands, signals, log formats, and the admin API are defined and how they behave. It consists of six documents: System Overview, Architecture Overview, Design Principles and Constraints, Build and Deployment, Operator Reference, and Admin Reference ("Documents" in `docs/README.md`). Of these, System Overview, Architecture Overview, and Design Principles and Constraints are initial drafts that record goals, assumptions, candidates, and open points (see section 1.7).

This book rearranges the documentation into a guide that can be read in order, and states no fact that is not in the documentation. Appendix A and Appendix B contain the text of the operator reference and the admin reference. When the text refers to another document in the repository, it gives the name of the document and the heading, as in "Building from Source" in Build and Deployment.

If this book and the documentation seem to disagree, follow the documentation. When a new release comes out, check the documentation and the release notes of that release first.

Chapter 1 begins with an overview of what tukuyomi core does and which processes it consists of.
