[English](design-principles.md) | [日本語](design-principles.ja.md)

# Design Principles and Constraints

> **Status: initial draft**
>
> The five design principles are assumptions. How to apply them, the inspection modes, and the policies on porting, version management, and code structure are under study. For the implemented scope, see "Current Status" in the [system overview](system-overview.md).

## Scope of This Document

This document describes the design principles and candidate ways to apply them, the distinction between inspection modes and technical failures, where fail-closed applies, how logs and management functions are handled, how porting and precedents are handled, the policy on versions of dependencies, rules, and configuration, and the policy on code structure.

For the candidate structure and the design obligations, see the [architecture overview](architecture.md). For the assumptions and terms, see the [system overview](system-overview.md).

## Design Principles

When in doubt, decide by asking: "Would this survive an adversarial audit?"

### 1. Privilege Separation

Divide the system into units with a single responsibility each, so that faults do not spread sideways. Keep each element's privileges to a minimum.

Application (candidate):

- Treat inspection, HTTP receiving and forwarding, and administration as separate responsibilities.
- Separate processes alone do not give privilege separation. Decide together the OS user to run as, the files it can access, external communication, resource limits, and who is responsible for starting and restarting (AR-03, AR-04).
- Some rule functions widen the privileges that the inspection side needs: queries to the outside (DNS and so on), running external commands, and writing to files. Decide which functions to keep together with the privileges and OS restrictions they need. An allowlist of usable functions is a candidate, but no function is removed until it is decided whether to adopt it (DP-07, OV-01).

### 2. Distrust All Input

Treat all external data as an attack path. Validate type, length, and range explicitly at the boundary.

Application (candidate):

- Treat the following as input: client requests, upstream responses, settings, rules, input to the entry point for administration, and messages between processes (in both directions).
- The Rust proxy also validates the decisions and the log information that the inspector process returns.
- Identifiers sent by the client (such as a request ID) are not used to identify internal transactions.
- The proposal is to accept a header that carries the client's IP address only when it comes from a peer configured as trusted (DP-08).

### 3. Minimalism

The less code, the fewer bugs. Every dependency is a permanent liability.

Application (candidate):

- When adding a dependency, record why it is added and what the alternative without it would be.
- In the separate-process proposal, limit the inspector process to building Coraza rules and inspecting, and give it no other functions.
- Do not build features or abstractions before they are known to be needed.
- Minimalism does not mean less checking. Less code does not mean fewer checks of boundaries and failure cases.

### 4. Deterministic Resources

Make acquisition and release explicit. Consider overflow and boundaries, and do not rely on platform behavior.

Application (candidate):

- Put explicit limits on bodies, decompression (the size, and the CPU, memory, disk, and time used for decompression), arguments, concurrency, queues, spilling to disk, and time. The limit values are undecided (AR-09, AR-14).
- Decide the limits of the WAF instance (such as the body and arguments passed to the inspection engine) separately from the limits that apply when the Rust proxy receives and forwards. Whichever of On, DetectionOnly, Off, and explicit bypass is adopted, the proposal is that the Rust proxy keeps boundaries on resources and time when it receives and forwards (AR-09).
- When a limit is exceeded, do not truncate silently: either refuse, or treat it as explicit partial inspection. Partial inspection cannot be applied to traffic that requires inspection (AR-09). Which of the two applies is decided for each kind of traffic (DP-03).
- For transactions, temporary files, connections, and concurrency slots, decide who is responsible for releasing them in all normal and abnormal cases (AR-10, AR-15).
- Do not rely on the inspection engine's default values; set the values to use explicitly in the settings.

### 5. Structural Security

Build security into the structure, not as a later fix. Eliminate the class of vulnerability, not the symptom.

Application (candidate):

- When traffic that requires inspection (DP-02) becomes uninspectable, do not treat it like intended non-inspection, such as explicit bypass or Off. Whether to forward or refuse is decided for each mode and kind of failure (DP-03).
- Keep "no decision" distinct from "allow". When inspection was not done, record whether the reason was explicit bypass or uninspectable.
- Make inspection, decision, and forwarding interpret the form the same way (AR-07).
- Do not accept ambiguous HTTP framing as it is (AR-06).

## Inspection Modes Versus Technical Failures

The inspection mode is described along the following two axes.

| Axis | Values |
|---|---|
| Rule selection | The default rule set, a different rule set for each route, explicit bypass |
| Behavior of the chosen WAF instance | On, DetectionOnly, Off |

- Whether to keep these modes, and which ones, is undecided (DP-01, OV-01). The table below lists the points to decide if they are kept; it does not adopt any mode.
- Treat technical uninspectability as different both from intended non-inspection (explicit bypass, Off) and from inspection that does not execute disruptive actions (DetectionOnly).
- Technical uninspectability comes in kinds such as not yet ready, abnormal exit, no response, communication errors, timeout, limit exceeded, and build failure. How each combination of failure kind and mode is handled is covered by DP-03.
- Off and explicit bypass are not the same either. Even with Off, a design may involve the WAF instance side for logs and resource management.
- Some rule actions can change the behavior of the WAF instance and the handling of the body for each transaction. Where they can, the mode can also change from within the rules, so check this in the version to be adopted and decide it together with the range of usable functions (DP-07).

| Configured state | Intended behavior | Handling on a technical failure |
|---|---|---|
| Rule set (default or per route) + On | Executes the disruptive actions of rules (deny, drop, redirect, and so on) | For traffic that requires inspection (DP-02), the proposal is to refuse requests that cannot use the specified WAF instance (fail-closed). The conditions under which switching to other rules is allowed are covered by DP-04 |
| Rule set + DetectionOnly | Evaluates rules but does not execute disruptive actions. Whether logs are kept depends on the rules and the audit log settings (DP-10) | Detecting without blocking is not the same as a technical failure. Whether to refuse on a technical failure or to pass and record, and how to tell a technical failure apart from detection without blocking in the logs, is covered by DP-03. Whether DetectionOnly traffic counts as traffic that requires inspection is covered by DP-02 |
| Rule set + Off | Does not evaluate rules | What still needs the WAF instance (logs, resource management), and whether to forward on a failure, are covered by DP-03. The proposal is that the Rust proxy keeps its limits and timeouts for receiving and forwarding even with Off (AR-09, AR-14) |
| Explicit bypass (if kept, DP-01) | The proposal is not to call the inspector process | The proposal is that failures of the inspector process do not affect it, and that the Rust proxy keeps its limits and timeouts for receiving and forwarding (AR-09). The intent of the setting, the requirements for logs, and the form used for the decision are covered by DP-05 |
| Whether inspection is needed, or the route, cannot be determined | — | Not treated as bypass. Whether to treat it as traffic that requires inspection or to refuse it is covered by DP-03 (AR-07) |
| Failure to build or select a rule set | — | Decide the handling separately for a build failure at start, a failed update, and a reference to a rule set that does not exist. Whether to switch to the default rules or to refuse is covered by DP-04. For traffic that requires inspection, switching to a weaker setting (DetectionOnly, Off, explicit bypass) is not compatible with the candidate under principle 5. The requirements for logs and notification when switching are also covered by DP-04 |

## Where Fail-Closed Applies

- The candidate is that when traffic defined as requiring inspection becomes uninspectable, it is not turned into intended non-inspection. This is not applied uniformly to all modes and all traffic.
- The scope of "traffic that requires inspection" is undecided. For example, whether to include DetectionOnly traffic is handled in DP-02.
- The response returned to the client on a refusal is undecided (AR-16).
- Data that has already been forwarded cannot be taken back. How much may be sent before inspection completes is handled in AR-08.
- Partial inspection that forwards the uninspected rest is not compatible with fail-closed for traffic that requires inspection (AR-09).
- Switching to other rules when a rule set cannot be used is decided separately from fail-closed (DP-04).
- Upstream failures are handled separately from uninspectability (AR-18).

## Logs and Management Functions

Logs (DP-10):

- Logs may contain values sent by an attacker and sensitive data such as credentials and personal information. Decide what to record, how to hide sensitive data (masking and so on), how to handle control characters and the like in storage and display, who may view logs, their size, retention period, and capacity, and what to do when logs cannot be recorded.
- Treat log information, including what the inspector process returns, as input and validate it at the Rust proxy's boundary (AR-13).
- A candidate check is that log output does not become a way to leak information or to inject input into whatever views and analyzes the logs.
- The values, the storage method (OV-07), and the display method are undecided.

Management functions (if adopted; OV-03, AR-05):

- Studying the reuse and improvement of the admin UI is an assumption. If management functions are adopted, decide not only where they are placed but also authentication, how privileges are divided for each operation (changing rules and bypasses versus viewing logs, and so on), the change history, and how far changes reach.
- Treat input to the entry point for administration as untrusted input too (principle 2).
- Concrete roles, the authentication method, and the details of the screens are undecided.

## Porting and Precedents

The policy in this section is a candidate. How precedents are handled as a whole is covered by DP-06.

- The version to port from (OV-02) and the criteria for which features to keep (OV-01) are undecided. Until they are decided, no decision is made to keep, remove, or move any individual feature.
- If matching the behavior of the port's source is the only acceptance condition, that behavior becomes the specification without being checked. The proposal is to write the inspection scope down explicitly as a specification and to verify against it.
- For the behaviors of the port's source that need checking, the proposal is to record which to "copy", which to "fix", and which to "decide whether to adopt".
- Treat adding or removing features separately from the connection work needed to run the existing inspection scope correctly.

Candidates for how to divide precedents (DP-06):

| Subject | Precedent to refer to (candidate) |
|---|---|
| Product routes, configuration, logs, and operation | The implementation and design of tukuyomi. The scope to keep is covered by OV-01 |
| Input to Coraza, phases, decisions, and lifetime | The official Coraza API for the version to be adopted, and the official connection implementations. However, the modes and partial inspection settings in the official examples are not taken as the product specification as they are |
| Rust ownership, errors, and concurrency | Decided separately for tukuyomi-core |

When precedents behave differently, record the grounds and whether each is adopted in a design record before moving to implementation.

## Versions of Dependencies, Rules and Configuration

- At the time of adoption, confirm that the version is maintained and includes known fixes, and then pin the version. This document does not recommend a specific version.
- Upgrading the inspection engine is sometimes not enough. Check the settings and rules that refuse a request that reaches a limit or causes a parse error, together with the engine version (AR-09).
- In the libcoraza proposal, check both the version of the connection library and the version of Coraza included in it.
- In the separate-process proposal, check that the version combination of the two executables, the Rust proxy and the inspector process, matches the communication contract. How to keep them consistent is undecided: for example, detecting and rejecting a combination that does not match, or distributing only combinations known to match (AR-13, OV-06).
- Pin and check the rule set version and the inspection engine's settings in the same way.
- When comparing connection methods, record the Coraza version on the side that uses the Go API directly and the Coraza version included in libcoraza, make them part of the comparison conditions, and align them if possible. If they cannot be aligned, the comparison is between configurations that include their versions, and no conclusion is drawn that the difference comes only from the connection method.
- Repeat the same checks each time a version is updated. The procedure for checking is undecided (DP-09).

## Code Structure

- Organize code by responsibility, type, and owner. Do not split files excessively.
- This document does not define the concrete structure of modules and files; it is decided as needed at the time of implementation.

## Open Points

| ID | Item | Current handling | Related |
|---|---|---|---|
| DP-01 | How far to keep the inspection modes (rule selection, behavior of the WAF instance, explicit bypass) | Undecided | OV-01, DP-07 |
| DP-02 | The definition of traffic that requires inspection (whether to include DetectionOnly traffic, and so on) | Undecided | DP-03 |
| DP-03 | How a technical failure is handled for each combination of failure kind and mode (including when it cannot be determined whether inspection is needed) | Undecided. The proposal is to refuse traffic that requires inspection under On | AR-07, AR-09, AR-16 |
| DP-04 | Switching (fallback) when building or selecting a rule set fails, limits on what it may switch to, and logs and notification | Undecided | AR-11, AR-12 |
| DP-05 | The form used to decide explicit bypass, and the requirements for logs | Undecided | AR-07, DP-10 |
| DP-06 | How to divide precedents when porting | Dividing them into three subjects is a candidate | OV-02 |
| DP-07 | The functions usable in rules, decided together with the privileges they need | Undecided. An allowlist of usable functions is a candidate | AR-04, OV-01, DP-01 |
| DP-08 | Trust settings for headers that carry the client's IP address and the like | Undecided | AR-10, OV-01 |
| DP-09 | The procedure to check and pin the versions of dependencies, rules, and configuration (including the combination of the two executables and recording the Coraza version used in the comparison) | The policy is to check at adoption. The procedure is undecided | AR-01, AR-13, OV-06 |
| DP-10 | Requirements for logs and audit logs, including which process writes them, what to record, how to handle sensitive data, how to handle control characters and the like in storage and display, who may view them, their size, retention period, and capacity, and whether to keep forwarding when logs cannot be recorded | Undecided | AR-05, AR-10, AR-13, AR-18, OV-03, OV-07 |

## Related Documents

- [System Overview](system-overview.md)
- [Architecture Overview](architecture.md)
- [Documentation Index](../../README.md)
