[English](design-principles.md) | [日本語](design-principles.ja.md)

# Design Principles and Constraints

> **Status: initial draft**
>
> The five design principles are assumed. How to apply the principles, the inspection modes, and the policies on porting, version management, and code structure are under study. For the implemented scope, see "Current Status" in the [system overview](system-overview.md).

## Scope of This Document

This document shows the design principles and the candidates for applying them, the distinction between inspection modes and technical failures, where fail-closed applies, the handling of logs and management functions, the handling of porting and precedents, the policy on the versions of dependencies, rules, and configuration, and the policy on code structure.

For the candidate structure and the design obligations, see the [architecture overview](architecture.md). For the assumptions and terms, see the [system overview](system-overview.md).

## Design Principles

When in doubt, decide by asking: "Would this survive an adversarial audit?"

### 1. Privilege Separation

Divide the system into units with a single responsibility, and do not let faults spread sideways. Keep the privileges of each element to the minimum.

Application (candidate):

- Treat inspection, HTTP receiving and forwarding, and administration as separate responsibilities.
- Separating processes alone does not give privilege separation. Decide as a set the OS user to run as, the files it can access, external communication, the limits on resources, and the responsibility for start and restart (AR-03, AR-04).
- Among the functions of rules, queries to the outside (DNS and so on), running external commands, and writing to files widen the privileges needed on the inspection side. Decide the functions to keep together with the privileges and OS restrictions they need. An allowlist of usable functions is a candidate, but functions are not removed until the decision to adopt or not is made (DP-07, OV-01).

### 2. Distrust All Input

Treat all external data as an attack path. Validate type, length, and range explicitly at the boundary.

Application (candidate):

- Treat as input client requests, upstream responses, settings, rules, input to the entrance for administration, and messages between processes (in both directions).
- Decisions and information for logs returned from the inspector process are also validated in the Rust proxy.
- Identifiers sent by the client (such as a request ID) are not used as the identifier of an internal transaction.
- The proposal is to adopt a header that shows the client's IP address only when it comes from a peer configured as trusted (DP-08).

### 3. Minimalism

The less code, the fewer bugs. Every dependency is a permanent liability.

Application (candidate):

- When adding a dependency, record the reason and the alternative of not adding it.
- In the separate-process proposal, limit the inspector process to building and inspecting Coraza rules, and give it no other functions.
- Do not build in advance features or abstractions whose necessity has not been confirmed.
- Minimalism does not mean less checking. Even if code is reduced, the checks of boundaries and failure cases are not reduced.

### 4. Deterministic Resources

Make acquisition and release explicit. Consider overflow and boundaries, and do not rely on platform behavior.

Application (candidate):

- Put explicit limits on bodies, decompression (the size, and the CPU, memory, disk, and time used for decompression), arguments, concurrency, queues, spilling to disk, and time. The values are undecided (AR-09, AR-14).
- Decide separately the limits of the WAF instance (the body and arguments passed to the inspection engine) and the limits when the Rust proxy receives and forwards. Whichever of On, DetectionOnly, Off, and explicit bypass is adopted, the proposal is that the Rust proxy has boundaries on resources and time when it receives and forwards (AR-09).
- When a limit is exceeded, do not truncate silently; refuse, or treat it as explicit partial inspection. Partial inspection cannot be applied to traffic that requires inspection (AR-09). Which of the two applies is decided for each kind of traffic (DP-03).
- For transactions, temporary files, connections, and concurrency slots, decide who is responsible for release in all normal and abnormal cases (AR-10, AR-15).
- Do not rely on the default values of the inspection engine; state the values to use explicitly in the settings.

### 5. Structural Security

Build security into the structure, not as a later fix. Eliminate the kind of vulnerability, not the symptom.

Application (candidate):

- Do not treat the uninspectability of traffic that requires inspection (DP-02) as the same as intended non-inspection such as explicit bypass or Off. Whether to forward or refuse is decided for each mode and kind of failure (DP-03).
- Distinguish "no decision" from "allow". Record separately the reason inspection was not done (explicit bypass or uninspectable).
- Align the interpretation of the form among inspection, decision, and forwarding (AR-07).
- Do not accept ambiguity in HTTP framing as it is (AR-06).

## Inspection Modes Versus Technical Failures

The inspection mode is handled in terms of the following two axes.

| Axis | Values |
|---|---|
| Rule selection | The default rule set, a different rule set for each route, explicit bypass |
| Behavior of the chosen WAF instance | On, DetectionOnly, Off |

- Whether to keep these modes, and which to keep, is undecided (DP-01, OV-01). The following table shows the points to decide if they are kept, and does not decide the adoption of any mode.
- Treat intended non-inspection (explicit bypass, Off), and inspection that does not execute disruptive actions (DetectionOnly), as different from technical uninspectability.
- Technical uninspectability has kinds such as before ready, abnormal exit, no response, communication anomaly, timeout, limit exceeded, and build failure. The handling for each combination of kind of failure and mode is decided in DP-03.
- Off and explicit bypass are not the same either. Even with Off, there can be designs in which the WAF instance side is involved for logs and resource management.
- Depending on rule actions, the behavior of the WAF instance and the handling of the body can sometimes be changed for each transaction. In that case, the mode can also change from within the rules, so check it in the version to be adopted and decide it together with the range of usable functions (DP-07).

| Configured state | Intended behavior | Handling on a technical failure |
|---|---|---|
| Rule set (default or per route) + On | Executes the disruptive actions of rules (deny, drop, redirect, and so on) | For traffic that requires inspection (DP-02), the proposal is to refuse what cannot use the specified WAF instance (fail-closed). The condition under which switching to other rules is allowed is DP-04 |
| Rule set + DetectionOnly | Evaluates rules but does not execute disruptive actions. Whether logs remain depends on the rules and the audit log settings (DP-10) | Detecting without blocking is different from a technical failure. Whether to refuse on a technical failure, or to pass and record, and how to distinguish this in the logs, is DP-03. Whether to include DetectionOnly traffic in traffic that requires inspection is DP-02 |
| Rule set + Off | Does not evaluate rules | The range that needs the WAF instance (logs, resource management), and whether to forward on a failure, is DP-03. The proposal is that the limits and timeouts when the Rust proxy receives and forwards are kept even with Off (AR-09, AR-14) |
| Explicit bypass (if kept, DP-01) | The proposal is not to call the inspector process | The proposal is that it is not affected by failures of the inspector process. The proposal is that the limits and timeouts when the Rust proxy receives and forwards are kept (AR-09). The intent of the setting, the requirements for logs, and the form used for the decision are DP-05 |
| Whether inspection is needed, or the route, cannot be decided | — | Not treated as bypass. Whether to treat it as traffic that requires inspection, or to refuse it, is DP-03 (AR-07) |
| Failure to build or select a rule set | — | Decide separately a failure to build at start, a failure to update, and a reference to a rule set that does not exist. Whether to switch to the default rules or to refuse is DP-04. For traffic that requires inspection, switching to a weaker setting (DetectionOnly, Off, explicit bypass) is not compatible with the candidate of principle 5. The requirements for logs and notification when switching are also decided in DP-04 |

## Where Fail-Closed Applies

- The candidate is to not convert the uninspectability of traffic defined as requiring inspection into intended non-inspection. It is not applied uniformly to all modes and all traffic.
- The range of "traffic that requires inspection" is undecided. For example, whether to include DetectionOnly traffic is handled in DP-02.
- The response returned to the client on a refusal is undecided (AR-16).
- Data that has already been forwarded cannot be taken back. The range that may be sent before inspection completes is handled in AR-08.
- Partial inspection that forwards the uninspected rest is not compatible with fail-closed for traffic that requires inspection (AR-09).
- Switching to other rules when a rule set cannot be used is decided separately from fail-closed (DP-04).
- Upstream failures are handled separately from uninspectability (AR-18).

## Logs and Management Functions

Logs (DP-10):

- Logs may contain values sent by an attacker and sensitive data such as credentials and personal information. Decide the items to record, how to hide sensitive data (masking and so on), the handling of control characters and so on in storage and display, the permissions to view, the size, retention period, and capacity, and the handling when recording is not possible.
- Treat the information for logs, including what the inspector process returns, as input and validate it at the boundary of the Rust proxy (AR-13).
- Make it a candidate for verification that the output of logs does not become an entrance for leaking information or for injecting input into the side that views and analyzes the logs.
- The values, the storage method (OV-07), and the display method are undecided.

Management functions (if adopted; OV-03, AR-05):

- Studying reuse and improvement of the admin UI is an assumption. If adopted, decide not only the placement but also authentication, how privileges are divided for each operation (changes to rules and bypass versus viewing logs, and so on), the history of changes, and the scope that changes reach.
- Treat input to the entrance for administration as untrusted input too (principle 2).
- Concrete roles, the authentication method, and the details of the screens are undecided.

## Porting and Precedents

The policy in this section is a candidate. The handling of precedents as a whole is decided in DP-06.

- The version to port from (OV-02) and the criteria for the features to keep (OV-01) are undecided. Until they are decided, no individual feature is decided to be kept, removed, or moved.
- If matching the behavior of the source of the port is made the only acceptance condition, the behavior of the source is fixed as a specification without checking it. The proposal is to state the inspection scope explicitly as a specification and to verify against the specification.
- The proposal is to record, among the behaviors of the source of the port that need checking, which to "copy", which to "fix", and which to "decide whether to adopt".
- Treat adding or removing features separately from connection work that is needed to run the existing inspection scope correctly.

Candidates for how to divide precedents (DP-06):

| Subject | Precedent to refer to (candidate) |
|---|---|
| Product routes, configuration, logs, and operation | The implementation and design of tukuyomi. The scope to keep is decided in OV-01 |
| Input to Coraza, phases, decisions, and lifetime | The official Coraza API of the version to be adopted, and the official connection implementations. However, the modes and partial inspection settings of the official examples are not made the product specification as they are |
| Rust ownership, errors, and concurrency | Decided separately in tukuyomi-core |

When precedents disagree in behavior, move to implementation after recording the grounds and the decision to adopt or not in a design record.

## Versions of Dependencies, Rules and Configuration

- At the time of adoption, confirm that the version is maintained and includes known fixes, and pin the version. This document does not recommend a specific version.
- Raising the version of the inspection engine is sometimes not enough. Check the settings and rules that refuse reaching a limit or a parsing error together with the version of the engine (AR-09).
- In the libcoraza proposal, check both the version of the connection library and the version of Coraza included in it.
- In the separate-process proposal, check that the combination of versions of the two executables, the Rust proxy and the inspector process, matches the communication contract. Whether to detect a combination that does not match and reject it, or to distribute only combinations known to match, is undecided (AR-13, OV-06).
- Pin and check the version of the rule set and the settings of the inspection engine in the same way.
- When comparing connection methods, record the Coraza version on the side that uses the Go API directly and the Coraza version included in libcoraza, include them in the conditions of the comparison, and align them if possible. If they cannot be aligned, it is a comparison between configurations that include the versions, and it is not concluded that the difference is only in the connection method.
- Repeat the same checks each time a version is updated. The procedure for checking is undecided (DP-09).

## Code Structure

- Organize code by responsibility, type, and owner. Do not split files excessively.
- The concrete structure of modules and files is decided as needed at the time of implementation. It is not defined in this document.

## Open Points

| ID | Item | Current handling | Related |
|---|---|---|---|
| DP-01 | How far to keep the inspection modes (rule selection, behavior of the WAF instance, explicit bypass) | Undecided | OV-01, DP-07 |
| DP-02 | The definition of traffic that requires inspection (whether to include DetectionOnly traffic, and so on) | Undecided | DP-03 |
| DP-03 | The handling on a technical failure for each combination of kind of failure and mode (including when whether inspection is needed cannot be decided) | Undecided. The proposal is to refuse traffic that requires inspection with On | AR-07, AR-09, AR-16 |
| DP-04 | Switching (fallback) when building or selecting a rule set fails, the limits on the switch destination, and logs and notification | Undecided | AR-11, AR-12 |
| DP-05 | The form used to decide explicit bypass, and the requirements for logs | Undecided | AR-07, DP-10 |
| DP-06 | How to divide precedents when porting | The proposal to divide into three subjects is a candidate | OV-02 |
| DP-07 | The functions usable in rules, and the privileges they need, as a set | Undecided. An allowlist of usable functions is a candidate | AR-04, OV-01, DP-01 |
| DP-08 | Trust settings for headers that show the client's IP address and so on | Undecided | AR-10, OV-01 |
| DP-09 | The procedure to check and pin the versions of dependencies, rules, and configuration (including the combination of the two executables and recording the Coraza version used in the comparison) | A policy of checking at adoption. The procedure is undecided | AR-01, AR-13, OV-06 |
| DP-10 | Requirements for logs and audit logs. This includes which process writes them, the items to record, the handling of sensitive data, the handling of control characters and so on in storage and display, the permissions to view, the size, retention period, and capacity, and whether to continue forwarding when recording is not possible | Undecided | AR-05, AR-10, AR-13, AR-18, OV-03, OV-07 |

## Related Documents

- [System Overview](system-overview.md)
- [Architecture Overview](architecture.md)
- [Documentation Index](../../README.md)
