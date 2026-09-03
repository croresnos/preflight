# Blast Chambers resource-only threat model

Status: design and pre-activation implementation. No released version currently
claims this boundary.

## Protected assets and adversary

The long-term product protects host files, credentials, registry, network
identity, other processes, service identity, policy and artifact integrity,
resource availability, and audit truth. Resource-only addresses only the subset
listed below.

Assume the workload is arbitrary malicious native user-mode code. It may send
malformed or replayed IPC, race files, create process storms and nested
children, exhaust CPU, memory, time, and output, request breakaway, crash,
disconnect its client, or deliberately terminate reachable components.

Local administrators, kernel compromise, malicious drivers, physical attacks,
and Windows kernel escapes are outside this boundary.

## Resource-only guarantee

Resource-only may be reported only when all acceptance evidence proves:

- the client authenticated the SCM-owned service endpoint and the service
  authenticated the caller;
- the target launches with no more authority than the caller;
- its first instruction cannot execute before successful Job Object assignment;
- direct job-member CPU, memory, process count, output, and wall time are
  bounded;
- disconnect, service failure, or owned-handle closure kills the entire job;
- the service seals deterministic, signed, hash-chained evidence.

Job Objects constrain processes that remain members of the job. Resource-only
does **not** restrict ordinary user-file or registry access, credentials,
network and loopback, UI or devices, persistence, injection, or same-user
brokers. Negative controls must demonstrate those gaps and the report must keep
their protection flags false.

Standard and Maximum remain unavailable. Standard requires an AppContainer/LPAC
boundary with proven broker policy. Maximum additionally requires an
independent-kernel boundary.

## Fail-closed invariants

The service state is strictly:

    authenticated -> staged -> limits verified -> created suspended -> assigned
    -> resumed -> running -> terminating -> sealed

No transition can be skipped. Every Win32 failure before resume terminates the
suspended process and proves its tripwire did not run. Every failure after
resume terminates the job. Service absence, identity or token mismatch,
protocol mismatch, replay, evidence failure, and unavailable controls produce
"backend_unavailable"; the Windows client never selects the Python runner as a
fallback.

## Activation rule

Building the crates is not activation. The native backend may become available
only after the privileged Windows 11 acceptance manifest records every hostile
fixture, failure-injection point, parser mutation target, identity/handle check,
negative control, Python compatibility test, and the repository merge gate as
passing. Missing proof is "pending", never inferred from API availability.
