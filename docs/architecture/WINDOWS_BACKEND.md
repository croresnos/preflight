# Windows Blast Chambers enforcement backend

Status: design contract for the next implementation phase. No current command
may claim Standard or Maximum isolation until the corresponding acceptance
tests in this document pass on a clean Windows 11 machine.

The earlier resource-only slice is governed separately by
ADR-0001-BLAST-CHAMBERS-RESOURCE-BOUNDARY.md and the Blast Chambers threat
model. Job Object resource enforcement does not satisfy any Standard control.

## Boundary

The Python package remains an unprivileged client and deterministic policy
library. A native Blast Chambers Windows service owns every privileged or
security-sensitive operation. The first implementation language is Rust, using explicit Win32
bindings, a small dependency surface, memory-safe request parsing, and a single
versioned protocol shared by CLI, desktop UI, IDEs, and supported agents.

```text
CLI / UI / IDE / agent
        |
        | authenticated, versioned named-pipe protocol
        v
Preflight Blast Chambers service (LocalService identity)
        |-- artifact store and evidence signing key
        |-- Standard launcher: AppContainer + Job Object
        |-- credential/action brokers
        `-- Maximum controller: disposable Hyper-V compute system
```

The service never trusts a client claim about its user, project, executable,
artifact hash, or policy. It impersonates the named-pipe caller, validates the
caller's token and executable identity, reopens files itself, and recomputes all
security-critical hashes.

## Standard launch sequence

1. Resolve the immutable artifact and dependency graph from the service-owned
   content store. Refuse writable or unverified inputs.
2. Create a unique AppContainer identity for the project and sandbox version.
   Grant access only to the immutable runtime, artifact store objects, and
   explicitly selected broker endpoints.
3. Omit network capabilities unless policy names approved destinations. Network
   access, when allowed, goes through the service proxy; the workload never
   receives host proxy credentials.
4. Create an isolated desktop/window station when UI is denied. Do not grant
   clipboard, global hooks, accessibility, or broad device capabilities.
5. Create the process suspended with an explicit mitigation policy and scrubbed
   environment. Never launch through a shell.
6. Assign the suspended process to a kill-on-close Job Object with active
   process, memory, CPU, wall-time, and handle restrictions before resuming its
   first thread. Failure at any step terminates the process and refuses the run.
7. Exchange structured input/output over bounded named pipes. Treat malformed,
   oversized, late, or impersonated broker messages as denials.
8. Terminate and wait for the entire Job Object, seal output hashes and policy
   evidence, remove temporary ACL grants, and destroy the per-run identity.

Starting a process and assigning it to a Job Object afterward is not accepted:
deliberate code can create children in that race. The first instruction must not
run until containment is attached.

## Maximum launch sequence

Maximum uses a disposable Hyper-V-backed compute system with its own kernel.
The guest receives a read-only virtual disk containing exact content-addressed
inputs and a one-run worker. It starts with no host mounts, clipboard, device
sharing, host credentials, or network adapter. Policy-approved network and
actions are brokered over a narrowly scoped service channel. The guest disk and
VM are destroyed after outputs and evidence are sealed.

Unsigned, source-built, unknown, high-impact, or explicitly elevated-risk code
defaults to Maximum. If Hyper-V or the required service capability is absent,
the decision is `backend_unavailable`. Standard may be offered only as a new,
separately approved request; it is never substituted automatically.

## Acquisition and build

The service pipeline is indivisible:

```text
Acquire -> Resolve -> Hash -> Build in Maximum -> Inspect -> Decide ->
Approve -> Install to immutable environment -> Run -> Monitor -> Record
```

- Downloading may write only to a service-owned staging area and executes no
  package hooks.
- Every transitive dependency is pinned by source and SHA-256 before install.
- Wheels are preferred. Build backends and sdists execute only in Maximum with
  the network removed after declared inputs are fetched.
- Git hooks never execute. Submodules are explicit graph nodes, pinned to exact
  commits, and acquired as inert content.
- Archive traversal, links, duplicate/case-colliding paths, special files,
  excessive member counts, size limits, and expansion ratios are checked before
  extraction. Extraction uses create-new semantics beneath a fresh root.
- Installation produces a new immutable environment. Unsigned code is never
  copied into the host Python environment.

## Broker rules

- Protected secrets are never environment variables, command-line arguments,
  files in the sandbox, or raw API tokens returned to the workload.
- Account actions are exact typed requests. The service validates project,
  artifact, recipient, amount, service, expiry, and current device-level policy.
- `spending = deny` is enforced by the service and cannot be weakened by project
  policy. The alpha has no standing financial approvals.
- Files are opened by the broker after canonicalization and reparse-point checks;
  the sandbox does not receive broad host directory access.

## Evidence custody

The service owns an OS-protected signing key unavailable to sandbox identities
and ordinary clients. Records include caller identity, project, artifact and
graph hashes, entrypoint, capabilities, policy/sandbox/backend versions,
requested and achieved tiers, decision reasons, resource termination, outputs,
and the previous record hash. Losing or rolling back the store is detectable by
an independently protected checkpoint.

The current Python alpha's same-user HMAC store is a protocol prototype, not
this guarantee.

## Mandatory acceptance tests

Standard remains unavailable until real OS-boundary tests prove denial of:

- host file and reparse-point escape;
- undeclared network and DNS;
- environment, credential-manager, browser, SSH, and cloud-token theft;
- registry, startup, service, scheduled-task, and shell persistence;
- child, breakaway, debugger, handle-inheritance, and process-injection escape;
- clipboard, window messages, hooks, accessibility, camera, microphone, USB,
  serial, and GPU/device access outside policy;
- CPU, RAM, disk, process-count, handle-count, output-size, and wall-time abuse;
- broker spoofing, replay, confused-deputy requests, and caller impersonation.

Maximum additionally requires kernel-boundary escape testing, no-host-mount
proof, network-off proof, guest rollback/destruction proof, and recovery after
service, host, and guest crashes. Every invariant must have a mutation that
causes a known test failure. External red-team review is required before
Windows 1.0.

The experimental `CreateProcessInSandbox` API may be feature-detected later as
an accelerator. It is not the sole boundary until Microsoft declares it stable
and Preflight's complete acceptance suite passes against it.
