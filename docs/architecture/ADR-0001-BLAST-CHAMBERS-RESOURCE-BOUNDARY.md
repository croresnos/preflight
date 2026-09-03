# ADR 0001: Blast Chambers resource boundary

Status: accepted; backend activation pending acceptance proof.

## Decisions

1. The source is a pinned Rust workspace at "native/blast-chambers/". Release
   engineering will build and sign its binaries separately from the Python
   wheel.
2. The Windows service runs as "LocalService", with a restricted per-service
   SID and only privileges required for caller impersonation and token-based
   process creation. Installation accepts binaries only from an
   administrator-protected staging directory, never Cargo's user-writable
   target directory.
3. IPC is a local named pipe using an explicit ACL,
   "PIPE_REJECT_REMOTE_CLIENTS", first-instance protection, client
   impersonation, and fail-closed identity checks. The client compares the pipe
   server PID and token with SCM state. The server validates caller SID,
   session, and token and rejects callers already inside one of its jobs.
4. Protocol v1 is a four-byte little-endian length followed by at most 1 MiB of
   UTF-8 JSON. Schemas are exact; duplicate and unknown fields, replayed UUID /
   sequence / nonce tuples, version mismatch, and downgrade are rejected.
5. Inputs are copied while impersonating the caller into a service-owned
   content-addressed store. Reparse points, special files, case collisions, and
   configured count/byte limits are rejected. Hashing occurs during create-new
   copying and publication is atomic.
6. A duplicated caller primary token, scrubbed environment, isolated working
   directory, and explicit bounded-stdio handle list create the target
   suspended. All Job limits are configured and read back; membership is
   verified before the first thread is resumed.
7. Evidence payload bytes are signed with a non-exportable CNG ECDSA P-256 key
   ACLed to the service SID, chained, and checkpointed under protected HKLM.
   Recovery kills surviving jobs and seals "service_interrupted" without
   claiming success.

## Consequences

Job Objects provide resource and process-tree controls, not an OS security
principal boundary. Resource-only therefore remains an explicit downgrade and
requires acceptance during both approval and execution. Standard and Maximum
refuse until their distinct boundaries are proven.

The current workspace contains the strict protocol, lifecycle machine, and
read-back-verified Job configuration. The service intentionally refuses to run
until authenticated IPC, caller-token launch, protected signing, recovery, and
the privileged acceptance suite are complete.
