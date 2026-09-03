# Blast Chambers native workspace

This workspace is the Windows resource-boundary implementation. It is pinned to
Rust 1.96 MSVC and is built separately from the Python wheel.

Current status: **inactive / acceptance pending**.

Implemented and locally proven:

- strict protocol-v1 models and 1 MiB length framing;
- rejection of duplicate and unknown JSON fields;
- finite resource-limit validation;
- monotonic service lifecycle transitions;
- RAII Job Object ownership;
- kill-on-close, active-process, memory, total CPU, and CPU hard-cap setup with
  read-back verification;
- a real suspended-process test that assigns and verifies Job membership before
  resuming the first thread;
- hostile fixture binaries for later privileged acceptance;
- fail-closed Python client discovery and evidence schema validation.

Not implemented or claimed:

- authenticated SCM named-pipe transport and mutual identity checks;
- caller impersonation/token launch and secure content staging;
- bounded inherited handle-list stdio;
- completion-port monitoring and hostile-fixture enforcement tests;
- non-exportable CNG signing, HKLM checkpointing, and crash recovery;
- AppContainer/LPAC Standard or Hyper-V Maximum isolation.

The service binary exits with "backend_unavailable" by design. Do not install
it. Activation requires every field in "acceptance/activation.json" to be
independently proven on Windows 11 and changed through review.

Local verification:

    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace --all-targets -j 1
