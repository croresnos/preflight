# Changelog

All notable changes follow Keep a Changelog. Preflight uses semantic versioning
while its public API remains pre-1.0.

## [Unreleased]

## [0.8.0a1] - 2026-09-01

### Added

- Experimental project opt-in, content-addressed lockfiles, exact approvals,
  tamper-evident local evidence, stable reason codes, and backend capability
  diagnostics.
- Deterministic archive inspection for wheels, sdists, and local project trees,
  including traversal, symlink, duplicate-member, and decompression-bomb
  refusals.
- A backend-neutral isolation contract for the future Windows Blast Chambers
  service.

### Changed

- Added an explicitly weaker `resource-only` protocol runner for exercising the
  approval lifecycle. It enforces only a wall-clock timeout and is never
  reported as Standard or Maximum isolation.

## [0.7.0] - 2026-09-01

### Added

- Distribution-content auditing and trusted-publishing workflows.
- Directory-wide package, plugin, and tool collision detection.
- Static entrypoint syntax diagnostics and broader Python binding analysis.
- Bare-module adaptation, settings profiles, stronger check/gate parity,
  transcript verification, and a wheel-installed end-to-end demonstration.

### Security

- Manifest limits are enforced before every parse, including load ordering and
  terminal inspection.
- Sandbox tutorials require an inventoried ownership marker before reset.
- Symlinked entrypoint files cannot escape the trusted plugin root.

[Unreleased]: https://github.com/croresnos/preflight/compare/v0.8.0a1...HEAD
[0.8.0a1]: https://github.com/croresnos/preflight/compare/v0.7.0...v0.8.0a1
[0.7.0]: https://github.com/croresnos/preflight/releases/tag/v0.7.0
