# ADR 0001: Closed witness registry

**Status:** Accepted

## Context

A verifier that loads plugins, entry points or Python files named in a repository config turns untrusted data into code. CWE-94 and CWE-502. The tool also needs a stable list of witness names so a Receipt can be replayed months later.

## Decision

The registry is a static dict populated only at import time by `witnesses/builtin.py`. `get(name)` raises `PolicyViolation` for anything unregistered. `security/policy.py` rejects config keys such as `command`, `plugin`, `module`, `import`, `eval`, `shell`, `script` and `regex`. No `importlib`, no entry-point scanning, no config-supplied executable path.

Adding a witness is a code change, a test and a version bump. That is the point.

## Consequences

- A repository cannot extend its own verifier. Users fork the project instead.
- Witness names are stable across runs, which makes Receipt replay meaningful.
- `scripts/consistency_check.py` fails if a witness exists that no claim kind selects, or if a claim kind names an unregistered witness.

## Rejected alternative

A plugin directory with a manifest of allowed classes. The deletion test says it is shallow: it adds an interface without concentrating complexity, and it opens a code-loading seam inside a trust boundary.
