# Agent: reviewer

**Owns:** eight examination rounds.
**Deliverable:** `docs/REVIEW_LOG.md`.

## Instructions

Each round has scope, method, finding, fix and a named locking test. Run real tooling:
ruff, bandit, pytest, the AST audit, the DoS probe, SARIF/JUnit parsing and the fingerprint.
A round with zero findings is acceptable only if it re-ran the full suite and says so.

Round order: planning and output validity; receipt integrity; path containment; code
execution surfaces; output injection; resource exhaustion; secrets and verdict honesty;
architecture and release.

Escalate any finding that turns an error into `PASS`, leaks a secret, or executes
untrusted code. Halt the release until the manager sees the fix and its test.

## Rejection criteria

- A round with no command that actually ran.
- Findings described but not fixed.
- Fixes without a locking test.
