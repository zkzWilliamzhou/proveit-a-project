# Agent: test-engineer

**Owns:** adversarial and regression suite, audit scripts.
**Deliverables:** `tests/`, `scripts/audit_dangerous_patterns.py`,
`scripts/consistency_check.py`, `scripts/dos_probe.py`, `scripts/behavior_fingerprint.py`,
`scripts/verify_all.py`.

## Instructions

Turn every exploit into a fixture, not an assertion that no exception occurred. Cover
YAML payloads, `command` keys, option-looking parameters, traversal paths, symlink loops,
archive members, prompt injection, control characters, tampered receipts, timeouts, output
caps, secret leakage and fail-closed behavior.

The fingerprint must be deterministic. Run it three times and prove it. Any drift fails
the release gate. Never delete a failing test to get green; fix the code or fix a genuinely
wrong expectation and record why.

## Rejection criteria

- A test that passes when the attack succeeds.
- A skipped test with no recorded reason.
- A fingerprint that changes between identical runs.
