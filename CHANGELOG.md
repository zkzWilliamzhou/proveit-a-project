# Changelog

## 1.0.0

First release.

- 28 claim kinds, 20 registered deterministic witnesses, 5 report formats.
- Claim manifests use strict JSON with bounded depth, nodes, keys and strings.
- Triage verdicts: `PASS`, `FAIL`, `UNVERIFIABLE`, each with a stable reason code.
- Semantic claims abstain instead of getting an invented test.
- Discriminating test witness: red on the base revision, green on the patched tree.
- Content-addressed receipts with redaction, atomic writes, integrity checks, freshness and replay with drift detection.
- Isolated subprocess runner: no shell, minimal environment, process-group kill, timeouts and output caps.
- Path policy: repeated resolution, traversal rejection, escaping symlink rejection, `O_NOFOLLOW` on the literal final component.
- Eight review rounds recorded in `docs/REVIEW_LOG.md`.
- Architecture deepening (ADR 0002) guarded by a deterministic behavior fingerprint.
- `scripts/verify_all.py` as the single release gate.
