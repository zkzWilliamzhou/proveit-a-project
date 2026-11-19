# ADR 0002: Deep detectors module, gated by a behavior fingerprint

**Status:** Accepted

## Context

Before deepening, `witnesses/builtin.py` owned the secret detector catalog, Shannon entropy, per-line caps, finding shape and the `diff.no_secrets` verdict in one function. The interface into that complexity was a witness call requiring a full git Context. Nothing else could use the detector, and tests could only reach it through a repository fixture.

The deletion test: removing the inline block would scatter patterns, entropy math and caps into every caller that needs them. Concentrating them behind one small interface increases **depth** and **locality**.

## Decision

Create `proveit/detectors.py`:

```python
scan_added_lines([(origin, line_number, text), ...]) -> ScanResult(findings, lines_scanned)
```

The witness becomes a thin adapter. `ScanResult.as_evidence()` preserves the exact dict shape and key order used before. Caps, patterns, entropy threshold and finding shape move into the deep module. `detector_names()` exposes only the catalog, for audits.

One adapter = a hypothetical seam. Two adapters = a real one. This decision does not yet create a general detection seam; it creates one deep module.

## Hard gate: no function changed

The user required that architecture work change no function. We enforced this two ways.

1. `scripts/behavior_fingerprint.py` builds six fixed git fixtures, evaluates a fixed claim battery, renders all five report formats, masks volatile fields (hashes, timestamps, temp paths, durations, platform) and hashes the 36 observations.
2. We reconstructed the pre-deepening implementation, ran the same script, restored the new module, ran it again.

Result in `docs/fingerprint_equivalence.json`: the two hashes are identical across 6 scenarios and 5 formats. `scripts/verify_all.py` compares every subsequent fingerprint with the recorded value and fails on drift.

`tests/test_detectors_equivalence.py` keeps the legacy algorithm as a permanent oracle and compares it against the deep module on four corpora. `scripts/verify_all.py` reruns the fingerprint on every release gate.

## Rejected candidates

- **Split `builtin.py` by claim family.** Purely moves code between files. The deletion test says it concentrates nothing. Rejected.
- **Reporter plugin registry.** Would add a dynamic-loading seam inside code that writes public CI artifacts. Security regression. Rejected under ADR 0001.
