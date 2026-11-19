# Architecture

## Domain vocabulary

From `docs/GLOSSARY.md`: a **Claim** is one falsifiable assertion. A **Witness** is a registered, deterministic check. A **Plan** maps a Claim to one or more Witnesses or records an **Abstention**. A **Receipt** is the redacted, content-addressed evidence bundle. A **Runner** is the isolated subprocess boundary.

proveit has four modules that are deliberately deep and one seam that is deliberately closed.

| Module | Interface | What it hides |
| --- | --- | --- |
| `security/paths.py` | `safe_path`, `read_file_bounded` | symlink resolution, traversal rules, O_NOFOLLOW, byte caps |
| `security/runner.py` | `run_isolated(argv, cwd, timeout, max_output)` | env scrubbing, process groups, kill-on-timeout, output caps |
| `detectors.py` | `scan_added_lines(lines) -> ScanResult` | detector catalog, entropy, caps, finding shape |
| `reporters/__init__.py` | `render(receipt, fmt) -> str` | five output formats and control-character cleaning |

The seam is `witnesses/registry.py`. Registration happens only at import time from `witnesses/builtin.py`. There is no plugin discovery, no entry-point scan and no dynamic import. A repository cannot add a Witness by dropping a file into the checkout.

## Data flow

```
transcript / manifest / --claim
        |
        v
claims/parser.py  (bounded, closed pattern table)
        |
        v
claims/normalizer.py  (cap, dedupe)
        |
        v
claims/grammar.py  (kind -> WitnessSpec | Abstention)
        |
        v
engine.evaluate  ----------------------------> plan[]
        |                                          |
        |  for each spec                            |
        v                                          |
witnesses/registry.get(name).fn(ctx, params)        |
        |                                          |
        +-- security/paths.py      (reads)          |
        +-- gitstate.py            (git facts)      |
        +-- detectors.py           (scan)           |
        +-- security/runner.py     (subprocess)     |
        |                                          |
        v                                          |
WitnessResult (PASS / FAIL / UNVERIFIABLE)          |
        |                                          |
        v                                          |
_aggregate  (any FAIL -> FAIL; any non-PASS -> UNVERIFIABLE)
        |
        v
redact_receipt(body)  ->  sha256(canonical_json(body))  ->  Receipt
        |
        v
render(receipt, fmt)  /  write_receipt  /  replay
```

`engine.evaluate` never upgrades an error to `PASS`. Witness exceptions are caught once, classified, and converted to `UNVERIFIABLE`. That single wide catch is the only one in the codebase and carries an inline exemption.

## Trust boundaries

| Data | Trusted? | Handling |
| --- | --- | --- |
| git checkout | no | canonical root, repeated resolution, NUL-delimited git paths, byte caps |
| agent transcript | no | opaque text, closed pattern table, JSONL shape allowlist |
| claim manifest | no | strict JSON, bounded depth/nodes, unknown keys rejected |
| `.proveit.json` | no | same strict loader, four allowed keys |
| witness name | yes | lookup in a static dict |
| argv | yes | built in code, validated values appended as single items |
| evidence | no | redacted before hashing and rendering |

## Execution isolation

`run_isolated` is the only place a child process starts. It passes `shell=False`, a fixed minimal environment, `stdin=DEVNULL`, `close_fds=True`, `start_new_session=True`, a temporary HOME, a wall-clock timeout, process-group SIGKILL and bounded stdout/stderr. Git, pytest and ruff invocations all go through it.

Witnesses that execute repository code require `--trust-tests`. The flag is recorded in `receipt.policy.trust_tests`. A receipt produced with the flag cannot be silently replayed without it.

## Freshness and integrity

`receipt.receipt_id` is `sha256(canonical_json(body))` where `body` excludes the id. `load_receipt` recomputes and rejects mismatches. `freshness` compares HEAD, base and diff hash. `replay --execute` re-runs the plan and reports verdict drift.

`gitstate.diff_hash()` hashes the tracked diff plus every untracked file, so an untracked secret file cannot hide from the state binding.

## Decisions

See `docs/adr/`:

- `0001-closed-witness-registry.md`: no plugin seam.
- `0002-deep-detectors-module.md`: deepening with a behavior fingerprint gate.
- `0003-strict-json-only.md`: no YAML or arbitrary config.
- `0004-abstention-is-a-result.md`: `UNVERIFIABLE` as a first class outcome.

## Build and verification

`python3 scripts/verify_all.py` is the single release gate. It fails on any lint error, high/medium Bandit finding, forbidden execution primitive, inconsistent claim/witness mapping, invalid vendored skill frontmatter, failing test, resource-limit regression or fingerprint mismatch.
