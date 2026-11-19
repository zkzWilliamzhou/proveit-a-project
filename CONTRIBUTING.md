# Contributing

## Before you start

```bash
python3 -m pip install -e '.[test]' ruff bandit
python3 scripts/verify_all.py
```

The gate must be green before you change anything. It is green on a fresh checkout.

## Adding a claim kind

1. Add the kind to `claims/grammar.py` and, if it needs text detection, to the closed table in `claims/parser.py`.
2. Register a witness in `witnesses/builtin.py` if no existing one fits.
3. Add tests for `PASS`, `FAIL` and `UNVERIFIABLE` paths.
4. Run `scripts/consistency_check.py`. Orphan witnesses and unmapped kinds fail the build.
5. Update the README table and `examples/claims.json`.

Never add a witness that accepts a command, a regex, a plugin path or an import name from data. ADR 0001 is not negotiable.

## Changing a function

Architecture work and behavior changes are separate commits. If you intend to refactor only, run `scripts/behavior_fingerprint.py` before and after. The hash must not move. If it moves, either the refactor changed behavior or the fingerprint needs a new volatile field documented in the script.

## Adding a report format

Add the format to `FORMATS` and to `render()` in `reporters/__init__.py`. Clean every untrusted string through `_clean()`. Add a parse test. Do not add a plugin registry.

## Review standard

No success claim without fresh command output. No lint suppression without a reason in a comment. No failing test deleted to get green. `UNVERIFIABLE` is a valid outcome; do not convert it into a pass to make a report look better.

Read `docs/SECURITY.md` before touching `security/`.
