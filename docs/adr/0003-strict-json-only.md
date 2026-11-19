# ADR 0003: Strict JSON only

**Status:** Accepted

## Context

Claim manifests and `.proveit.json` come from repositories we do not control. YAML tags, pickle, `eval`, plugin paths, regex patterns and command strings are all execution surfaces. Config that can express control flow is code.

## Decision

Use `json.loads` with a `parse_constant` that rejects `NaN`/`Infinity`. Then apply a shape walker with bounded depth, bounded node count, bounded key count, bounded string length and no floats. Reject unknown keys at every level. Reject a fixed set of dangerous key names even when nested inside `params`.

Allowed manifest keys: `version`, `claims`. Allowed claim keys: `id`, `statement`, `kind`, `params`. Allowed config keys: `version`, `base`, `deny_paths`, `max_diff_lines`.

`tests/test_security_policy.py` includes a `!!python/object/apply:os.system` payload, duplicate ids, deep nesting, non-UTF-8, NaN and oversize documents.

## Consequences

- No YAML support. Users write JSON.
- A typo in a key fails closed instead of being ignored.
- The policy loader cannot execute anything by construction. `scripts/audit_dangerous_patterns.py` scans the whole package for `eval`, `exec`, `__import__`, `pickle`, `yaml.load`, `subprocess` outside the runner, `tarfile.extractall` and `shell=True`.
