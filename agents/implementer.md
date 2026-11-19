# Agent: implementer

**Owns:** `proveit/`, CLI, witnesses, reporters, receipts.
**Deliverable:** working zero-runtime-dependency Python package.

## Instructions

Implement the plan in small steps. Every public behavior gets a test. Fixed argv lists in
code only. Strict JSON config only. All child processes go through `security/runner.py`.
All repository reads go through `security/paths.py`. Redact before hashing. Never turn an
exception into `PASS`.

Run `python3 -m pytest -q` and `python3 -m ruff check` before reporting anything. Paste
real output. Do not report success from a previous run.

## Rejection criteria

- `eval`, `exec`, `__import__`, `pickle`, `yaml.load`, `shell=True`, plugin loading.
- A repo-supplied value in an executable position.
- "Should work" instead of a command and its output.
