# proveit

Claim receipts for AI coding agents. No model judges a model.

An agent says "all tests pass", "I only touched `src/app.py`", "no secrets introduced". A reviewer reads the prose and hopes. proveit turns each assertion into a deterministic check, runs it after the change, and writes a signed-by-content receipt with `PASS`, `FAIL` or `UNVERIFIABLE` for every claim.

```
$ proveit check --manifest claims.json --base HEAD~1 --trust-tests

proveit - claim receipts
receipt  4f2a91c8b0d7e613
repo     my-app @ 9ac41b2e0b11 (base HEAD~1)

[PASS] C1: No secrets were introduced
         OK
[FAIL] C2: I only touched src/app.py
         UNEXPECTED_CHANGED_PATHS
         - diff.changed_subset: 2 changed path(s) outside the declared allowlist.
[UNVERIFIABLE] C3: The change is backward compatible
         NO_TARGET_FILES
[UNVERIFIABLE] C4: All tests pass
         NO_TESTS_RAN
         - tests.pytest: The run did not produce usable evidence.

overall  FAIL
claims   1 pass / 1 fail / 2 unverifiable
```

## Why this exists

CI runs tests. Linters run rules. Secret scanners scan files. None of them knows what the agent claimed. A green build can sit next to a false sentence in a pull request description.

proveit adds the missing layer: a compiler from an assertion to a fresh, independently executed witness, plus an evidence bundle that binds the result to a repository state. It abstains when no sound witness exists. `UNVERIFIABLE` is a first class result, not an error and not a quiet pass.

Three rules shape the whole tool:

1. **No LLM judges a claim.** Claim extraction uses a closed pattern table. Verdicts come from exit codes, git state, hashes and literal byte comparisons.
2. **Untrusted data is never code.** Claim manifests are strict JSON. No YAML, no plugins, no repo-supplied commands, no regex from input, no `eval`, no dynamic imports.
3. **Failure closes.** An exception, a timeout, a missing tool or a refused path becomes `UNVERIFIABLE` with a reason code. It never becomes `PASS`.

## Install

```bash
pip install proveit        # from a checkout: pip install -e .
```

Requires Python 3.9+ and git. Zero runtime dependencies. `pytest` is optional and only needed for the two witnesses that execute repository tests.

## Quick start

```bash
proveit init                        # writes proveit.claims.json
proveit check --manifest proveit.claims.json --base HEAD
proveit explain --claim "All tests pass"    # dry run, executes nothing
proveit witnesses                    # list the closed registry
proveit doctor                      # report the local runner
```

`--base HEAD` checks the current working tree, including untracked files. Use
`--base HEAD~1` for committed changes, or a branch name such as `origin/main`
in CI.

Claims also come from plain text or an agent transcript:

```bash
proveit check --claim "No secrets were introduced" --claim "No new dependencies"
proveit check --transcript agent.jsonl --transcript-format jsonl --trust-tests
```

Transcript adapters read Claude Code style JSONL and plain text. They extract assistant text only. Prompt injection inside a transcript produces an abstention, never a command.

## Claim manifest

```json
{
  "version": 1,
  "claims": [
    {
      "id": "C1",
      "statement": "I only touched src/app.py",
      "kind": "only_changed_files",
      "params": { "files": ["src/app.py"] }
    },
    {
      "id": "C2",
      "statement": "No secrets were introduced",
      "kind": "no_secrets"
    },
    {
      "id": "C3",
      "statement": "I fixed the bug",
      "kind": "bug_fixed",
      "params": { "test": "tests/test_regression.py" }
    }
  ]
}
```

Unknown kinds, missing parameters and semantic claims do not get a guessed test. Run `proveit explain` to see the plan before anything executes.

### What can be verified

| Kind | Witness | Needs opt-in |
| --- | --- | --- |
| `only_changed_files`, `changed_files_equal`, `no_forbidden_paths`, `no_deleted_files`, `small_diff` | git diff against a base ref | no |
| `no_secrets` | curated detectors and entropy screening on introduced lines | no |
| `no_new_dependencies` | hash comparison of known lockfiles | no |
| `file_exists`, `file_absent`, `file_contains`, `file_lacks`, `file_hash` | bounded in-process reads | no |
| `python_syntax_ok`, `json_valid` | `ast.parse`, `json.loads` | no |
| `backward_compatible` | public top-level Python symbol comparison (narrow proxy) | no |
| `tests_added`, `clean_worktree` | path and git status checks | no |
| `tests_pass` | fresh pytest run | `--trust-tests` |
| `bug_fixed`, `discriminating_test` | red on base revision, green on patched revision | `--trust-tests` |
| `lint_clean` | fresh ruff run | `--trust-tests` |

### What abstains on purpose

`issue_resolved`, `production_ready`, `secure`, `performance_improved`, `handles_edge_cases`, `correct`, `no_breaking_changes` all return `UNVERIFIABLE` with `NO_SOUND_WITNESS`. A tool that invents a test for "production ready" is a tool that lies. `bug_fixed` without `params.test` abstains with `NO_DISCRIMINATING_TEST`.

## The discriminating test

`bug_fixed` is the sharpest witness. It materializes the base revision into a temporary directory, overlays the new test file, and runs the same test twice:

- base tree + new test must **fail** (the test detects the bug)
- patched tree + new test must **pass** (the fix works)

A test that passes on both revisions returns `FAIL` with `TEST_NOT_DISCRIMINATING`. The agent cannot satisfy the claim by adding a tautology.

## Outputs

`--format` accepts `terminal`, `json`, `markdown`, `sarif`, `junit`. `--receipt` writes a canonical, content-addressed receipt. Receipts are redacted before hashing, written atomically, and verified on load:

```bash
proveit check --manifest claims.json --receipt .proveit/receipt.json --format sarif --out report.sarif
proveit replay .proveit/receipt.json --execute
```

`replay` reports `CURRENT` or `STALE` by comparing HEAD, base and diff hash. With `--execute` it re-runs the plan and lists any verdict drift.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | every claim verified |
| 1 | at least one claim falsified, or `--strict` with an unverifiable claim |
| 2 | at least one claim unverifiable |
| 3 | operator or policy error |

## CI

```yaml
- name: Verify agent claims
  run: |
    proveit check --manifest claims.json --base origin/main \
      --trust-tests --format junit --out proveit.xml \
      --receipt proveit-receipt.json
```

See `.github/workflows/proveit.yml` for a complete example that uploads SARIF and JUnit.

## Security model

proveit reads attacker-controlled repositories, transcripts and manifests. It treats all of them as hostile.

- Fixed argv lists built in application code. `shell=False`, empty environment, no inherited tokens, own process group, wall-clock timeout, output caps.
- Repository paths resolved against a canonical root on every use. `..`, absolute paths, option-looking values and escaping symlinks are refused. Final-component symlinks are rejected before open.
- Strict JSON with unknown-key rejection. No YAML, pickle, plugins, dynamic imports, regex from input, or repo-supplied commands.
- Evidence is redacted on the structured receipt before serialization or display. Raw suspicious lines never enter the bundle.
- Downloads, network calls and arbitrary command execution are not part of the tool.

Four low-severity Bandit notes remain and are documented in `docs/SECURITY.md`. They concern the string constant `PASS`, `xml.sax.saxutils.escape` (used to emit XML, not parse it), the subprocess import and the single hardened `Popen` call.

Read `docs/SECURITY.md` before pointing this at an untrusted repository.

## What proveit does not do

It does not review code, understand an issue, prove correctness, benchmark performance, certify security or replace a human reviewer. It does not guarantee a GitHub star count. It answers one narrow question: which of the agent's assertions have fresh, reproducible, machine-checkable evidence, and which do not.

## Verify the build

```bash
pip install -e '.[test]'
python3 -m pytest -q
python3 scripts/verify_all.py
```

`verify_all.py` is the release gate. It runs the full test suite, ruff, bandit, the AST audit for forbidden execution primitives, the claim/witness consistency check, resource-exhaustion probes and a determinism check on the behavior fingerprint. The fingerprint proves that architecture deepening did not change a single observable function. See `docs/fingerprint_equivalence.json`.

## Layout

```
proveit/
  claims/      text extraction, claim grammar, normalization
  witnesses/   closed registry and 20 deterministic witnesses
  detectors.py deep secret-detection module
  security/    paths, strict policy, redaction, isolated runner
  adapters/    transcript readers
  reporters/   terminal, JSON, Markdown, SARIF, JUnit
  engine.py    plan compilation and fail-closed aggregation
  receipt.py   content addressing, integrity, freshness, replay
  cli.py       six commands and exit code contract
docs/          architecture, ADRs, review log, security, research
agents/        the specialist agent roster used to build this
skills/        vendored GitHub skills with attribution in docs/VENDOR_SKILLS.md
```

## License

MIT. Vendored skills keep their own licenses.
