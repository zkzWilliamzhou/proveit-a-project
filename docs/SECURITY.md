# Security notes

## Threat model

proveit is a CI privilege boundary. It reads repositories, agent transcripts and claim manifests controlled by someone else, then starts child processes and writes artifacts that may be published to pull requests. Assume all three inputs are hostile.

Primary weaknesses addressed: CWE-78 (command injection), CWE-88 (argument injection), CWE-22 (path traversal), CWE-59 (symlink following), CWE-362 (TOCTOU), CWE-502 (unsafe deserialization), CWE-94 (code injection), CWE-426 (untrusted search path), CWE-770 (resource exhaustion), CWE-1333 (ReDoS), CWE-200 (information exposure).

## Controls

| Control | Implementation | Test |
| --- | --- | --- |
| No arbitrary commands | static witness catalog; config cannot name an executable | `test_forbidden_keys_rejected`, AST audit |
| No argument injection | values validated against a closed character set, appended as single argv items, leading `-` refused | `test_values_rejected`, `test_option_like_param_is_blocked` |
| No shell | `shell=False` everywhere; `shell=True` is an AST-audit finding | `audit_dangerous_patterns.py` |
| No inherited secrets | fixed minimal env, temporary HOME, `close_fds=True`, `start_new_session=True` | `test_runner_does_not_inherit_secrets` |
| No runaway processes | wall-clock timeout, process-group SIGKILL, stdout/stderr caps | `test_runner_timeout_kills_process_group`, `test_runner_caps_output` |
| No path escape | canonical root, raw segment validation, symlink checks, `O_NOFOLLOW` on the literal final component | `test_symlink_escape_is_rejected`, `test_o_nofollow_rejects_final_symlink` |
| No unsafe deserialization | strict JSON only, bounded depth/nodes/keys/strings, no floats, unknown keys rejected | `test_security_policy.py` |
| No code loading | no `eval`, `exec`, `compile`, `__import__`, `pickle`, `yaml.load` or plugin imports | AST audit |
| No archive escape | explicit tar member iteration, type checks, size caps, `O_EXCL` writes | `test_base_archive_rejects_symlink_member`, `test_base_archive_rejects_traversal_member` |
| No secret leakage | structured redaction before hashing and rendering; findings carry only kind, origin and line number | `test_secret_raw_content_never_enters_receipt`, `test_redaction_is_applied_and_recorded` |
| No output injection | one control-character cleaning boundary for all five formats | `test_hardening.py` |
| No fabricated evidence | refused reads abstain; exceptions become `UNVERIFIABLE` | `test_refused_path_is_not_reported_as_failure`, `test_fail_closed_on_unexpected_exception` |

## Opt-in execution

`tests.pytest`, `tests.discriminating` and `lint.ruff` execute repository code. They require `--trust-tests`, are recorded in `receipt.policy.trust_tests`, and cannot run implicitly through `explain`, `witnesses`, `doctor` or receipt loading. `tests.discriminating` materializes the base revision into a temporary directory with explicit member writes. It does not run the agent's own commands.

## Residual limits

- `diff.no_secrets` is a rule-based scanner. Non-detection is not proof of absence. It scans introduced lines and untracked files, not the entire history or environment variables held by the agent process.
- `api.public_surface` compares public top-level Python names. It does not check signatures, types, runtime behaviour or non-Python APIs.
- `tests.discriminating` trusts that the named test exists in the patched tree and is relevant. A test written by the same agent can encode the same misunderstanding as the patch. Independent tests remain necessary for high-stakes changes.
- Receipts are content-addressed, not cryptographically signed by a trusted runner. `receipt_id` detects tampering; it does not establish who ran the check.
- `UNVERIFIABLE` is common. It is a correct result, not a gap to hide.

## Bandit low-severity notes

Four remain after the fixes. Each is recorded rather than suppressed.

| ID | Location | Why it is acceptable |
| --- | --- | --- |
| B105 | `proveit/model.py:14` | The string constant is `PASS`, a verdict label, not a password. |
| B406 | `proveit/reporters/__init__.py` | We import `xml.sax.saxutils.escape` to **emit** XML. We never parse untrusted XML. `ElementTree.fromstring` appears only in tests. |
| B404 | `proveit/security/runner.py` | The subprocess import is intentional. This module is the only execution boundary. |
| B603 | `proveit/security/runner.py` | The single `Popen` call uses a fixed argv list, `shell=False`, empty environment, no inherited fds, a timeout and output caps. All repo-supplied values are validated before they become separate argv items. |

## Reporting

Open an issue with a reproducing claim manifest and the receipt. Do not paste credentials into an issue.
