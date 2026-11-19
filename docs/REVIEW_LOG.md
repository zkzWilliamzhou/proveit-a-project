# Eight-round examination log

Each round ran real tooling against the code at that point. "Finding" means a defect that was reproduced and fixed. "Lock" names the test or script that now fails if the defect returns. Findings from earlier rounds were not silently carried forward: every round re-ran the full suite.

## Round 1. Claim planning and output validity

**Scope:** `claims/grammar.py`, `claims/parser.py`, `reporters`.

**Method:** `proveit explain`, SARIF schema inspection, `scripts/consistency_check.py`.

**Findings**

1. SARIF emitted `ruleId: claim.unrecognized` for abstaining claims, but that rule was absent from `tool.driver.rules`. Invalid SARIF.
2. "All tests pass and no secrets were introduced" became one claim (`tests_pass`). Half of the sentence was never verified.
3. Claim kinds existed that no witness could reach, with no automated check for orphan witnesses.

**Fixes:** declare a `claim.abstention` fallback rule; split compound lines only when at least two segments match the closed pattern table; add `consistency_check.py` for orphan and unregistered witnesses.

**Locks:** `test_sarif_rule_ids_are_declared`, `test_compound_line_yields_multiple_claims`, `scripts/consistency_check.py`.

## Round 2. Receipt integrity and determinism

**Scope:** `model.py`, `receipt.py`, fingerprint tooling.

**Findings**

1. `ClaimVerdict.to_dict()` used `asdict()`, which keeps tuples. `json.loads(render(receipt, "json"))` therefore did not equal the receipt object. Replay input shape drifted.
2. A tamper test modified `summary.overall` from `PASS` to `PASS`, so it asserted nothing.
3. `duration_ms` leaked into rendered JSON strings. The behavior fingerprint and the receipt stability test changed with wall-clock scheduling.

**Fixes:** return JSON-native lists from `to_dict()`; make the tamper test actually change a value; normalize `"duration_ms":N` inside rendered strings and exclude timing fields in the stability test.

**Locks:** `test_json_format_is_canonical`, `test_tampered_receipt_rejected`, `test_receipt_content_is_stable_for_identical_state`, three consecutive identical fingerprint runs.

## Round 3. Path containment and evidence fabrication

**Scope:** `security/paths.py`, `witnesses/builtin.py` file witnesses.

**Findings**

1. `require_relative("a/./b")` passed because `pathlib.Path.parts` normalizes `.` segments away before the check.
2. `O_NOFOLLOW` never fired for a final-component symlink. `safe_path` resolved the symlink first, so `os.open` saw a regular path.
3. `file.exists` turned a policy-refused read into `FILE_MISSING` (`FAIL`). An attacker-controlled symlink could therefore manufacture falsifying evidence against a claim.

**Fixes:** validate raw `/`-split segments; check the literal final component for a symlink before resolution; add `_path_state` returning `present | absent | blocked` and return `UNVERIFIABLE / POLICY_BLOCKED` for blocked paths in both `file.exists` and `file.absent`.

**Locks:** `test_relative_paths_rejected`, `test_o_nofollow_rejects_final_symlink`, `test_symlink_escape_never_becomes_evidence_of_absence`, `test_refused_path_is_not_reported_as_failure`, `test_nested_symlink_loop_is_rejected`.

## Round 4. Arbitrary code execution surfaces

**Scope:** every Python file, plus `witnesses/builtin.py` archive handling.

**Method:** `scripts/audit_dangerous_patterns.py` (AST), `bandit`, crafted YAML and manifest payloads.

**Findings**

1. `security/policy.py` used `__import__("re")` inside the strict policy loader. A dynamic import in the module that parses untrusted config is an unacceptable primitive.
2. `tarfile.extractall(members=...)` triggered Bandit B202 (medium). Even with member checks, `extractall` is the wrong primitive inside a trust boundary.
3. A `!!python/object/apply:os.system` payload and a manifest `command` key had to be proven inert, not assumed inert.

**Fixes:** plain `import re`; replace `extractall` with explicit member iteration, type checks, member byte caps, path re-resolution after `mkdir`, `O_EXCL | O_CLOEXEC` writes; add exploit tests.

**Locks:** `scripts/audit_dangerous_patterns.py` (0 findings), `test_forbidden_keys_rejected`, `test_yaml_payload_is_not_accepted`, `test_base_archive_rejects_symlink_member`, `test_base_archive_rejects_traversal_member`, Bandit 0 high / 0 medium.

## Round 5. Output injection into CI artifacts

**Scope:** `reporters/__init__.py` and all five formats.

**Findings**

1. Untrusted claim text flowed to terminal, Markdown, SARIF and JUnit without control-character filtering. ANSI escapes and NUL could reach a terminal or an XML document.
2. A newline inside a claim statement could add a Markdown table row or a terminal line.
3. SARIF carried a `helpUri` pointing at a repository that does not exist.

**Fixes:** one `_clean()` boundary that strips control characters and folds LF/CR/TAB to spaces; cap every interpolated field; remove the invented URI.

**Locks:** `test_ansi_and_control_characters_never_reach_reports`, `test_junit_stays_well_formed_with_hostile_text`, `test_markdown_cannot_break_out_of_table`, `test_sarif_rules_cover_every_result`.

## Round 6. Resource exhaustion

**Scope:** transcript parsing, manifests, redaction, subprocesses, archives.

**Method:** `scripts/dos_probe.py`, timeout tests, output-cap tests.

**Findings**

1. The first DoS probe crashed on `LimitExceeded` instead of recording a correct rejection. The probe was wrong, so it gave no signal.
2. Classic ReDoS input `(a+)+$` shaped text, 50k claim lines, a 1 MB redaction payload and a 10-second sleeping child all needed measured bounds.
3. Base archives had a member count cap but no per-member size cap.

**Fixes:** record expected rejections as passes; measure all four cases against a 5-second ceiling; cap each archive member at `MAX_FILE_BYTES`; verify the process-group kill and the 512-byte output cap.

**Locks:** `scripts/dos_probe.py`, `test_runner_timeout_kills_process_group`, `test_runner_caps_output`, `test_line_count_is_bounded`, `test_finding_count_is_bounded`, `test_size_cap`, `test_deep_nesting_cap`.

## Round 7. Secrets and verdict honesty

**Scope:** `diff.no_secrets`, redaction, test execution, semantic abstentions.

**Findings**

1. A redaction test expected a credential from a source file to appear in the receipt. It did not, because receipts must never contain repository file contents. The test was wrong; the behavior was correct.
2. `tests.pytest` needed to distinguish "0 failures" from "no tests ran" and from a truncated or filtered run.
3. Semantic claims needed an explicit, documented refusal rather than a guessed test.

**Fixes:** put the credential in a claim statement (the path that actually reaches the receipt); add `NO_TESTS_RAN`, `PROCESS_TIMEOUT`, `OUTPUT_TRUNCATED` and `TOOL_UNAVAILABLE`; document the scanner limitation inside the witness evidence; list semantic kinds that abstain.

**Locks:** `test_redaction_is_applied_and_recorded`, `test_secret_raw_content_never_enters_receipt`, `test_semantic_claims_abstain`, `test_bug_fixed_without_test_abstains`, `test_pytest_fresh_run`, `test_discriminating_rejects_non_discriminating_test`, `test_fail_closed_on_unexpected_exception`.

## Round 8. Architecture, toolchain and release

**Scope:** `detectors.py` deepening, lint configuration, fingerprint gate, packaging and full release.

**Findings**

1. The fingerprint was non-deterministic (see Round 2). It could not serve as an architecture gate until fixed.
2. `EXE002` appeared on every file because this build sandbox mount forces mode `0777` regardless of `chmod`. Suppressing it without a reason would hide a real signal in a normal checkout.
3. A SARIF fix (Round 5) changed the fingerprint after the first equivalence measurement. The recorded hash was stale.
4. Bandit reported four low-severity notes. Three are structural false positives; one is the single hardened `Popen` call.
5. `pip install -e .` failed on the distro pip build: it installed setuptools 84 into the isolated environment but then reported the backend had no `build_editable` hook. `python3 -m proveit` worked, the console script did not exist. A project that cannot be installed is not done.
6. `docs/VENDOR_SKILLS.md` claimed a vendored `tomerose/stop-slop` reference copy that was not present, and claimed an anthropics subtree that had not been vendored. Attribution drifted from evidence.
7. No check verified that every vendored `SKILL.md` had the two required frontmatter fields and a name matching its folder.
8. The final gate caught an unused `sys` import in `scripts/validate_vendored_skills.py` and a missing `setup.py` in the lint scope. A gate that cannot fail is not a gate.
9. One CLI smoke step took 25 seconds. Direct timing showed `git status --porcelain` alone takes 2.5 seconds on this sandbox mount; the cost is environmental, not a proveit regression. No code change was made on a measurement that does not support one.

**Fixes:** normalize durations in rendered strings; document the `EXE002` ignore with the mount reason instead of a blanket suppression; re-run the before/after equivalence against the final code; document every low finding in `docs/SECURITY.md`; raise the build requirement to `setuptools>=64` and add a minimal `setup.py` shim with duplicated metadata for the documented legacy editable fallback; rewrite `VENDOR_SKILLS.md` against what was actually retrieved, add an attributed `anthropics-skill-spec` derived reference, add `scripts/validate_vendored_skills.py` to the release gate, remove the unused import, and put `setup.py` inside the lint scope.

**Locks:** `docs/fingerprint_equivalence.json` (identical before/after across 6 scenarios and 5 formats), `tests/test_detectors_equivalence.py`, `scripts/verify_all.py`, `python3 -m ruff check` (clean), `python3 -m pip install -e . --no-deps`, `python3 -m pip wheel . --no-deps`, `proveit --version`, `proveit witnesses --format json`, `scripts/validate_vendored_skills.py`, direct `git status` timing.

## Final state

`scripts/verify_all.py` runs all of the above. No known high or medium severity finding remains. Four low Bandit notes are documented with reasons. The tool has 28 claim kinds, 20 registered witnesses, 5 report formats, 6 CLI commands and a test suite covering policy, paths, redaction, injection, reporters, receipts, engine semantics and witness behavior. Editable install, wheel build and the console script were verified. 16 vendored skill folders pass frontmatter validation.
