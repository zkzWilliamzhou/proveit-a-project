"""The claim contract.

A claim type resolves to one or more registered witnesses, or to an explicit
abstention. Nothing here generates code, imports a module named in data, or
constructs a command. Unknown and semantically empty claims abstain; they never
guess a check.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..model import WitnessSpec

UNVERIFIABLE = "UNVERIFIABLE"


@dataclass(frozen=True)
class PlanOutcome:
    specs: tuple[WitnessSpec, ...]
    reason_code: str | None = None
    note: str = ""


def _spec(name: str, params: dict, trust: bool = False, why: str = "") -> WitnessSpec:
    return WitnessSpec(name=name, params=params, trust_required=trust, rationale=why)


def _abstain(code: str, note: str) -> PlanOutcome:
    return PlanOutcome(specs=(), reason_code=code, note=note)


# Claim types that have no sound deterministic witness. Listing them explicitly
# is a feature: proveit refuses to invent a test for a semantic claim.
_NO_SOUND_WITNESS = {
    "issue_resolved": "A linked issue has no pre-registered discriminating test.",
    "performance_improved": "Speed claims need a benchmark baseline and a measured threshold.",
    "secure": "Security is not a single falsifiable predicate.",
    "production_ready": "Readiness is a human judgement, not an executable check.",
    "handles_edge_cases": "Unbounded input space; no finite witness exists.",
    "no_breaking_changes": "Use backward_compatible with an explicit API surface contract.",
    "correct": "Correctness requires a specification proveit does not have.",
}


def plan_for(kind: str, params: dict) -> PlanOutcome:
    kind = kind.lower()
    if kind in _NO_SOUND_WITNESS:
        return _abstain("NO_SOUND_WITNESS", _NO_SOUND_WITNESS[kind])

    if kind == "bug_fixed" or kind == "discriminating_test":
        if "test" not in params:
            return _abstain(
                "NO_DISCRIMINATING_TEST",
                "Provide params.test: a repository-relative test file, plus a base ref.",
            )
        return PlanOutcome(
            (_spec("tests.discriminating", {"test": params["test"]}, True,
                   "The test must fail on the base revision and pass on the patched one."),),
            note="Red/green proof against the base revision.",
        )

    table: dict[str, tuple[WitnessSpec, ...]] = {
        "tests_pass": (
            _spec("tests.pytest", _pick(params, "target"), True,
                  "Fresh, complete, unfiltered pytest run in an isolated environment."),
        ),
        "tests_added": (_spec("tests.new_test_added", {}, False,
                              "At least one test file must appear in the change."),),
        "only_changed_files": (_spec("diff.changed_subset", _pick(params, "files"), False,
                                     "Every changed path must be inside the declared allowlist."),),
        "changed_files_equal": (_spec("diff.changed_equals", _pick(params, "files"), False,
                                      "The changed path set must equal the declared set."),),
        "no_forbidden_paths": (_spec("diff.paths_denied", _pick(params, "deny"), False,
                                     "No changed path may start with a denied prefix."),),
        "no_secrets": (_spec("diff.no_secrets", {}, False,
                             "Curated detectors plus entropy screening on added lines."),),
        "no_new_dependencies": (_spec("deps.unchanged", {}, False,
                                      "Dependency manifests must hash-identically match the base."),),
        "no_deleted_files": (_spec("diff.no_deletions", {}, False,
                                   "No file may have status D in the diff."),),
        "small_diff": (_spec("diff.max_lines", _pick(params, "max"), False,
                             "Added and removed line count must stay under the cap."),),
        "backward_compatible": (
            _spec("api.public_surface", _pick(params, "files"), False,
                  "No public top-level Python symbol may disappear. This is a narrow proxy, "
                  "not a full compatibility proof."),
        ),
        "python_syntax_ok": (_spec("python.syntax_ok", _pick(params, "files"), False,
                                   "ast.parse every changed Python file in-process."),),
        "json_valid": (_spec("json.valid", _pick(params, "files"), False,
                             "Parse every named JSON file with the standard library."),),
        "file_exists": (_spec("file.exists", _pick(params, "files", "path"), False,
                              "Named paths must exist inside the repository."),),
        "file_absent": (_spec("file.absent", _pick(params, "files", "path"), False,
                              "Named paths must not exist inside the repository."),),
        "file_contains": (_spec("file.contains_literal", _pick(params, "path", "literal"), False,
                                "A bounded literal byte search, never a regex."),),
        "file_lacks": (_spec("file.no_literal", _pick(params, "path", "literal"), False,
                             "A bounded literal byte search, never a regex."),),
        "file_hash": (_spec("file.hash_equals", _pick(params, "path", "sha256"), False,
                            "SHA-256 of the file must equal the declared digest."),),
        "clean_worktree": (_spec("git.clean", {}, False,
                                 "git status --porcelain must be empty."),),
        "lint_clean": (_spec("lint.ruff", _pick(params, "target"), True,
                             "Fresh linter run; opt-in because it reads repo config."),),
    }
    if kind not in table:
        return _abstain(
            "UNRECOGNIZED_CLAIM_KIND",
            f"No registered witness for claim kind {kind!r}. See `proveit witnesses`.",
        )
    return PlanOutcome(table[kind])


def _pick(params: dict, *names: str) -> dict:
    return {name: params[name] for name in names if name in params}


def known_kinds() -> tuple[str, ...]:
    return tuple(sorted(set(_NO_SOUND_WITNESS) | {
        "bug_fixed", "discriminating_test", "tests_pass", "tests_added",
        "only_changed_files", "changed_files_equal", "no_forbidden_paths",
        "no_secrets", "no_new_dependencies", "no_deleted_files", "small_diff",
        "backward_compatible", "python_syntax_ok", "json_valid", "file_exists",
        "file_absent", "file_contains", "file_lacks", "file_hash",
        "clean_worktree", "lint_clean",
    }))
