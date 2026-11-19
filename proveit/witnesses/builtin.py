"""Built-in deterministic witnesses.

Every witness returns PASS / FAIL / UNVERIFIABLE with a reason code. FAIL is
reserved for evidence that contradicts the claim. Anything the tool cannot
establish becomes UNVERIFIABLE; an exception never becomes PASS.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

from ..context import Context
from ..detectors import scan_added_lines
from ..errors import InputError, LimitExceeded, PolicyViolation, WitnessUnavailable
from ..gitstate import DEP_FILES
from ..limits import MAX_FILE_BYTES, MAX_LIST_ITEMS, MAX_TAR_MEMBERS
from ..model import FAIL, PASS, UNVERIFIABLE
from ..security.paths import decode, read_file_bounded, require_relative, safe_path, validate_value
from ..security.runner import run_isolated
from ..witnesses.registry import register, result

_PYTEST = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
_RUFF = shutil.which("ruff")


def _start() -> float:
    return time.monotonic()


def _res(name, status, code, detail, evidence=None, t0=None):
    return result(name, status, code, detail, evidence, t0)


def _list_param(params: dict[str, Any], key: str) -> list[str] | None:
    value = params.get(key)
    if value is None:
        return None
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise InputError(f"{key} must be a string or a list of strings")
    if len(value) > MAX_LIST_ITEMS:
        raise LimitExceeded(f"{key} has too many entries")
    return [require_relative(v) for v in value]


def _one(params: dict[str, Any], key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str):
        raise InputError(f"missing required parameter: {key}")
    return value


def _trust(ctx: Context, name: str):
    if not ctx.trust_tests:
        return _res(name, UNVERIFIABLE, "TRUST_REQUIRED",
                    "This witness executes repository code. Re-run with --trust-tests to opt in.")
    return None


def _changed_python(ctx: Context, params: dict[str, Any]) -> list[str]:
    wanted = _list_param(params, "files")
    if wanted is not None:
        return [p for p in wanted if p.endswith(".py")]
    return [
        p for p in ctx.git.changed_files()
        if p.endswith(".py") and (ctx.root / p).is_file()
    ]


# --------------------------------------------------------------------------
# diff witnesses
# --------------------------------------------------------------------------

@register("diff.changed_subset", "Every changed path is inside a declared allowlist.",
          required=("files",), caveat="Compares against the base ref plus untracked files.")
def _diff_changed_subset(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    allowed = _list_param(p, "files")
    if allowed is None:
        return _res("diff.changed_subset", UNVERIFIABLE, "MISSING_PARAM",
                    "Declare params.files: the set of paths the agent was allowed to touch.", t0=t0)
    changed = ctx.git.changed_files()
    extra = sorted(set(changed) - set(allowed))
    if extra:
        return _res("diff.changed_subset", FAIL, "UNEXPECTED_CHANGED_PATHS",
                    f"{len(extra)} changed path(s) outside the declared allowlist.",
                    {"unexpected": extra, "changed": changed, "allowed": allowed}, t0)
    return _res("diff.changed_subset", PASS, "OK",
                f"All {len(changed)} changed path(s) are inside the allowlist.",
                {"changed": changed}, t0)


@register("diff.changed_equals", "The changed path set equals a declared set.",
          required=("files",))
def _diff_changed_equals(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    wanted = _list_param(p, "files")
    if wanted is None:
        return _res("diff.changed_equals", UNVERIFIABLE, "MISSING_PARAM",
                    "Declare params.files.", t0=t0)
    changed = ctx.git.changed_files()
    missing = sorted(set(wanted) - set(changed))
    extra = sorted(set(changed) - set(wanted))
    if missing or extra:
        return _res("diff.changed_equals", FAIL, "CHANGED_SET_MISMATCH",
                    "The changed path set differs from the declared set.",
                    {"missing": missing, "unexpected": extra}, t0)
    return _res("diff.changed_equals", PASS, "OK", "Changed path set matches.",
                {"changed": changed}, t0)


@register("diff.paths_denied", "No changed path starts with a denied prefix.",
          required=("deny",))
def _diff_paths_denied(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    denied = _list_param(p, "deny") or list(ctx.config.get("deny_paths", []))
    denied = [require_relative(d.rstrip("/")) for d in denied]
    if not denied:
        return _res("diff.paths_denied", UNVERIFIABLE, "MISSING_PARAM",
                    "Declare params.deny or config.deny_paths.", t0=t0)
    hits = [f for f in ctx.git.changed_files()
            if any(f == d or f.startswith(d + "/") for d in denied)]
    if hits:
        return _res("diff.paths_denied", FAIL, "DENIED_PATH_CHANGED",
                    f"{len(hits)} denied path(s) changed.", {"denied_paths_changed": hits}, t0)
    return _res("diff.paths_denied", PASS, "OK", "No denied path changed.",
                {"deny": denied}, t0)


@register("diff.max_lines", "Added and removed lines stay below a declared cap.",
          required=("max",))
def _diff_max_lines(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    raw = p.get("max", ctx.config.get("max_diff_lines"))
    if not isinstance(raw, int) or isinstance(raw, bool) or raw < 0:
        return _res("diff.max_lines", UNVERIFIABLE, "MISSING_PARAM",
                    "Declare params.max or config.max_diff_lines as a non-negative integer.", t0=t0)
    lines = [
        line for line in ctx.git.diff_text().splitlines()
        if (line.startswith("+") and not line.startswith("+++"))
        or (line.startswith("-") and not line.startswith("---"))
    ]
    count = len(lines)
    if count > raw:
        return _res("diff.max_lines", FAIL, "DIFF_TOO_LARGE",
                    f"{count} changed lines exceed the cap of {raw}.",
                    {"changed_lines": count, "max": raw}, t0)
    return _res("diff.max_lines", PASS, "OK", f"{count} changed lines within cap {raw}.",
                {"changed_lines": count, "max": raw}, t0)


@register("diff.no_deletions", "No file was deleted.",
          caveat="Detects status D in the diff against the base ref.")
def _diff_no_deletions(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    deleted = sorted(path for status, path in ctx.git.name_status() if status == "D")
    if deleted:
        return _res("diff.no_deletions", FAIL, "DELETIONS_PRESENT",
                    f"{len(deleted)} deleted file(s).", {"deleted": deleted}, t0)
    return _res("diff.no_deletions", PASS, "OK", "No deletions in the diff.", t0=t0)


@register("diff.no_secrets", "Curated detectors plus entropy screening on introduced lines.",
          caveat="Non-detection is not proof of absence. Scans added lines and untracked files only.")
def _diff_no_secrets(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    scan = scan_added_lines(ctx.git.added_lines())
    findings = scan.as_evidence()
    scanned = scan.lines_scanned
    if findings:
        return _res("diff.no_secrets", FAIL, "SECRET_PATTERN_MATCH",
                    f"{len(findings)} suspicious introduced line(s). Raw content is withheld.",
                    {"findings": findings, "lines_scanned": scanned}, t0)
    return _res("diff.no_secrets", PASS, "OK",
                f"No detector matched in {scanned} introduced line(s).",
                {"lines_scanned": scanned,
                 "limitation": "Detection is rule-based; absence is not proven."}, t0)


# --------------------------------------------------------------------------
# file witnesses
# --------------------------------------------------------------------------

def _named_paths(p: dict[str, Any]) -> list[str]:
    paths = _list_param(p, "files")
    if paths is None:
        single = p.get("path")
        if isinstance(single, str):
            paths = [require_relative(single)]
    if not paths:
        raise InputError("declare params.files or params.path")
    return paths


def _path_state(ctx: Context, rel: str) -> str:
    """present | absent | blocked.

    A path the policy refuses to inspect is neither present nor absent. Turning
    it into FAIL would let an attacker-manipulated repository manufacture
    falsifying evidence, so it must abstain instead.
    """
    try:
        target = safe_path(ctx.root, rel, must_exist=False)
    except PolicyViolation:
        return "blocked"
    return "present" if target.exists() else "absent"


@register("file.exists", "Named paths exist inside the repository.", required=("files",))
def _file_exists(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    paths = _named_paths(p)
    blocked = [rel for rel in paths if _path_state(ctx, rel) == "blocked"]
    if blocked:
        return _res("file.exists", UNVERIFIABLE, "POLICY_BLOCKED",
                    "One or more paths were refused by the path policy.",
                    {"blocked": blocked}, t0)
    missing = [rel for rel in paths if _path_state(ctx, rel) == "absent"]
    if missing:
        return _res("file.exists", FAIL, "FILE_MISSING", f"{len(missing)} path(s) missing.",
                    {"missing": missing}, t0)
    return _res("file.exists", PASS, "OK", "All named paths exist.", t0=t0)


@register("file.absent", "Named paths do not exist inside the repository.", required=("files",))
def _file_absent(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    paths = _named_paths(p)
    blocked = [rel for rel in paths if _path_state(ctx, rel) == "blocked"]
    if blocked:
        return _res("file.absent", UNVERIFIABLE, "POLICY_BLOCKED",
                    "One or more paths were refused by the path policy.",
                    {"blocked": blocked}, t0)
    present = [rel for rel in paths if _path_state(ctx, rel) == "present"]
    if present:
        return _res("file.absent", FAIL, "FILE_PRESENT", f"{len(present)} path(s) still exist.",
                    {"present": present}, t0)
    return _res("file.absent", PASS, "OK", "No named path exists.", t0=t0)


def _literal_check(ctx: Context, p: dict[str, Any], name: str, want_present: bool):
    t0 = _start()
    rel = require_relative(_one(p, "path"))
    literal = _one(p, "literal")
    if not literal or len(literal) > 256:
        raise InputError("literal must be 1..256 characters")
    data = read_file_bounded(ctx.root, rel)
    found = literal.encode("utf-8", errors="replace") in data
    if want_present and not found:
        return _res(name, FAIL, "LITERAL_NOT_FOUND", "The declared literal is absent.",
                    {"path": rel}, t0)
    if not want_present and found:
        return _res(name, FAIL, "LITERAL_FOUND", "The declared literal is present.",
                    {"path": rel}, t0)
    return _res(name, PASS, "OK", "Literal check satisfied.", {"path": rel}, t0)


@register("file.contains_literal", "A bounded literal byte search (never a regex).",
          required=("path", "literal"))
def _file_contains(ctx: Context, p: dict[str, Any]):
    return _literal_check(ctx, p, "file.contains_literal", True)


@register("file.no_literal", "A bounded literal byte search (never a regex).",
          required=("path", "literal"))
def _file_lacks(ctx: Context, p: dict[str, Any]):
    return _literal_check(ctx, p, "file.no_literal", False)


@register("file.hash_equals", "SHA-256 of a file equals the declared digest.",
          required=("path", "sha256"))
def _file_hash(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    rel = require_relative(_one(p, "path"))
    expected = _one(p, "sha256").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise InputError("sha256 must be 64 lowercase hex characters")
    actual = hashlib.sha256(read_file_bounded(ctx.root, rel)).hexdigest()
    if actual != expected:
        return _res("file.hash_equals", FAIL, "HASH_MISMATCH", "File digest differs.",
                    {"path": rel, "actual": actual, "expected": expected}, t0)
    return _res("file.hash_equals", PASS, "OK", "Digest matches.", {"path": rel}, t0)


@register("python.syntax_ok", "ast.parse every changed Python file in-process.",
          caveat="Parses only; never imports or executes repository code.")
def _python_syntax(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    files = _changed_python(ctx, p)
    if not files:
        return _res("python.syntax_ok", UNVERIFIABLE, "NO_TARGET_FILES",
                    "No changed Python file to parse.", t0=t0)
    errors = []
    for rel in files:
        try:
            data = read_file_bounded(ctx.root, rel)
            ast.parse(decode(data), filename=rel)
        except SyntaxError as exc:
            errors.append({"path": rel, "line": exc.lineno, "message": str(exc.msg)[:200]})
        except (PolicyViolation, LimitExceeded) as exc:
            return _res("python.syntax_ok", UNVERIFIABLE, "UNREADABLE_TARGET",
                        str(exc), {"path": rel}, t0)
    if errors:
        return _res("python.syntax_ok", FAIL, "SYNTAX_ERROR", f"{len(errors)} file(s) fail to parse.",
                    {"errors": errors}, t0)
    return _res("python.syntax_ok", PASS, "OK", f"Parsed {len(files)} Python file(s).",
                {"files": files}, t0)


@register("json.valid", "Parse named JSON files with the standard library.",
          required=("files",))
def _json_valid(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    files = _list_param(p, "files")
    if not files:
        return _res("json.valid", UNVERIFIABLE, "MISSING_PARAM", "Declare params.files.", t0=t0)
    errors = []
    for rel in files:
        try:
            json.loads(decode(read_file_bounded(ctx.root, rel)))
        except (ValueError, RecursionError) as exc:
            errors.append({"path": rel, "message": str(exc)[:200]})
        except (PolicyViolation, LimitExceeded) as exc:
            return _res("json.valid", UNVERIFIABLE, "UNREADABLE_TARGET", str(exc),
                        {"path": rel}, t0)
    if errors:
        return _res("json.valid", FAIL, "INVALID_JSON", f"{len(errors)} invalid JSON file(s).",
                    {"errors": errors}, t0)
    return _res("json.valid", PASS, "OK", f"Parsed {len(files)} JSON file(s).", t0=t0)


def _public_names(source: str) -> set[str]:
    tree = ast.parse(source)
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return {n for n in names if not n.startswith("_")}


@register("api.public_surface", "No public top-level Python symbol disappears.",
          caveat="A narrow structural proxy. It does not check signatures, behaviour or types.")
def _api_surface(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    if not ctx.git.base_exists():
        return _res("api.public_surface", UNVERIFIABLE, "BASE_REVISION_UNAVAILABLE",
                    "The base revision is not available for comparison.", t0=t0)
    files = _list_param(p, "files") or [
        f for f in ctx.git.changed_files() if f.endswith(".py") and (ctx.root / f).is_file()
    ]
    if not files:
        return _res("api.public_surface", UNVERIFIABLE, "NO_TARGET_FILES",
                    "No Python file to compare.", t0=t0)
    removed: list[dict[str, str]] = []
    compared = 0
    for rel in files:
        try:
            current = _public_names(decode(read_file_bounded(ctx.root, rel)))
        except (PolicyViolation, LimitExceeded):
            continue
        try:
            previous = _public_names(decode(ctx.git.base_file_bytes(rel)))
        except WitnessUnavailable:
            continue  # new file: nothing can disappear
        except (SyntaxError, ValueError) as exc:
            return _res("api.public_surface", UNVERIFIABLE, "UNPARSEABLE_TARGET",
                        f"Cannot parse {rel}: {exc}", t0=t0)
        compared += 1
        for name in sorted(previous - current):
            removed.append({"path": rel, "symbol": name})
    if compared == 0:
        return _res("api.public_surface", UNVERIFIABLE, "NO_BASELINE_FILES",
                    "No file could be compared against the base revision.", t0=t0)
    if removed:
        return _res("api.public_surface", FAIL, "PUBLIC_SYMBOL_REMOVED",
                    f"{len(removed)} public symbol(s) disappeared.", {"removed": removed}, t0)
    return _res("api.public_surface", PASS, "OK",
                f"No public symbol disappeared across {compared} file(s).",
                {"files_compared": compared}, t0)


@register("deps.unchanged", "Dependency manifests hash-identically match the base.",
          caveat="Only known manifest filenames are compared.")
def _deps_unchanged(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    if not ctx.git.base_exists():
        return _res("deps.unchanged", UNVERIFIABLE, "BASE_REVISION_UNAVAILABLE",
                    "The base revision is not available for comparison.", t0=t0)
    changed: list[dict[str, str]] = []
    compared = 0
    for rel in DEP_FILES:
        try:
            now = read_file_bounded(ctx.root, rel)
            now_exists = True
        except (PolicyViolation, LimitExceeded):
            now, now_exists = b"", False
        try:
            before = ctx.git.base_file_bytes(rel)
            before_exists = True
        except WitnessUnavailable:
            before, before_exists = b"", False
        if now_exists != before_exists:
            changed.append({"path": rel, "reason": "added_or_removed"})
            continue
        if not now_exists:
            continue
        compared += 1
        if hashlib.sha256(now).hexdigest() != hashlib.sha256(before).hexdigest():
            changed.append({"path": rel, "reason": "content_changed"})
    if changed:
        return _res("deps.unchanged", FAIL, "DEPENDENCY_MANIFEST_CHANGED",
                    f"{len(changed)} dependency manifest(s) changed.", {"changed": changed}, t0)
    if compared == 0:
        return _res("deps.unchanged", UNVERIFIABLE, "NO_TARGET_FILES",
                    "No known dependency manifest found in the repository.", t0=t0)
    return _res("deps.unchanged", PASS, "OK",
                f"{compared} dependency manifest(s) unchanged.", {"files_compared": compared}, t0)


@register("git.clean", "git status --porcelain is empty.")
def _git_clean(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    lines = [line for line in ctx.git.status_porcelain() if line.strip()]
    if lines:
        return _res("git.clean", FAIL, "DIRTY_WORKTREE",
                    f"{len(lines)} uncommitted change(s).", {"count": len(lines)}, t0)
    return _res("git.clean", PASS, "OK", "Worktree is clean.", t0=t0)


@register("tests.new_test_added", "At least one test file appears in the change.",
          caveat="Checks path names only. It does not prove the test is meaningful.")
def _tests_added(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    added = {path for status, path in ctx.git.name_status() if status in ("A", "M")}
    for path in ctx.git.changed_files():
        if path.startswith("tests/") or Path(path).name.startswith("test_"):
            added.add(path)
    matches = sorted(
        p for p in added
        if p.startswith("tests/") or Path(p).name.startswith("test_")
    )
    if not matches:
        return _res("tests.new_test_added", FAIL, "NO_TEST_FILE_ADDED",
                    "No test path appears in the change.", t0=t0)
    return _res("tests.new_test_added", PASS, "OK",
                f"{len(matches)} test path(s) changed.", {"paths": matches}, t0)


# --------------------------------------------------------------------------
# opt-in execution witnesses
# --------------------------------------------------------------------------

def _pytest_argv(target: str | None) -> list[str]:
    if target is None:
        return list(_PYTEST)
    return [*_PYTEST, validate_value(require_relative(target), "target")]


def _pytest_problem(res) -> str | None:
    text = (res.stdout + b"\n" + res.stderr).decode("utf-8", errors="replace").lower()
    if "no module named pytest" in text:
        return "TOOL_UNAVAILABLE"
    if res.truncated:
        return "OUTPUT_TRUNCATED"
    if res.timed_out:
        return "PROCESS_TIMEOUT"
    if "no tests ran" in text or "collected 0 items" in text:
        return "NO_TESTS_RAN"
    return None


@register("tests.pytest", "Fresh, complete, unfiltered pytest run.", trust=True,
          caveat="Executes repository test code. Requires --trust-tests.")
def _tests_pytest(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    blocked = _trust(ctx, "tests.pytest")
    if blocked:
        return blocked
    target = p.get("target")
    if target is not None and not isinstance(target, str):
        raise InputError("target must be a string")
    res = run_isolated(_pytest_argv(target), cwd=ctx.root)
    problem = _pytest_problem(res)
    if problem:
        return _res("tests.pytest", UNVERIFIABLE, problem,
                    "The run did not produce usable evidence.",
                    {"returncode": res.returncode, "detail": res.text(400)}, t0)
    if res.returncode != 0:
        return _res("tests.pytest", FAIL, "TESTS_FAILED",
                    f"pytest exited {res.returncode}.", {"output_tail": res.text(800)}, t0)
    return _res("tests.pytest", PASS, "OK", "pytest exited 0 with tests collected.",
                {"output_tail": res.text(400)}, t0)


def _extract_base_tree(tar_bytes: bytes, dest: Path) -> None:
    """Materialize a git archive without extractall.

    Every member is a regular file or directory, is bounded in size, and is
    written to a freshly resolved path inside dest. Symlinks, devices and hard
    links are rejected before anything is written.
    """
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
        members = archive.getmembers()[:MAX_TAR_MEMBERS]
        root = dest.resolve()
        for member in members:
            if not (member.isfile() or member.isdir()):
                raise PolicyViolation("base archive contains a non-regular member")
            name = member.name
            if name.startswith("/") or "\\" in name or ".." in Path(name).parts:
                raise PolicyViolation("unsafe member path in base archive")
            target = (root / name).resolve()
            if target != root and root not in target.parents:
                raise PolicyViolation("base archive member escapes destination")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            source = archive.extractfile(member)
            if source is None:
                raise PolicyViolation("base archive member has no data")
            payload = source.read(MAX_FILE_BYTES + 1)
            if len(payload) > MAX_FILE_BYTES:
                raise LimitExceeded("base archive member exceeds the file bound")
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.resolve() != root and root not in target.resolve().parents:
                raise PolicyViolation("base archive member escapes destination after mkdir")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            try:
                fd = os.open(target, flags, 0o600)
            except OSError as exc:
                raise PolicyViolation(f"cannot materialize archive member: {exc}") from exc
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)


@register("tests.discriminating",
          "A named test fails on the base revision and passes on the patched one.",
          trust=True, required=("test",),
          caveat="Executes repository test code in an isolated copy of the base tree. Requires --trust-tests.")
def _tests_discriminating(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    blocked = _trust(ctx, "tests.discriminating")
    if blocked:
        return blocked
    test = require_relative(_one(p, "test"))
    if not ctx.git.base_exists():
        return _res("tests.discriminating", UNVERIFIABLE, "BASE_REVISION_UNAVAILABLE",
                    "A base revision is required for a red/green proof.", t0=t0)
    test_bytes = read_file_bounded(ctx.root, test, max_bytes=MAX_FILE_BYTES)
    tar_bytes = ctx.git.base_tree_tar()
    with tempfile.TemporaryDirectory(prefix="proveit-base-") as tmp:
        base = Path(tmp)
        _extract_base_tree(tar_bytes, base)
        overlay = (base / test).resolve()
        if overlay != base.resolve() and base.resolve() not in overlay.parents:
            raise PolicyViolation("test path escapes base tree")
        overlay.parent.mkdir(parents=True, exist_ok=True)
        overlay.write_bytes(test_bytes)
        red = run_isolated(_pytest_argv(test), cwd=base)
        green = run_isolated(_pytest_argv(test), cwd=ctx.root)
    for label, res in (("base", red), ("patched", green)):
        problem = _pytest_problem(res)
        if problem:
            return _res("tests.discriminating", UNVERIFIABLE, problem,
                        f"The {label} run did not produce usable evidence.",
                        {"run": label, "detail": res.text(400)}, t0)
    if red.returncode == 0:
        return _res("tests.discriminating", FAIL, "TEST_NOT_DISCRIMINATING",
                    "The test passes on the base revision; it cannot detect the fix.",
                    {"base_returncode": red.returncode}, t0)
    if green.returncode != 0:
        return _res("tests.discriminating", FAIL, "TEST_FAILS_ON_PATCH",
                    "The test fails on the patched revision.",
                    {"patched_returncode": green.returncode, "output_tail": green.text(600)}, t0)
    return _res("tests.discriminating", PASS, "OK",
                "Red on base, green on patched: the test discriminates the change.",
                {"base_returncode": red.returncode, "patched_returncode": green.returncode}, t0)


@register("lint.ruff", "Fresh linter run with a fixed argv.", trust=True,
          caveat="Reads repository lint configuration. Requires --trust-tests.")
def _lint_ruff(ctx: Context, p: dict[str, Any]):
    t0 = _start()
    blocked = _trust(ctx, "lint.ruff")
    if blocked:
        return blocked
    if not _RUFF:
        return _res("lint.ruff", UNVERIFIABLE, "TOOL_UNAVAILABLE",
                    "ruff is not installed on this runner.", t0=t0)
    target = p.get("target")
    argv = [_RUFF, "check", "--output-format", "concise"]
    if target is not None:
        argv.append(validate_value(require_relative(str(target)), "target"))
    else:
        argv.append(".")
    res = run_isolated(argv, cwd=ctx.root)
    if res.truncated or res.timed_out:
        return _res("lint.ruff", UNVERIFIABLE, "OUTPUT_TRUNCATED",
                    "Linter output exceeded its bound.", t0=t0)
    if res.returncode == 0:
        return _res("lint.ruff", PASS, "OK", "ruff reported no findings.",
                    {"output_tail": res.text(400)}, t0)
    if res.returncode == 1:
        return _res("lint.ruff", FAIL, "LINT_ERRORS", "ruff reported findings.",
                    {"output_tail": res.text(800)}, t0)
    return _res("lint.ruff", UNVERIFIABLE, "TOOL_UNAVAILABLE",
                f"ruff exited {res.returncode}.", {"output_tail": res.text(400)}, t0)
