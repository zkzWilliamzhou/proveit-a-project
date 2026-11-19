import hashlib
from pathlib import Path

from proveit.model import FAIL, PASS, UNVERIFIABLE
from proveit.witnesses import get


def run(name: str, ctx, params=None):
    return get(name).fn(ctx, params or {})


def test_clean_worktree(repo: Path, ctx_for):
    assert run("git.clean", ctx_for(repo)).status == PASS
    (repo / "app.py").write_text("changed\n", encoding="utf-8")
    assert run("git.clean", ctx_for(repo)).status == FAIL


def test_changed_subset(repo: Path, ctx_for):
    (repo / "app.py").write_text("def public_func():\n    return 3\n", encoding="utf-8")
    assert run("diff.changed_subset", ctx_for(repo), {"files": ["app.py"]}).status == PASS
    bad = run("diff.changed_subset", ctx_for(repo), {"files": ["other.py"]})
    assert bad.status == FAIL and bad.reason_code == "UNEXPECTED_CHANGED_PATHS"
    assert run("diff.changed_subset", ctx_for(repo)).status == UNVERIFIABLE


def test_no_secrets_detects_added_secret(repo: Path, ctx_for):
    assert run("diff.no_secrets", ctx_for(repo)).status == PASS
    (repo / "app.py").write_text(
        'api_key = "AKIA\x49OSFODNN7EXAMPLE"\n', encoding="utf-8"
    )
    res = run("diff.no_secrets", ctx_for(repo))
    assert res.status == FAIL and res.reason_code == "SECRET_PATTERN_MATCH"
    assert "AKIA\x49OSFODNN7EXAMPLE" not in str(res.evidence)


def test_python_syntax(repo: Path, ctx_for):
    (repo / "app.py").write_text("def public_func():\n    return 3\n", encoding="utf-8")
    assert run("python.syntax_ok", ctx_for(repo)).status == PASS
    (repo / "app.py").write_text("def broken(:\n", encoding="utf-8")
    bad = run("python.syntax_ok", ctx_for(repo))
    assert bad.status == FAIL and bad.reason_code == "SYNTAX_ERROR"


def test_json_valid(repo: Path, ctx_for):
    assert run("json.valid", ctx_for(repo), {"files": ["data.json"]}).status == PASS
    (repo / "data.json").write_text("{oops", encoding="utf-8")
    assert run("json.valid", ctx_for(repo), {"files": ["data.json"]}).status == FAIL
    assert run("json.valid", ctx_for(repo)).status == UNVERIFIABLE


def test_dependency_manifest(repo: Path, ctx_for):
    assert run("deps.unchanged", ctx_for(repo)).status == PASS
    (repo / "requirements.txt").write_text("foo==2.0\n", encoding="utf-8")
    assert run("deps.unchanged", ctx_for(repo)).status == FAIL


def test_public_surface(repo: Path, ctx_for):
    (repo / "app.py").write_text("def helper():\n    return 2\n", encoding="utf-8")
    bad = run("api.public_surface", ctx_for(repo))
    assert bad.status == FAIL and bad.reason_code == "PUBLIC_SYMBOL_REMOVED"
    (repo / "app.py").write_text(
        "def public_func():\n    return 3\n\ndef helper():\n    return 2\n", encoding="utf-8"
    )
    assert run("api.public_surface", ctx_for(repo)).status == PASS


def test_no_deletions(repo: Path, ctx_for):
    assert run("diff.no_deletions", ctx_for(repo)).status == PASS
    (repo / "README.md").unlink()
    assert run("diff.no_deletions", ctx_for(repo)).status == FAIL


def test_max_lines(repo: Path, ctx_for):
    (repo / "app.py").write_text("\n".join(f"x{i} = {i}" for i in range(6)), encoding="utf-8")
    assert run("diff.max_lines", ctx_for(repo), {"max": 100}).status == PASS
    assert run("diff.max_lines", ctx_for(repo), {"max": 2}).status == FAIL
    assert run("diff.max_lines", ctx_for(repo)).status == UNVERIFIABLE


def test_paths_denied(repo: Path, ctx_for):
    (repo / ".github").mkdir()
    (repo / ".github" / "ci.yml").write_text("x: 1\n", encoding="utf-8")
    bad = run("diff.paths_denied", ctx_for(repo), {"deny": [".github"]})
    assert bad.status == FAIL
    assert run("diff.paths_denied", ctx_for(repo), {"deny": ["docs"]}).status == PASS


def test_file_witnesses(repo: Path, ctx_for):
    assert run("file.exists", ctx_for(repo), {"path": "app.py"}).status == PASS
    assert run("file.exists", ctx_for(repo), {"path": "nope.py"}).status == FAIL
    assert run("file.absent", ctx_for(repo), {"path": "nope.py"}).status == PASS
    assert run("file.contains_literal", ctx_for(repo),
               {"path": "app.py", "literal": "def public_func"}).status == PASS
    assert run("file.no_literal", ctx_for(repo),
               {"path": "app.py", "literal": "print("}).status == PASS
    digest = hashlib.sha256((repo / "app.py").read_bytes()).hexdigest()
    assert run("file.hash_equals", ctx_for(repo),
               {"path": "app.py", "sha256": digest}).status == PASS
    assert run("file.hash_equals", ctx_for(repo),
               {"path": "app.py", "sha256": "0" * 64}).status == FAIL


def test_new_test_added(repo: Path, ctx_for):
    assert run("tests.new_test_added", ctx_for(repo)).status == FAIL
    (repo / "tests" / "test_new.py").write_text("def test_new():\n    assert True\n", encoding="utf-8")
    assert run("tests.new_test_added", ctx_for(repo)).status == PASS


def test_opt_in_gating(repo: Path, ctx_for):
    for name in ("tests.pytest", "tests.discriminating", "lint.ruff"):
        res = run(name, ctx_for(repo, trust=False))
        assert res.status == UNVERIFIABLE and res.reason_code == "TRUST_REQUIRED"


def test_discriminating_test_red_green(repo: Path, ctx_for):
    # 42 appears nowhere in the base revision, so the test must be red there.
    (repo / "app.py").write_text("def public_func():\n    return 42\n", encoding="utf-8")
    (repo / "tests" / "test_fix.py").write_text(
        "from pathlib import Path\n\n\ndef test_fix():\n"
        "    assert 'return 42' in Path('app.py').read_text()\n",
        encoding="utf-8",
    )
    res = run("tests.discriminating", ctx_for(repo, trust=True),
              {"test": "tests/test_fix.py"})
    assert res.status == PASS, res.detail + str(res.evidence)
    assert res.evidence["base_returncode"] != 0
    assert res.evidence["patched_returncode"] == 0


def test_discriminating_rejects_non_discriminating_test(repo: Path, ctx_for):
    (repo / "tests" / "test_weak.py").write_text(
        "def test_weak():\n    assert True\n", encoding="utf-8"
    )
    res = run("tests.discriminating", ctx_for(repo, trust=True),
              {"test": "tests/test_weak.py"})
    assert res.status == FAIL and res.reason_code == "TEST_NOT_DISCRIMINATING"


def test_pytest_fresh_run(repo: Path, ctx_for):
    res = run("tests.pytest", ctx_for(repo, trust=True), {"target": "tests"})
    assert res.status == PASS, res.detail + str(res.evidence)
