from pathlib import Path

import pytest

from proveit.errors import LimitExceeded, PolicyViolation
from proveit.security.paths import (
    canonical_root,
    read_file_bounded,
    require_relative,
    safe_path,
    validate_ref,
    validate_value,
)


@pytest.mark.parametrize("bad", [
    "../escape", "a/../../etc", "/etc/passwd", "C:/windows", "a\\b",
    "", "-leading", "a/./b", "a/~/b", "a\x00b", "a:ref",
])
def test_relative_paths_rejected(bad):
    with pytest.raises(PolicyViolation):
        require_relative(bad)


@pytest.mark.parametrize("good", ["app.py", "src/app.py", "tests/test_a.py", ".github/workflows/ci.yml"])
def test_relative_paths_accepted(good):
    assert require_relative(good) == good


@pytest.mark.parametrize("bad", ["--upload-pack=x", "-x", "HEAD:app.py", "../x", "ref:s", "a b"])
def test_refs_rejected(bad):
    with pytest.raises(PolicyViolation):
        validate_ref(bad)


@pytest.mark.parametrize("good", ["HEAD", "HEAD~1", "HEAD^", "main", "refs/heads/main", "a1b2c3d"])
def test_refs_accepted(good):
    assert validate_ref(good) == good


@pytest.mark.parametrize("bad", ["-aR", "--exec=cmd", "@input", "a b", "a\x00b", "$(id)"])
def test_values_rejected(bad):
    with pytest.raises(PolicyViolation):
        validate_value(bad)


def test_symlink_escape_is_rejected(repo: Path):
    (repo / "link").symlink_to("/etc")
    with pytest.raises(PolicyViolation):
        safe_path(canonical_root(repo), "link/passwd")


def test_symlink_inside_root_is_allowed(repo: Path):
    (repo / "link.py").symlink_to(repo / "app.py")
    resolved = safe_path(canonical_root(repo), "link.py")
    assert resolved.is_file()


def test_read_is_bounded(repo: Path):
    (repo / "big.txt").write_bytes(b"x" * 5000)
    with pytest.raises(LimitExceeded):
        read_file_bounded(canonical_root(repo), "big.txt", max_bytes=1024)


def test_read_normal_file(repo: Path):
    assert read_file_bounded(canonical_root(repo), "app.py").startswith(b"def public_func")


def test_o_nofollow_rejects_final_symlink(repo: Path):
    (repo / "link.py").symlink_to(repo / "app.py")
    with pytest.raises(PolicyViolation):
        read_file_bounded(canonical_root(repo), "link.py")
