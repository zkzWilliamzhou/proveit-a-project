"""Regression tests for findings from review rounds 3, 4 and 5."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from proveit.claims import claims_from_manifest
from proveit.engine import build_context, evaluate
from proveit.errors import PolicyViolation
from proveit.model import UNVERIFIABLE
from proveit.reporters import FORMATS, render
from proveit.witnesses import get


def _receipt(repo: Path, statement: str) -> dict:
    claims = claims_from_manifest({"claims": [
        {"id": "C1", "statement": statement, "kind": "no_secrets", "params": {}, "source": "manifest"}
    ]})
    return evaluate(claims, build_context(str(repo), "HEAD", False)).to_dict()


def test_ansi_and_control_characters_never_reach_reports(repo: Path):
    evil = "\x1b[31mRED\x1b[0m no secrets \x00 \x07 <script>alert(1)</script>"
    body = _receipt(repo, evil)
    for fmt in FORMATS:
        output = render(body, fmt)
        assert "\x1b" not in output, fmt
        assert "\x00" not in output, fmt
        assert "\x07" not in output, fmt


def test_junit_stays_well_formed_with_hostile_text(repo: Path):
    from xml.etree import ElementTree

    xml = render(_receipt(repo, "a & b < c > d \"quoted\" 'single'"), "junit")
    ElementTree.fromstring(xml)
    assert "<script>" not in xml


def test_markdown_cannot_break_out_of_table(repo: Path):
    md = render(_receipt(repo, "a | b\nsecond line"), "markdown")
    assert "| Claim |" in md
    assert md.count("| `no_secrets` |") == 1
    assert "| a \\| b second line |" in md


def test_sarif_rules_cover_every_result(repo: Path):
    sarif = json.loads(render(_receipt(repo, "plain claim"), "sarif"))
    declared = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in declared for r in sarif["runs"][0]["results"])
    assert all("helpUri" not in r for r in sarif["runs"][0]["tool"]["driver"]["rules"])


def _tar_with(members) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = payload.decode()
                archive.addfile(info)
            else:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
    return buf.getvalue()


def test_base_archive_rejects_symlink_member(tmp_path: Path):
    from proveit.witnesses.builtin import _extract_base_tree

    blob = _tar_with([("evil", "symlink", b"/etc")])
    with pytest.raises(PolicyViolation):
        _extract_base_tree(blob, tmp_path)
    assert not (tmp_path / "evil").is_symlink()


def test_base_archive_rejects_traversal_member(tmp_path: Path):
    from proveit.witnesses.builtin import _extract_base_tree

    blob = _tar_with([("../escape.py", "file", b"x = 1\n")])
    with pytest.raises(PolicyViolation):
        _extract_base_tree(blob, tmp_path)
    assert not (tmp_path.parent / "escape.py").exists()


def test_base_archive_extracts_regular_files(tmp_path: Path):
    from proveit.witnesses.builtin import _extract_base_tree

    blob = _tar_with([("app.py", "file", b"x = 1\n"), ("tests", "dir", b"")])
    _extract_base_tree(blob, tmp_path)
    assert (tmp_path / "app.py").read_bytes() == b"x = 1\n"


def test_refused_path_is_not_reported_as_failure(repo: Path):
    (repo / "link").symlink_to("/etc")
    for name, params in (("file.exists", {"files": ["link/passwd"]}),
                         ("file.absent", {"files": ["link/passwd"]})):
        res = get(name).fn(build_context(str(repo), "HEAD", False), params)
        assert res.status == UNVERIFIABLE, name
        assert res.reason_code == "POLICY_BLOCKED", name


def test_nested_symlink_loop_is_rejected(repo: Path):
    from proveit.security.paths import canonical_root, safe_path

    (repo / "a").mkdir()
    (repo / "a" / "b").symlink_to(repo / "a")
    with pytest.raises((PolicyViolation, OSError, RuntimeError)):
        safe_path(canonical_root(repo), "a/b/c")


def test_git_ref_rejects_refspec(repo: Path):
    from proveit.errors import PolicyViolation as PV
    from proveit.security.paths import validate_ref

    with pytest.raises(PV):
        validate_ref("HEAD:app.py")
    with pytest.raises(PV):
        validate_ref("--upload-pack=touch /tmp/x")


def test_secret_raw_content_never_enters_receipt(repo: Path):
    (repo / "app.py").write_text('api_key = "AKIA\x49OSFODNN7EXAMPLE"\n', encoding="utf-8")
    from proveit.claims import claims_from_manifest

    claims = claims_from_manifest({"claims": [
        {"id": "C1", "statement": "no secrets", "kind": "no_secrets", "params": {}, "source": "manifest"}
    ]})
    body = evaluate(claims, build_context(str(repo), "HEAD", False)).to_dict()
    assert "AKIA\x49OSFODNN7EXAMPLE" not in json.dumps(body)
    assert body["verdicts"][0]["status"] == "FAIL"
