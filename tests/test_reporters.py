import json
from pathlib import Path
from xml.etree import ElementTree

import pytest

from proveit.claims import claims_from_manifest
from proveit.engine import build_context, evaluate
from proveit.errors import UsageError
from proveit.reporters import FORMATS, render


def _receipt(repo: Path, statement: str = "no secrets") -> dict:
    claims = claims_from_manifest({"claims": [
        {"id": "C1", "statement": statement, "kind": "no_secrets", "params": {}, "source": "manifest"}
    ]})
    return evaluate(claims, build_context(str(repo), "HEAD", False)).to_dict()


def test_all_formats_render(repo: Path):
    body = _receipt(repo)
    for fmt in FORMATS:
        out = render(body, fmt)
        assert isinstance(out, str) and len(out) > 20


def test_json_format_is_canonical(repo: Path):
    body = _receipt(repo)
    assert json.loads(render(body, "json")) == body


def test_sarif_is_well_formed(repo: Path):
    sarif = json.loads(render(_receipt(repo), "sarif"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "proveit"
    assert len(sarif["runs"][0]["results"]) == 1


def test_junit_is_parseable_and_escapes(repo: Path):
    xml = render(_receipt(repo, "check <script>alert(1)</script> & more"), "junit")
    root = ElementTree.fromstring(xml)
    assert root.tag == "testsuites"
    assert "<script>" not in xml


def test_markdown_has_table(repo: Path):
    md = render(_receipt(repo), "markdown")
    assert "| Claim |" in md and "proveit claim receipt" in md


def test_terminal_reports_verdict(repo: Path):
    text = render(_receipt(repo), "terminal")
    assert "[PASS]" in text and "receipt" in text


def test_unknown_format_raises(repo: Path):
    with pytest.raises(UsageError):
        render(_receipt(repo), "pdf")
