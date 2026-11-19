import json
from pathlib import Path

import pytest

from proveit.claims import claims_from_manifest
from proveit.engine import build_context, evaluate
from proveit.errors import InputError
from proveit.receipt import freshness, load_receipt, replay, write_receipt


def _receipt(repo: Path):
    claims = claims_from_manifest({"claims": [
        {"id": "C1", "statement": "no secrets", "kind": "no_secrets", "params": {}, "source": "manifest"}
    ]})
    return evaluate(claims, build_context(str(repo), "HEAD", False)).to_dict()


def test_write_load_integrity(repo: Path, tmp_path: Path):
    body = _receipt(repo)
    path = tmp_path / "out" / "receipt.json"
    write_receipt(body, path)
    assert path.is_file()
    assert load_receipt(path)["receipt_id"] == body["receipt_id"]


def test_tampered_receipt_rejected(repo: Path, tmp_path: Path):
    body = _receipt(repo)
    path = tmp_path / "receipt.json"
    write_receipt(body, path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["summary"]["overall"] = "FAIL"
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(InputError, match="integrity"):
        load_receipt(path)


def _stable_body(body: dict) -> dict:
    """Remove fields that legitimately vary between two evaluations."""
    cleaned = {k: v for k, v in body.items() if k not in {"receipt_id", "created_at"}}
    verdicts = []
    for verdict in cleaned.get("verdicts", []):
        copy = dict(verdict)
        copy["witnesses"] = [
            {k: v for k, v in w.items() if k != "duration_ms"}
            for w in copy.get("witnesses", [])
        ]
        verdicts.append(copy)
    cleaned["verdicts"] = verdicts
    return cleaned


def test_receipt_content_is_stable_for_identical_state(repo: Path):
    assert _stable_body(_receipt(repo)) == _stable_body(_receipt(repo))


def test_freshness_detects_drift(repo: Path):
    body = _receipt(repo)
    ctx = build_context(str(repo), "HEAD", False)
    assert freshness(body, ctx)["status"] == "CURRENT"
    (repo / "app.py").write_text("changed\n", encoding="utf-8")
    assert freshness(body, ctx)["status"] == "STALE"


def test_replay_without_execute(repo: Path):
    body = _receipt(repo)
    ctx = build_context(str(repo), "HEAD", False)
    out = replay(body, ctx)
    assert out["freshness"]["status"] == "CURRENT"
    assert out.get("re_executed") is None


def test_replay_with_execute(repo: Path):
    body = _receipt(repo)
    ctx = build_context(str(repo), "HEAD", False)
    out = replay(body, ctx, execute=True)
    assert out["re_executed"] is True
    assert out["verdict_drift"] == []
    assert out["current_overall"] == out["recorded_overall"]
