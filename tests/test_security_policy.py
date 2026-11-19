import json

import pytest

from proveit.errors import InputError, LimitExceeded, PolicyViolation
from proveit.security.policy import load_config_bytes, load_manifest_bytes

VALID = {
    "version": 1,
    "claims": [
        {"id": "C1", "statement": "no secrets", "kind": "no_secrets", "params": {}},
        {"id": "C2", "statement": "only app.py", "kind": "only_changed_files",
         "params": {"files": ["app.py"]}},
    ],
}


def _b(obj) -> bytes:
    return json.dumps(obj).encode("utf-8")


def test_valid_manifest():
    doc = load_manifest_bytes(_b(VALID))
    assert len(doc["claims"]) == 2
    assert doc["claims"][1]["params"]["files"] == ["app.py"]


@pytest.mark.parametrize("extra", [
    {"command": "rm -rf /"},
    {"shell": "bash"},
    {"plugin": "evil.py"},
    {"import": "os"},
    {"eval": "1+1"},
    {"regex": "(a+)+$"},
])
def test_forbidden_keys_rejected(extra):
    doc = dict(VALID)
    doc.update(extra)
    with pytest.raises(PolicyViolation):
        load_manifest_bytes(_b(doc))


def test_forbidden_param_key_rejected():
    doc = json.loads(json.dumps(VALID))
    doc["claims"][0]["params"] = {"command": "curl attacker"}
    with pytest.raises(PolicyViolation):
        load_manifest_bytes(_b(doc))


def test_unknown_claim_key_rejected():
    doc = json.loads(json.dumps(VALID))
    doc["claims"][0]["executable"] = "/bin/sh"
    with pytest.raises(PolicyViolation):
        load_manifest_bytes(_b(doc))


def test_duplicate_ids_rejected():
    doc = json.loads(json.dumps(VALID))
    doc["claims"][1]["id"] = "C1"
    with pytest.raises(InputError):
        load_manifest_bytes(_b(doc))


def test_float_rejected():
    doc = json.loads(json.dumps(VALID))
    doc["claims"][0]["params"] = {"max": 1.5}
    with pytest.raises(InputError):
        load_manifest_bytes(_b(doc))


def test_non_utf8_rejected():
    with pytest.raises(InputError):
        load_manifest_bytes(b"\xff\xfe\x00")


def test_invalid_json_rejected():
    with pytest.raises(InputError):
        load_manifest_bytes(b"{not json")


def test_size_cap():
    with pytest.raises(LimitExceeded):
        load_manifest_bytes(b" " * (600 * 1024))


def test_deep_nesting_cap():
    node: dict = {"version": 1, "claims": [{"id": "C1", "statement": "x", "kind": "no_secrets",
                                           "params": {}}]}
    cursor = node["claims"][0]["params"]
    for _ in range(30):
        cursor["nested"] = {}
        cursor = cursor["nested"]
    with pytest.raises(LimitExceeded):
        load_manifest_bytes(_b(node))


def test_nan_rejected():
    with pytest.raises(InputError):
        load_manifest_bytes(b'{"version": NaN, "claims": []}')


def test_config_valid_and_unknown_key():
    assert load_config_bytes(_b({"version": 1, "base": "HEAD~1", "max_diff_lines": 50}))["base"] == "HEAD~1"
    with pytest.raises(PolicyViolation):
        load_config_bytes(_b({"version": 1, "shell": "sh"}))
