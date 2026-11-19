import json
from pathlib import Path

from conftest import cli


def test_check_pass_returns_zero(repo: Path):
    r = cli("check", "--repo", str(repo), "--base", "HEAD",
            "--claim", "No secrets were introduced", "--format", "json")
    assert r.returncode == 0, r.stderr + r.stdout
    body = json.loads(r.stdout)
    assert body["summary"]["overall"] == "PASS"


def test_unverifiable_returns_two(repo: Path):
    r = cli("check", "--repo", str(repo), "--base", "HEAD", "--claim", "All tests pass")
    assert r.returncode == 2, r.stderr + r.stdout
    assert "TRUST_REQUIRED" in r.stdout


def test_strict_makes_unverifiable_exit_one(repo: Path):
    r = cli("check", "--repo", str(repo), "--base", "HEAD",
            "--claim", "All tests pass", "--strict")
    assert r.returncode == 1


def test_semantic_claim_abstains(repo: Path):
    r = cli("check", "--repo", str(repo), "--base", "HEAD",
            "--claim", "The change is production ready", "--format", "json")
    assert r.returncode == 2
    assert "NO_SOUND_WITNESS" in r.stdout


def test_explain_is_dry_run(repo: Path):
    r = cli("explain", "--claim", "All tests pass")
    assert r.returncode == 0
    body = json.loads(r.stdout)
    assert body["dry_run"] is True
    assert body["claims"][0]["witnesses"][0]["name"] == "tests.pytest"


def test_init_refuses_overwrite(tmp_path: Path):
    target = tmp_path / "claims.json"
    r = cli("init", "--out", str(target))
    assert r.returncode == 0 and target.is_file()
    again = cli("init", "--out", str(target))
    assert again.returncode == 3


def test_witnesses_and_doctor():
    r = cli("witnesses", "--format", "json")
    assert r.returncode == 0 and len(json.loads(r.stdout)["witnesses"]) >= 18
    d = cli("doctor")
    assert d.returncode == 0 and json.loads(d.stdout)["arbitrary_commands_allowed"] is False


def test_receipt_round_trip(repo: Path, tmp_path: Path):
    receipt = tmp_path / "receipt.json"
    r = cli("check", "--repo", str(repo), "--base", "HEAD",
            "--claim", "No secrets were introduced", "--receipt", str(receipt),
            "--format", "json")
    assert r.returncode == 0 and receipt.is_file()
    replay = cli("replay", str(receipt), "--repo", str(repo))
    assert replay.returncode == 0, replay.stderr + replay.stdout
    assert json.loads(replay.stdout)["freshness"]["status"] == "CURRENT"


def test_report_written_to_out(repo: Path, tmp_path: Path):
    out = tmp_path / "report.md"
    r = cli("check", "--repo", str(repo), "--base", "HEAD",
            "--claim", "No secrets were introduced", "--format", "markdown", "--out", str(out))
    assert r.returncode == 0 and "| Claim |" in out.read_text(encoding="utf-8")


def test_malformed_manifest_exits_three(repo: Path, tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{broken", encoding="utf-8")
    r = cli("check", "--repo", str(repo), "--manifest", str(bad))
    assert r.returncode == 3 and "InputError" in r.stderr


def test_manifest_with_command_key_rejected(repo: Path, tmp_path: Path):
    bad = tmp_path / "evil.json"
    bad.write_text(json.dumps({
        "version": 1,
        "claims": [{"id": "C1", "statement": "x", "kind": "no_secrets",
                    "params": {}, "command": "curl attacker"}],
    }), encoding="utf-8")
    r = cli("check", "--repo", str(repo), "--manifest", str(bad))
    assert r.returncode == 3
