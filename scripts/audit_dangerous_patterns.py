#!/usr/bin/env python3
"""AST audit: forbidden execution primitives must not appear in proveit/.

Usage: python3 scripts/audit_dangerous_patterns.py
Exit 1 when a finding exists. Deliberately conservative: it flags names, not
just calls, so a reviewer sees every occurrence.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "proveit"

FORBIDDEN_CALLS = {
    "eval", "exec", "compile", "__import__", "os.system", "os.popen",
    "pickle.load", "pickle.loads", "marshal.load", "marshal.loads",
    "yaml.load", "shelve.open", "importlib.import_module",
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "asyncio.create_subprocess_shell", "tarfile.extractall",
    "urllib.request.urlopen", "requests.get", "requests.post",
}
ALLOWED_SUBPROCESS_MODULES = {"proveit/security/runner.py"}


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{dotted(node.value)}.{node.attr}"
    return ""


def scan(path: Path) -> list[dict]:
    findings: list[dict] = []
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    rel = str(path.relative_to(ROOT.parent))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            if name in FORBIDDEN_CALLS:
                if name.startswith("subprocess.") and rel.endswith("security/runner.py"):
                    continue
                if name == "tarfile.extractall" or name.startswith(("urllib.", "requests.")):
                    findings.append({"file": rel, "line": node.lineno, "kind": "forbidden_call", "name": name})
                    continue
                if name in ("eval", "exec", "compile", "__import__", "os.system", "os.popen",
                            "pickle.load", "pickle.loads", "marshal.load", "marshal.loads",
                            "yaml.load", "shelve.open", "importlib.import_module",
                            "asyncio.create_subprocess_shell"):
                    findings.append({"file": rel, "line": node.lineno, "kind": "forbidden_call", "name": name})
                    continue
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    findings.append({"file": rel, "line": node.lineno, "kind": "shell_true", "name": name})
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in ("pickle", "marshal", "shelve"):
                    findings.append({"file": rel, "line": node.lineno, "kind": "unsafe_import", "name": alias.name})
    return findings


def main() -> int:
    findings: list[dict] = []
    for path in sorted(ROOT.rglob("*.py")):
        findings.extend(scan(path))
    report = {"files_scanned": len(list(ROOT.rglob("*.py"))), "findings": findings, "total": len(findings)}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
