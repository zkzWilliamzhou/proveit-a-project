#!/usr/bin/env python3
"""Validate the vendored skill folders without a YAML dependency.

Checks the two required frontmatter fields from the Agent Skills format, the
name regex, and the folder/name match. It does not validate upstream content.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
NAME = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def _frontmatter(path: Path) -> tuple[dict[str, str], str | None]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, "missing opening frontmatter delimiter"
    try:
        end = next(i for i in range(1, len(lines)) if lines[i].strip() == "---")
    except StopIteration:
        return {}, "missing closing frontmatter delimiter"
    fields: dict[str, str] = {}
    for line in lines[1:end]:
        if not line or line.lstrip().startswith("#"):
            continue
        match = re.match(r"^([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.*)$", line)
        if match:
            value = match.group(2).strip()
            if value.startswith(("'", '"')) and value.endswith(value[0]):
                value = value[1:-1]
            fields[match.group(1)] = value
    return fields, None


def main() -> int:
    problems: list[str] = []
    checked = 0
    for folder in sorted(p for p in SKILLS.iterdir() if p.is_dir()):
        skill = folder / "SKILL.md"
        if not skill.is_file():
            problems.append(f"{folder.name}: missing SKILL.md")
            continue
        fields, error = _frontmatter(skill)
        if error:
            problems.append(f"{folder.name}: {error}")
            continue
        checked += 1
        name = fields.get("name", "")
        description = fields.get("description", "")
        if not name:
            problems.append(f"{folder.name}: missing name")
        elif not NAME.match(name) or len(name) > 64:
            problems.append(f"{folder.name}: invalid name {name!r}")
        elif name != folder.name:
            problems.append(f"{folder.name}: name {name!r} does not match folder")
        if not description:
            problems.append(f"{folder.name}: missing description")
        elif len(description) > 1024:
            problems.append(f"{folder.name}: description exceeds 1024 characters")
    report = {"folders_checked": checked, "problems": problems, "valid": not problems}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
