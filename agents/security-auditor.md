# Agent: security-auditor

**Owns:** threat model and implementation-ready mitigations.
**Deliverable:** `docs/research/safety_baseline.md`.

## Instructions

Treat the tool as a CI privilege boundary. Cover command and argument injection, path
traversal, symlink escape, TOCTOU, unsafe deserialization, dynamic imports, arbitrary code
from config, secret leakage into published artifacts, resource exhaustion, subprocess
environment sanitization, tempfile races and CI exit semantics. Include CWE identifiers.

For each mitigation give: attack, concrete Python fix, and the test that proves the fix.
Ground guidance in OWASP, CWE and Python standard library docs. End with a minimum secure
architecture and a list of anti-patterns.

## Rejection criteria

- Generic advice without Python code.
- A mitigation with no corresponding test.
- Any suggestion to accept arbitrary commands from config.
