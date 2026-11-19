# Workflow and quality gates

The build ran as a managed pipeline. One manager owned the plan, assigned a specialist to each work item, inspected every deliverable and rejected anything incomplete. Rejected work came back with a specific defect list. No agent marked its own work done.

## Roster

| Agent | Owns | Deliverable | Gate |
| --- | --- | --- | --- |
| `prior-art-researcher` | Novelty and adoption | `docs/research/prior_art.md` | Adversarial. Must name the closest existing tools with URLs and state the exact remaining gap. No flattery. |
| `security-auditor` | Threat model and mitigations | `docs/research/safety_baseline.md` | Must cite CWE identifiers and give a Python fix plus a test per mitigation. |
| `product-architect` | Scope, claim taxonomy, verdict semantics | `docs/ADR`s, `docs/GLOSSARY.md`, `docs/ARCHITECTURE.md` | Must define what abstains. Must not claim the idea is unprecedented. |
| `implementer` | Source code, CLI, 20 witnesses | `proveit/`, `tests/` | Every public behavior gets a test. No arbitrary command execution. |
| `test-engineer` | Adversarial and regression suite | `tests/`, `scripts/` | Exploit payloads must be reproduced as tests, not asserted away. |
| `reviewer` (8 rounds) | Bug and safety review | `docs/REVIEW_LOG.md` | Each round names a real finding, a fix and the test that locks it. |
| `architecture-reviewer` | Deepening with behavior preservation | `docs/architecture-review.html`, ADR 0002 | Deletion test on every candidate. Fingerprint must match before and after. |
| `docs-editor` | README, CI, examples | `README.md`, `.github/`, `examples/` | No AI slop, no fake badges, no unverifiable claims. |

## Order

1. Install and read the requested GitHub skills.
2. Adversarial prior-art scan, then a second independent ideation round after evidence.
3. Security baseline before implementation, so the runner and policy loader are designed against attacks rather than patched after them.
4. Scope and claim grammar. Declare abstentions first.
5. Implement core, witnesses, reporters, receipts and CLI.
6. Build tests and audit scripts.
7. Eight examination rounds. Each round runs real tooling and can halt the release.
8. Architecture deepening with a hard behavior-preservation gate.
9. Documentation, CI, examples.
10. Release gate: `python3 scripts/verify_all.py`. Package.

## Manager rejection rules

A deliverable comes back when it:

- asserts success without a command that produced evidence;
- reports `PASS` from an exception, a timeout or a refused path;
- uses a repo-supplied string as a command, import path or regex;
- includes raw secret content in an artifact;
- adds a plugin or dynamic-loading seam inside a trust boundary;
- claims novelty as fact rather than as a bounded research conclusion;
- changes a function during an architecture pass;
- adds a lint suppression without naming the reason;
- ships docs with unverifiable marketing claims.

## Eight review rounds

See `docs/REVIEW_LOG.md`. Each round has scope, method, finding, fix and locking test. Rounds 1 to 7 found real defects. Round 8 verified the architecture gate and the final release state.

## Skill usage

`skills/` contains vendored GitHub skills with attribution in `docs/VENDOR_SKILLS.md`. The practices actually applied: brainstorming and adversarial grilling, verification before completion, systematic debugging, TDD, codebase-design vocabulary, improve-codebase-architecture (deletion test, deepening, report, grilling loop), stop-slop for prose, and Vercel writing guidelines for docs.
