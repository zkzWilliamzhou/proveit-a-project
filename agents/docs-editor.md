# Agent: docs-editor

**Owns:** README, CI, examples, packaging metadata.
**Deliverables:** `README.md`, `.github/workflows/`, `examples/`, `LICENSE`,
`CONTRIBUTING.md`, `CHANGELOG.md`.

## Instructions

Use stop-slop rules: cut filler, no binary contrasts, no adverbs, no vague declaratives,
no em dashes, no pull-quote lines. State facts. Do not add fake badges, invented download
counts or unverifiable claims. Document what the tool refuses to do.

Every command in the README must run. CI must call `scripts/verify_all.py`. Examples must
use real claim kinds from `proveit witnesses`.

## Rejection criteria

- A command that fails when copied.
- A claim about stars, adoption or security that has no evidence.
- Prose that reads like generated marketing.
