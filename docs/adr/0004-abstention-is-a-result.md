# ADR 0004: Abstention is a first class result

**Status:** Accepted

## Context

A verifier that always finds a check will fabricate relevance. "Production ready", "secure", "I fixed issue #12" and "backward compatible" have no finite deterministic witness unless someone supplies a contract. An LLM judge would hide that gap behind fluent prose.

## Decision

The claim grammar lists semantic kinds that abstain with `NO_SOUND_WITNESS`. `bug_fixed` without `params.test` abstains with `NO_DISCRIMINATING_TEST`. Unknown kinds abstain with `UNRECOGNIZED_CLAIM_KIND`. Missing tools, timeouts, truncated output, refused paths and witness exceptions produce distinct reason codes (`TOOL_UNAVAILABLE`, `PROCESS_TIMEOUT`, `OUTPUT_TRUNCATED`, `POLICY_BLOCKED`, `LIMIT_EXCEEDED`, `INTERNAL_ERROR`, `TRUST_REQUIRED`).

`FAIL` is reserved for evidence that contradicts a claim. A refused read is never `FAIL`, because an attacker-controlled symlink could otherwise manufacture falsifying evidence.

`PASS` means reproducible evidence exists. It does not mean the code is correct. Every terminal and Markdown report says so.

## Consequences

- Real-world runs often return `UNVERIFIABLE`. That is the product working.
- `claim_coverage` and `evidence_coverage` in the Receipt make abstention measurable.
- Exit code 2 keeps unverifiable claims visible in CI without blocking a merge unless `--strict` is set.
