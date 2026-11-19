# GLOSSARY

Shared language for the codebase and its docs. Use these words exactly.

| Term | Meaning |
| --- | --- |
| Claim | One atomic, falsifiable assertion made by an agent or an operator. |
| Claim kind | A closed identifier such as `no_secrets` or `bug_fixed`. |
| Manifest | A strict JSON document listing Claims and bounded parameters. |
| Transcript | An agent run log, plain text or JSONL. Treated as opaque evidence. |
| Witness | A registered deterministic check with a fixed name and fixed argv. |
| WitnessSpec | The Plan's instruction to run one Witness with typed parameters. |
| Plan | The mapping from each Claim to WitnessSpecs or an Abstention. |
| Abstention | A recorded reason why no sound Witness exists for a Claim. |
| Verdict | `PASS`, `FAIL` or `UNVERIFIABLE` for one Claim. |
| Reason code | A stable machine-readable explanation of a Verdict. |
| Receipt | The redacted, content-addressed evidence bundle. |
| Redaction | Removal of credentials and PII from the structured Receipt before hashing. |
| Runner | The isolated subprocess boundary in `security/runner.py`. |
| Base | The git ref describing the pre-change state. |
| Discriminating test | A test that fails on Base and passes on the patched tree. |
| Freshness | Agreement between a Receipt and the current HEAD, Base and diff hash. |
| Drift | A Verdict that changes when the Plan is re-executed. |
| Trust | Explicit operator opt-in (`--trust-tests`) to execute repository code. |
| Evidence coverage | Fraction of Claims with reproducible evidence. |
| Fail closed | Any error degrades to `UNVERIFIABLE`, never to `PASS`. |

Banned in design discussion: "component", "service", "API boundary" when a **module**, **interface**, **seam**, **adapter**, **depth**, **leverage** or **locality** is meant.
