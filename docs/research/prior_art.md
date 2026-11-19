# Prior-Art Analysis: Claim-to-Evidence Verification for AI Coding Agents

## Executive summary

The proposed idea is **not fully anticipated, but it is far from a clean inventive leap**. Nearly every primitive already exists: test runners, linters, secret scanners, SCA tools, policy engines, reproducibility frameworks, build attestation, provenance tooling, and AI code reviewers can generate deterministic or semi-deterministic evidence. The novel—and still unproven—core would be a **claim compiler**: taking an arbitrary agent’s final message or transcript, identifying atomic claims, selecting or generating executable witnesses, running them in a trusted environment, emitting one of `PASS`, `FAIL`, or `UNVERIFIABLE`, and packaging the machine-readable evidence. Based on this multi-source scan, **no project was found that demonstrably implements this complete, agent-agnostic, LLM-free closed loop**. The closest projects are Superpowers’ “verification before completion,” OpenSquilla’s red/green/regression self-verification, TestMu’s Kane CLI evidence packages, and the small tool *honestly*, which blocks completion claims unsupported by test execution. Each stops short in a material way: they are in-agent workflow rules, self-contained agent runtimes, commercial platforms, or claim-interception hooks rather than universal post-hoc claim compilers.

The defensible gap is therefore narrow: **trustworthy mapping from a specific agent’s self-reported claim to a fresh, independently executed, provenance-bearing check, with explicit abstention when no safe witness exists**. A local-first Python CLI is plausible, but the product should not be sold as “we verify AI.” It can at best provide auditable evidence for claims that have a sound operational definition. Issue-resolution claims, backward compatibility, “only touched X and Y,” and semantic “fixed the bug” statements remain especially weak targets unless bound to pre-registered tests, schemas, API contracts, or other non-LLM witnesses.

## 1. Scope and standard of proof

The question is not whether tools can test code. It is whether an existing tool **consumes an agent’s natural-language completion claim**, **translates it into an executable check without using an LLM as judge**, **runs that check**, and **emits a falsifiable PASS/FAIL/UNVERIFIABLE verdict plus a machine-readable evidence bundle**. A tool that runs tests but does not know what claim it is testing is not sufficient. A tool that asks an LLM whether an agent completed its task is disqualified by the stated constraint. A tool that emits a structured report is not enough unless the report connects a specific claim to a specific independently executable check. This distinction is decisive: the industry has excellent evidence generators, but few systems tie evidence to the exact assertion made by the agent.

The evidence standard here is deliberately adversarial. Repository search results, product marketing, and secondary tutorials are used only to identify candidates and explain positioning. They are not treated as proof of a complete claim-to-evidence pipeline. Likewise, the inability of a web search to find a tool is not proof of non-existence; it lowers confidence in novelty but cannot replace a patent database or source-code search. The most this scan can support is the judgment that the proposed complete system is **not clearly documented as existing in the surveyed public sources**, not that it has zero prior art.

## 2. Closest existing projects

| Project | URL | What it actually verifies | Relationship to the proposed idea |
|---|---|---|---|
| Superpowers | https://github.com/superpowers/skills | Its `verification-before-completion` guidance bars completion claims without fresh evidence; the gate requires finding a supporting command, executing it, reading full output, and checking exit code and failure count. | Directly anticipates the principle and the gate logic, but it is an agent workflow/skill rather than a documented standalone tool that ingests arbitrary agent transcripts and emits a canonical evidence bundle. |
| OpenSquilla | https://github.com/OpenSquilla/OpenSquilla | Uses a red/green/regression chain: write a test expected to fail for the stated defect, make it pass, then run regression tests; the agent collects evidence before delivering. | Closest in spirit because the agent must show executable evidence. It is not shown to parse arbitrary agent completion messages, map claims to independently selected checks, or produce a standardized evidence package without an LLM. |
| *honestly* | https://github.com/obra/honestly | Intercepts completion claims such as “all tests pass,” checks whether relevant tests were freshly executed, detects `no tests ran` or failures, and rejects commands that hide test output. | Very close to claim interception and enforcement. Public descriptions do not establish arbitrary-agent transcript parsing, a broad library of executable claim witnesses, or a formal machine-readable evidence bundle. |
| TestMu Kane CLI | https://www.lambdatest.com/kane-cli | Converts requirements into recorded, replayable browser executions and produces an `.evidence` package containing traces, HAR, console/DOM state, video, and root-cause analysis; output can be exported to CTRF/JUnit. | Strong prior art for evidence packaging and deterministic replay, but the reported conversion from requirement to execution and analysis is not necessarily LLM-free, and it targets UI quality automation rather than generic coding-agent completion claims. |
| GitHub Spec Kit | https://github.com/github/spec-kit | Establishes a spec-driven development process: constitution, specification, plan, and tasks; the workflow creates artifacts used during implementation. | Anticipates formal completion conditions, but does not itself appear to be a claim compiler or verifier for arbitrary agent text. |
| OpenSpec | https://github.com/microsoft/OpenSpec | Maintains change specifications and lifecycle artifacts; references a `verify` workflow stage after implementation. | Relevant as a structured target against which completion can be checked. The exact input language and claim-to-check compiler are not documented in the accessible materials reviewed here. |
| BMAD Method | https://github.com/BMAD-Code/BMAD-METHOD | Provides agent workflow skills and structured development artifacts, including verification-oriented practices. | It provides process discipline, not independent claim-to-evidence compilation. |
| Open Policy Agent | https://www.openpolicyagent.org/ | Evaluates structured data against declarative Rego policies and can emit JSON decisions. | A strong policy-decision substrate. It verifies facts against rules; it does not extract claims from natural language or run tests. |
| Conftest | https://www.conftest.dev/ | Runs OPA/Rego policies against configuration, Terraform, Kubernetes, and other structured files. | It can produce policy evidence for structured artifacts, but it does not understand an agent’s prose completion message. |
| SLSA / in-toto attestation | https://slsa.dev/, https://in-toto.io/ | Describes authenticated provenance, build statements, and verifiable attestations about how artifacts were built. | A mature foundation for signed evidence bundles, but it attests to build or supply-chain facts rather than adjudicating an agent’s completion claim. |
| Sigstore | https://www.sigstore.dev/ | Provides signing, verification, and provenance infrastructure for software artifacts. | Relevant for integrity and authenticity of the evidence bundle, not for claim extraction or test execution. |
| Gitleaks | https://github.com/gitleaks/gitleaks | Scans git repositories, files, and pipelines for secrets using deterministic rules; supports JSON output. | Directly relevant to “no secrets were introduced,” but only checks the repository or files it is pointed at; it does not parse the agent’s claim. |
| TruffleHog | https://github.com/trufflesecurity/trufflehog | Scans sources for verified or unverified secrets and supports JSON output. | Same limitation as Gitleaks: a powerful witness, not a claim compiler. |
| GitGuardian / ggshield | https://www.gitguardian.com/, https://github.com/GitGuardian/ggshield | Detects secrets in repositories, pre-receive hooks, and developer environments; exposes machine-readable results. | Useful backend checker; the broader product adds remediation and SaaS workflow, but it is not an agent-claim adjudicator. |
| Ruff, ESLint, ShellCheck, Semgrep, Bandit, etc. | https://github.com/astral-sh/ruff, https://github.com/eslint/eslint, https://github.com/koalaman/shellcheck, https://github.com/semgrep/semgrep, https://github.com/PyCQA/bandit | Run deterministic or rule-based static analysis and emit structured diagnostics. | These can verify syntactic, style, and many security claims, but their verdicts apply to code, not the agent’s assertion. |
| Pytest / JUnit / other test runners | https://docs.pytest.org/, https://junit.org/ | Execute tests, produce exit codes, JUnit XML, JSON, and structured reports. | The canonical executable witness for “all tests pass,” but they do not know whether the run is fresh, complete, independent, or relevant to the claim. |
| SWE-bench | https://www.swebench.com/ | Uses `FAIL_TO_PASS` and `PASS_TO_PASS` tests to determine whether a patch fixes an issue and avoids unrelated regressions. | A major prior-art system for semantic completion evidence, but it is a benchmark/evaluation harness with curated tests, not a general-purpose verifier for arbitrary agent messages. |
| GitHub Actions review bots / PR bots | https://github.com/features/actions | Run CI jobs, tests, scans, and automated review on pull requests. | They can aggregate evidence at merge time, but most AI review products use models to judge code or produce advisory comments rather than issuing deterministic claim verdicts. |
| CodeRabbit, Snyk, GitHub Advanced Security, etc. | https://www.coderabbit.ai/, https://snyk.io/, https://github.com/features/security | Provide security, quality, dependency, secret, and code-review signals. | These can be excellent evidence sources; many are SaaS, model-assisted, or advisory rather than a local, LLM-free claim adjudicator. |
| Git-ai | https://github.com/git-ai/git-ai | Tracks AI-generated code attribution and measures agent activity/cost. | It is a line-attribution and ROI/productivity tool, not a verifier of completion claims. The name makes it look relevant, but its function is different. |

## 3. What each closest system actually verifies

### Superpowers anticipates the gate, but not the compiler

Superpowers is the most direct conceptual prior art. Its `verification-before-completion` skill is built around the rule that a completion claim should not be made without fresh verification evidence. The documented gate asks the agent to find a command capable of supporting the conclusion, actually execute it, read complete output, inspect exit code and failure counts, and confirm that the result truly supports the conclusion. This is not merely “run tests”; it is a deliberate chain from assertion to evidence. Its weakness relative to the proposal is that it is normally enforced **inside an agent’s own workflow**, mediated by instructions to the same agent. That creates a self-referential trust problem: the agent is told not to claim completion without evidence, but the gate can still be bypassed if the agent fails to invoke it, misruns a command, or interprets evidence incorrectly. The publicly described system also does not appear to be a local CLI that ingests a transcript from Claude Code, Codex, Cursor, or another unrelated agent and emits a stable evidence schema.

### OpenSquilla demonstrates self-verification, not external auditing

OpenSquilla is important because it moves beyond asking the agent to summarize what it did. It uses a red/green/regression workflow: first create a test that exposes the defect; then implement until the new test passes; then run regression tests to check for collateral damage. This directly addresses the core failure mode in which an agent says “I fixed the bug” without any discriminating test. It is substantially more credible than a static code review because the evidence must come from execution. Yet it remains the **agent’s own internal harness**. The available public evidence does not show that it accepts a free-form final message from any agent, compiles that message into a separate set of checks, or produces a portable bundle with hashes, environment data, and per-claim verdicts. It also inherits a deep verification risk: tests written by the same agent may encode the same mistaken understanding of the bug.

### *honestly* directly attacks completion honesty, but with a narrow scope

The *honestly* project is unusually close because it is designed to prevent a familiar deception pattern: the agent edits code and reports success even though it never executed tests, executed them before the edit, or truncated the output. It checks whether tests actually ran, whether any failed, and whether shell commands such as `head`, `grep`, or `wc` might have hidden the test summary. This is closer to a guardrail than to a general verifier, and it appears tightly coupled to test-completion claims. Its most valuable insight is that output capture and freshness matter as much as test success. However, the public description does not establish a general claim taxonomy, multi-tool witness selection, a stable JSON/JSONL evidence bundle, or support for claims such as “I only touched files X and Y,” “no secrets,” or “backward compatible.”

### Kane CLI proves that evidence packaging is already a product category

TestMu’s Kane CLI is especially relevant to the evidence-bundle requirement. It records browser interactions, replays them deterministically, and produces an `.evidence` package containing the agent trace, HAR requests, console output, DOM state, video, and analysis, with Markdown/YAML forms and export to CTRF and JUnit. This shows that the industry already treats test execution records as portable audit artifacts. The limitation is scope and judgment: Kane is focused on web/UI verification, its “requirement-to-judgment” path is not established as LLM-free, and it does not ingest arbitrary coding-agent text. It is therefore stronger prior art for the bundle format and deterministic replay than for the semantic compiler.

### Spec-driven toolkits anticipate structured completion criteria, not free-text interpretation

Spec Kit, OpenSpec, and BMAD are often cited in the same conversation because they attempt to replace vague final messages with machine-legible plans, tasks, and acceptance conditions. This is important prior art: if a team already writes a specification or task list, the verifier need not interpret prose. OpenSpec explicitly references a `verify` stage, and Spec Kit structures the development process around specs, plans, and tasks. But neither appears to be documented as a tool that reads an arbitrary agent’s final message, identifies which task or spec clause it references, and dispatches executable checks. They provide the **target language** that makes verification easier; they do not necessarily perform the mapping.

### Policy engines provide decision formats, not semantic understanding

OPA and Conftest are exact fits for the desired output discipline. OPA evaluates structured facts against declarative Rego rules and can emit JSON decisions; Conftest applies those rules to files, manifests, and configurations. This is a strong architectural precedent for deterministic verdicts and machine-readable evidence. However, both assume that facts are already encoded. Neither tool reads “I only touched files X and Y” and derives the appropriate diff check. They would be excellent downstream policy components of the proposed system, not complete prior art.

### Secret scanners can answer one claim type, but only under the right model

Gitleaks, TruffleHog, and ggshield are especially relevant to “no secrets were introduced.” They can scan a repository, staged changes, or pipeline artifacts; apply deterministic rules; and emit JSON. That means the proposed system does not need to invent secret detection. But a correct implementation must avoid two naïve errors. First, scanning the whole repo is not enough if the agent temporarily held a secret in an uncommitted file or environment variable. Second, a scanner’s failure to find a secret supports only the narrow statement “the scanned artifact matched none of the scanner’s rules.” It does not prove that no secret exists. A mature verdict should therefore distinguish scanner non-detection from cryptographic or formal absence.

### Build provenance proves artifacts, not agent claims

SLSA, in-toto attestations, and Sigstore solve a related but different trust problem. They can authenticate who built an artifact, what materials were used, and what steps occurred. This is valuable infrastructure for an evidence bundle because it allows a later auditor to check that a test result was signed by a known runner and not manufactured after the fact. Yet provenance does not by itself say whether an agent’s claim about fixing issue #12 is true. It can show that a particular test command was run in a particular build, but not whether the issue’s semantic requirement was correctly understood.

### SWE-bench is a powerful evaluator, but curated and benchmark-bound

SWE-bench is important counterevidence to the claim that “nothing verifies agent work.” It pairs issues with `FAIL_TO_PASS` tests that initially fail and `PASS_TO_PASS` tests that must remain green, then grades whether the agent’s patch resolves the issue and avoids unrelated regressions. This is far stronger than asking a model whether code looks correct. The reason it does not fully anticipate the proposal is that the benchmark supplies curated issue-to-test mappings, known environments, and a fixed evaluation protocol. The proposed product would have to infer or construct that mapping from a novel agent statement in an arbitrary repository.

## 4. The exact remaining gap

The remaining gap is not “verification tooling.” It is the **claim contract and witness dispatch layer** between natural-language assertions and independently runnable checks. More precisely, the unmet system must:

1. accept an agent transcript or final message plus a repository, diff, issue, specification, or test baseline;
2. identify atomic, falsifiable claims rather than vague summaries;
3. classify each claim as having a known executable witness, requiring structured input, or having no sound non-LLM test;
4. generate or select a safe, minimally privileged command or policy check;
5. execute that check in a clean, isolated, reproducible environment after the change;
6. bind the output to the claim through command identity, repository state, input hashes, output hashes, timestamps, exit codes, and signatures;
7. return `PASS`, `FAIL`, or `UNVERIFIABLE` with a reason; and
8. package the bundle in a stable schema that can be independently replayed or audited.

The third and seventh steps are the heart of the novelty—and the highest technical risk. If the system cannot parse a claim safely, it must abstain rather than fabricate a test. If the agent says “I fixed issue #12,” the tool should not invent a test that merely asserts the new code exists. It should resolve the issue to a requirement, identify a discriminating test or acceptance scenario, and report `UNVERIFIABLE` when none exists. Similarly, “backward compatible” is not a single executable claim unless it is decomposed into API schema compatibility, database migration reversibility, client contract tests, and dependency version constraints.

The gap is also **trust-boundary engineering**. A verifier must not trust test output produced by the agent under test. It needs its own runner, its own environment, and its own collection of artifacts. It must detect stale runs, partial output, test-hiding pipes, mock-only test suites, missing dependency installation, and tests that were modified by the patch. Otherwise, it becomes a sophisticated echo of the agent rather than an independent judge.

## 5. Direct verdict

**No surveyed project demonstrably implements the complete proposed system.** The verdict is *not novel as a collection of ideas*, but *plausibly novel as an integrated product* under a strict reading of the requirement: agent-agnostic ingestion of natural-language completion claims; deterministic, executable, LLM-free verification; a tri-state PASS/FAIL/UNVERIFIABLE judgment; and a portable evidence bundle. The strongest evidence against broad novelty is Superpowers’ fresh-evidence completion gate, OpenSquilla’s self-verification chain, *honestly*’s test-execution interception, Kane’s evidence packages, and SWE-bench’s issue-to-test evaluation protocol. Together, they cover nearly every component. The gap is the composition and, crucially, the requirement that the system work after the fact on **any** agent’s statement rather than directing a specific agent’s behavior.

This should not be described as “nothing like it exists.” That claim would be false. A more accurate statement is: **the architecture is highly derivative, but a useful niche remains in post-hoc, independent, claim-resolving evidence compilation**. The novelty would have to be earned through a concrete and auditable design, not through the observation that agents make unverified claims.

## 6. Five strongest arguments that the idea is derivative or useless

### 6.1 It is mostly glue around mature verification infrastructure

A first-cut implementation would call git, pytest, ruff, Gitleaks, Semgrep, OPA, and a build runner. There is no new test theory, no new static analysis, and no new policy logic. The visible product would be a parser, a test dispatcher, and a JSON report. Competitors could recreate the integration quickly, and developers may reasonably ask why they should install a CLI instead of running the same commands in CI.

### 6.2 The hard part is semantic interpretation, which the design explicitly forbids

The interesting claims are semantic: “fixed issue #12,” “backward compatible,” “only touched X and Y,” or “no secrets.” The first cannot be checked without understanding the issue; the second requires an explicit compatibility contract; the third can be checked only against an agreed baseline; and the fourth is a negative statement with no complete effective decision procedure. Prohibiting an LLM judge removes the only component flexible enough to bridge ambiguous language, but the alternative—hand-written claim grammars and per-repo adapters—is expensive and incomplete.

### 6.3 Agents can simply lie about claims or change wording

Natural-language completion text is not a contract. An agent can phrase the same work differently, make no claim, or state “I believe the change fixes the bug.” A post-hoc verifier must either attempt unreliable semantic parsing or require structured claim syntax. The former is vulnerable to prompt injection and paraphrase; the latter moves the burden back to the agent and reduces the value of accepting arbitrary transcripts. The strongest design may therefore be hybrid: extract candidate claims with a small parser or local model, but never use an LLM to make the final verdict.

### 6.4 Self-verification can share the agent’s blind spots

Even when tests pass, they may test the wrong requirement or share the patch’s incorrect assumptions. This is not a theoretical concern: benchmark research has repeatedly found that agents and evaluators can be exploited through shared environments, exposed answers, weak string matching, or tests altered by the agent. A general verifier must run independent tests, forbid test mutation by the change under test, isolate the runner, and use mutation testing or adversarial test review for high-stakes claims.

### 6.5 Evidence does not establish trust without provenance and governance

A JSON file containing test output is not automatically credible. Developers will ask who ran the test, which binary produced the result, whether the repository state matches, whether the test was complete, and whether the result was signed. Existing provenance, attestation, and policy ecosystems already cover much of that work. A new CLI that reinvents its own untrusted evidence format is unlikely to be adopted; one that merely wraps existing tools may be perceived as a thin wrapper.

## 7. Defensible design choices

### Make the input a claim schema, not free prose

Do not market the product as understanding arbitrary language. Accept a structured claim manifest alongside the transcript:

```json
{
  "claims": [
    {
      "id": "C1",
      "statement": "I fixed the bug described in issue #12",
      "issue": 12,
      "expected_evidence": {
        "type": "issue_test",
        "failing_before": "tests/issue_12_failure.py",
        "must_pass": ["tests/issue_12_failure.py"],
        "regression_suite": "pytest tests/"
      }
    }
  ]
}
```

The system can still extract candidate claims from text, but every candidate should be normalized into this schema and confirmed or rejected before verification. This avoids undocumented LLM judgment while allowing users and agent harnesses to adopt a claim standard over time.

### Use a small, closed world of witness types

Ship a registry of safe, versioned witnesses: diff set membership, baseline comparison, file ownership, test execution, build, lint, schema compatibility, migration dry-run, dependency diff, secret scan, SCA, and policy evaluation. Each witness should declare its prerequisites, allowed commands, inputs, outputs, exit-code contract, freshness constraints, and attack-model limitations. Arbitrary code generation must be prohibited; the verifier should never execute a shell command extracted from an agent message.

### Separate claim discovery from claim judgment

A parser may identify candidate claims and emit a claim plan. A deterministic planner then maps each accepted claim to one or more registered witnesses. The final verdict must be computed only from command exit codes, structured output, git state, hashes, and signed provenance. The system may optionally use a local small language model to normalize text, but it must not use any model to decide PASS, FAIL, UNVERIFIABLE, security severity, test relevance, or code correctness.

### Enforce trusted execution and freshness

Run checks in an isolated runner with pinned tool versions and no access to the agent’s secrets. Record pre- and post-patch commit hashes, working-tree state, repository URL, command line, environment hash, start/end time, stdout/stderr, files used, files produced, and the raw result. Reject results when the test command ran before the patch, produced no tests, had output truncated, was filtered through an unsafe pipe, or came from an unsigned runner.

### Embrace UNVERIFIABLE as a first-class output

The most credible design will often return `UNVERIFIABLE` because it has no discriminating test for a claim. This is not a weakness to hide; it is the product’s value. A system that always finds a check will fabricate relevance. The report should distinguish `PASS` from `UNVERIFIABLE_DUE_TO_MISSING_TEST`, `UNVERIFIABLE_DUE_TO_AMBIGUOUS_CLAIM`, and `UNVERIFIABLE_DUE_TO_ENVIRONMENT_REQUIREMENT`.

### Bind the bundle to a verifiable audit chain

Use a SLSA/in-toto-compatible attestation envelope or a clearly specified subset. Include an agent transcript hash, claim manifest hash, patch/diff hash, witness descriptors and versions, runner identity, raw outputs, and signatures. The bundle should be replayable: an independent system can re-run the recorded command in an equivalent environment and obtain the same result. If exact replay is impossible, it should preserve enough state for an independent re-execution rather than merely containing a screenshot or a PDF.

### Integrate with CI rather than compete with it

The CLI should be usable locally, but its natural home is a pull-request gate. It should convert claim results to Check Run annotations, JUnit XML, CTRF, SARIF, or OPA-compatible JSON. The unit of merge should be a **claim manifest plus evidence**, not a prose message. This changes the developer workflow from “trust my summary” to “present proof for the assertions you chose to make.”

### Add adversarial coverage, not more LLM commentary

For high-risk claims, add mutation testing, property-based tests, fuzzing, contract tests, or golden-file comparisons. Provide a mode that searches for tests which should fail on the base revision and pass on the patched revision. This directly addresses the shared-blind-spot failure. It also creates a measurable quality signal: coverage of claims, discriminating power of tests, and independent evidence freshness.

## 8. Adoption and competitive strategy

A local-first Python CLI can win only if it reduces integration friction. It should have zero mandatory cloud account, work from a Git checkout, read `claims.yaml`, run only declared checks, and emit one signed bundle. It should integrate with GitHub Actions, GitLab CI, pre-commit, and common test runners without replacing them. The CLI should not try to replace code review; it should triage which claims have evidence and which remain human judgments.

The strongest product narrative is **evidence accounting**, not “AI verification.” Teams do not need another model telling them whether code is good. They need to know which assertions have reproducible proof, which lack proof, and which proofs are stale, incomplete, or produced by an untrusted runner. The product should therefore expose a dashboard of claim coverage, evidence freshness, witness versions, and UNVERIFIABLE reasons. Over time, it could become a shared schema for agent harnesses, CI systems, and attestation services.

To deter fast cloning, the defensible moat should be an open claim schema, a vetted library of safe witnesses, reproducible execution environments, strong provenance bindings, and auditability—not a proprietary LLM. Open-source reference implementations of common claim types, along with conformance tests, would make the format more credible than a closed SaaS. A commercial version could add policy management, secret handling, private runners, audit retention, and enterprise identity without changing the core claim-contract model.

## 9. Recommended research and clearance actions

Before investing further, search the USPTO, EPO, WIPO Patentscope, and major code hosts for the exact phrases “completion claim,” “verification before completion,” “claim evidence bundle,” and “agent transcript verification.” Review the repositories of *honestly*, OpenSquilla, Superpowers, Kane CLI, and SWE-bench at the file level rather than relying on marketing or secondary articles. Conduct a patent attorney search, because workflow and evidence-pack claims may still be anticipated even when no end-to-end open-source project is found. Finally, validate the product with a controlled study: compare agent completion claims against independently generated tests, measure how often a naive test suite passes for an incorrect patch, and report the UNVERIFIABLE rate honestly.

## 10. Important sources and links

1. https://github.com/superpowers/skills
2. https://github.com/OpenSquilla/OpenSquilla
3. https://github.com/obra/honestly
4. https://www.lambdatest.com/kane-cli
5. https://github.com/github/spec-kit
6. https://github.com/microsoft/OpenSpec
7. https://github.com/BMAD-Code/BMAD-METHOD
8. https://www.openpolicyagent.org/
9. https://www.conftest.dev/
10. https://slsa.dev/
11. https://in-toto.io/
12. https://www.sigstore.dev/
13. https://github.com/gitleaks/gitleaks
14. https://github.com/trufflesecurity/trufflehog
15. https://www.gitguardian.com/
16. https://github.com/GitGuardian/ggshield
17. https://github.com/astral-sh/ruff
18. https://github.com/eslint/eslint
19. https://github.com/koalaman/shellcheck
20. https://github.com/semgrep/semgrep
21. https://github.com/PyCQA/bandit
22. https://docs.pytest.org/
23. https://junit.org/
24. https://www.swebench.com/
25. https://github.com/features/actions
26. https://github.com/features/security
27. https://www.coderabbit.ai/
28. https://snyk.io/
29. https://github.com/git-ai/git-ai

## Evidence caveats

This report relies on a public web scan and accessible project material available through 2026-11-12. Several candidate repository pages could not be retrieved through the page fetcher, so their internal commands and exact outputs are not described beyond material that could be corroborated through secondary official-linked documentation or reputable project descriptions. “No tool was found” is therefore a **research conclusion, not a legal guarantee of novelty**. Patent databases, private code repositories, and unpublished enterprise products were not exhaustively searched. The report also does not independently verify whether every commercial product’s AI review capability uses an LLM; such claims should be checked in current vendor documentation before being used in a clearance opinion.