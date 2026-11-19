# Safety Baseline for an Untrusted-Input Verification CLI

## Executive summary

Treat this tool as an **adversarial parser, not a workflow helper**. It ingests attacker-controlled repositories, config files, agent transcripts, and user-supplied verification parameters; it therefore occupies the same threat position as a CI privilege boundary. The default posture must be deny-by-default, read-only inspection, no network, no shell, and execution only through a tightly versioned, explicit allowlist. CWE-78 command injection and CWE-88 argument injection are primary threats; even `shell=False` does not prevent `rm -rf --no-preserve-root /` if the program constructs the argv list from untrusted values. Path traversal (CWE-22), symlink escape (CWE-59), and TOCTOU races arise when the tool computes a working path before opening it or follows a repository symlink outside the checkout. Deserialization, YAML tags, pickle, `eval`, `compile`, `importlib`, and repo-provided plugin modules are unconditionally treated as remote-code-execution primitives (CWE-502, CWE-94). Published evidence bundles are public artifacts: secret and PII filters must run on structured fields before serialization, not merely suppress terminal output.

The recommended implementation is a small core with four isolated stages: (1) immutable repo/transcript ingestion; (2) claim extraction into an enumerated schema; (3) policy-controlled command execution against an allowlist of frozen tool versions; (4) redaction and signed, atomic publication of evidence. Each command must be a fixed template; the only permitted external data are bounded, typed, allowlisted values interpolated as separate argv items. Python’s `subprocess.run` is used with a list, `shell=False`, an empty environment, a read-only `cwd`, `close_fds=True`, and a deadline. Repository paths are validated with `Path.resolve()` followed by a mandatory prefix check; any symlink that escapes the repository root is rejected. Tests must reproduce each exploit, not merely assert “no exception.” The tool fails closed on parse failure, unknown config keys, unsupported tools, redaction failure, size limits, deadlines, and permission errors.

## 1. This is a high-impact execution boundary, not ordinary CLI input validation

**The attack surface combines untrusted data, code-like configuration, and external process execution.** A repository can contain a rule file claiming to verify a project with a command such as `bash -c`, `python -c`, `git`, `curl`, or `rm`. A transcript can contain a model-generated claim that an attacker has already influenced through repository text, prompt injection, or direct transcript modification. A user may ask the tool to run an additional check. If the implementation turns any of these into a command string, imports a class named in config, expands a path relative to a symlink, or includes raw output in SARIF, it is no longer validating claims—it is allowing untrusted data to choose behavior.

CWE-78 describes external input modifying an OS command because special elements are not neutralized; its consequences include unauthorized command execution and modification of data that the user did not directly authorize [1]. CWE-88 is the more subtle case: even when shell metacharacters are filtered, an argument beginning with `-` or containing a delimiter can change program options or add arguments [2]. For example, a “filename” of `-aR` can turn a programmatic `ls -l <name>` invocation into `ls -l -aR`, producing a recursive listing. Both must be defeated by data/code separation, not string filtering.

**The minimum safe answer is not “sanitize the command”; it is “do not accept arbitrary commands.”** Verification capability should be implemented as a fixed catalog:

| Verifier identifier | Implementation | Permitted external values | Example unsafe request |
|---|---|---|---|
| `git.log.contains` | `git -C <root> log --max-count=1 --format=%s -- <path>` | repository-relative path from allowlist | `bash -c "..."` |
| `file.literal_absent` | open file, byte search | file path, literal bytes | regex compiled from config |
| `python.syntax_check` | `python -m py_compile <file>` | fixed executable path, one file | `python -c <repo string>` |
| `json.schema_valid` | in-process jsonschema validation | schema URI from trusted catalog | schema that executes code |
| `command.allowlisted` | only allowed after operator opt-in | named template + bounded params | arbitrary argv |

No config key may specify an executable path, loader, plugin, Python expression, regex flag, import path, or shell command. A declarative rule is data; it must not be able to express control flow, import machinery, or command semantics.

**Natural-language claim extraction is an untrusted parsing boundary.** Do not send the entire repository or transcript to a model with “extract claims and return code.” Instead, run deterministic, bounded extraction first; require structured output; validate every field against an explicit JSON schema; and constrain the verifier catalog by the claim type. Claim text should be handled as opaque evidence, not trusted instructions. If an LLM is used, it must run in a separate, network-isolated process with no repository-execution privileges and a maximum output token limit. The CLI must reject claims whose requested verifier, tool, or path is outside the policy. Treat model-generated command suggestions as human input: never executable.

## 2. Prioritized mitigation checklist

**Priority 1 controls determine whether the tool can execute arbitrary behavior. They must be implemented and tested before any feature work.**

### 1. Arbitrary command execution from repo config and user input

**Attack.** A rule file contains `command: ["sh","-c","curl attacker"]`, `python -c`, `rm -rf /`, `git config --global`, or a request to load a repository plugin. The tool builds an argv list from the file or passes a string through the shell. This maps to CWE-78 and CWE-94.

**Fix.** Use a static verifier catalog. The repository may supply only an opaque rule identifier and bounded parameters. Select the command template in application code, validate parameter types, and pass values as separate list items. Never use `shell=True`. Do not call `eval`, `exec`, `compile`, `getattr` on a name from data, `importlib.import_module`, `subprocess` on strings, `os.system`, `os.popen`, or `asyncio.create_subprocess_shell`.

```python
from dataclasses import dataclass
from pathlib import Path
import subprocess
from typing import Sequence

@dataclass(frozen=True)
class Verifier:
    name: str
    executable: str
    fixed_args: tuple[str, ...]
    max_input_bytes: int

ALLOWLIST: dict[str, Verifier] = {
    "py.compile": Verifier("py.compile", "/usr/bin/python3", ("-m", "py_compile"), 1_048_576),
}

def run_verifier(name: str, work_dir: Path, params: Sequence[str], limits) -> subprocess.CompletedProcess:
    verifier = ALLOWLIST.get(name)
    if verifier is None:
        raise PolicyViolation(f"verifier not allowed: {name!r}")
    if len(params) > 1:
        raise PolicyViolation("too many parameters")
    if params and not _is_allowlisted_value(params[0]):
        raise PolicyViolation("parameter not allowlisted")
    argv: list[str] = [verifier.executable, *verifier.fixed_args, *params]
    return subprocess.run(
        argv,
        cwd=work_dir,
        env={},
        shell=False,
        close_fds=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        timeout=limits.process_timeout,
        check=False,
    )
```

**Test.** Add a repo rule containing `command: ["sh","-c","touch /tmp/pwned"]`. Assert the process is never started and the filesystem object is not created. Add `command: "python -c 'open(\"/tmp/pwned\",\"w\").write(\"x\")'"`, which must be rejected as not a valid catalog reference. Add `params=["-c","evil"]` and assert it is not appended. Add a fuzz test that generates random strings for parameters and asserts the child always receives exactly the expected argv. Use `unittest.mock.patch("subprocess.run")` to record argv, then separately run integration tests with a harmless target.

### 2. Shell and argument injection

**Attack.** Even with `shell=False`, an argv list can contain `--override`, `-exec`, `@input.txt`, `--git-dir=`, or values that a subcommand interprets as options. A string like `-aR`, `--exclude=*`, `@(cmd)`, or `--upload-pack=...` can trigger behavior. This maps to CWE-88 and, where a command string is reconstructed, CWE-78.

**Fix.** Pass values as separate argv items, not whitespace-joined strings. Where the underlying tool permits, prefix each value with `./` if it is a repository-relative filename; otherwise validate that it contains no path separator, NUL, control character, or leading `-`. Insert `--` before variable positional arguments only when the tool documents that behavior; do not assume it. Prefer tools and flags that accept values after `=`, then require the value to pass a regex such as `^[\w.+\-/=]{1,128}$` depending on the semantic type. Keep a short allowlist of executable names and absolute paths; resolve and compare them.

```python
import os
import re

_ALLOWED_VALUE = re.compile(r"\A[\w.+\-/=]{1,128}\Z")

def require_non_option(value: str, where: str) -> str:
    if not isinstance(value, str):
        raise PolicyViolation(f"{where}: must be string")
    if "\x00" in value or value != value.strip():
        raise PolicyViolation(f"{where}: invalid characters")
    if value.startswith("-"):
        raise PolicyViolation(f"{where}: must not begin with '-'")
    if not _ALLOWED_VALUE.match(value):
        raise PolicyViolation(f"{where}: not allowlisted")
    return value
```

**Test.** Parameterize tests with `--exec=cmd`, `-aR`, `-x;rm`, `--system`, `-z$(cmd)`, `@input`, `..`, `/etc/passwd`, a value containing newline, and a value beginning with NUL. Assert the command is rejected before subprocess creation. Add a spy child that prints its real `argv` and verify each external value appears as one distinct argument. Do not test only that `shell=True` raises; test that `shell=False` with malicious list values is also rejected.

### 3. Path traversal and symlink escape

**Attack.** A repository contains `../../.gitconfig`, a symlink to `/etc`, `repo/evil -> /`, or nested symlinks forming a loop. A rule reads `path: /proc/self/environ`. The program computes `root / user_path`, checks that the prefix matches, then later opens a different file after the symlink target changes. This maps to CWE-22 and CWE-59. Python’s `pathlib.Path.resolve()` resolves symlinks and eliminates `..` [3].

**Fix.** Normalize the repository root once, without following symlinks that escape it. Require the rule’s repository-relative path to contain no `..`, no absolute component, and no NUL. Resolve the final path with `strict=True`, verify it is a file or directory as appropriate, and verify it remains lexically and physically under the canonical root. Open the resulting file descriptor rather than reopening a path string when possible. For directory walks, detect symlinks whose targets are outside the root and stop. Do not use `shutil.rmtree` on a repository owned by another user or on paths whose parents are attacker-controlled; where removal is necessary, first verify the directory is inside an isolated workspace and that the platform uses the fd-based race-resistant implementation, and document the residual risk otherwise.

```python
from pathlib import Path

def require_safe_repo_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str):
        raise PolicyViolation("path must be string")
    if not relative or "\x00" in relative:
        raise PolicyViolation("invalid path")
    if relative.startswith("/") or relative.startswith("\\"):
        raise PolicyViolation("absolute path not allowed")
    parts = Path(relative).parts
    if ".." in parts or any(p in ("", ".") for p in parts):
        raise PolicyViolation("path traversal not allowed")
    base = root.resolve(strict=True)
    candidate = (base / relative).resolve(strict=True)
    if base != candidate and base not in candidate.parents:
        raise PolicyViolation("path escapes repository root")
    if candidate.is_symlink() and not candidate.is_relative_to(base):
        raise PolicyViolation("symlink target escapes repository root")
    return candidate
```

**Test.** Create fixtures containing `a/normal`, `../escape`, `/abs`, `a/link -> /etc`, `a/out -> ../..`, and a symlink loop. Assert only `a/normal` is accepted. Assert that changing the symlink after the prefix check and before open causes a fresh rejection because each use resolves again. Run the test as a non-root user and verify no protected files are read. This tests the application’s policy, not merely Python’s `resolve`.

### 4. TOCTOU and repeated-resolution races

**Attack.** The program validates `repo/file` and then opens `repo/file`; between checks the file becomes a symlink to `/etc/shadow`. Another process races a temporary directory or writes into a predictable evidence filename. This maps to CWE-362.

**Fix.** Resolve immediately before each security-sensitive use. Prefer `os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0)` so symlinks fail explicitly; then wrap the fd with `os.fdopen`. Avoid `os.O_NOFOLLOW` on Windows symlink semantics unless the implementation is explicitly tested there. Keep path validation and file-open logic in one function rather than exporting helpers that return unverified paths for later use. For writes, create output inside `tempfile.TemporaryDirectory`, use `os.open` with `O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC`, then atomically `os.replace` to the final path. Do not reuse names derived from user data.

**Test.** Use two threads or processes: one repeatedly modifies a symlink while the verifier repeatedly opens the same path. Assert no iteration reads or writes outside the root and that exceptions are deterministic. Add a filesystem fault-injection hook to make the resolution/open step alternate; assert the final published artifact is either complete or absent, never partially named.

### 5. Unsafe deserialization and dynamic code/config loading

**Attack.** Config uses YAML tags to construct arbitrary objects; a transcript or cache is unpickled; a plugin path is imported; a rule supplies `__subclasses__`, `__import__`, `os.system`, or `eval("1+1")`. This maps to CWE-502 and CWE-94.

**Fix.** Parse YAML only with `yaml.safe_load`, and then validate the resulting structure against a schema. Do not use `yaml.load(input)` without an explicit safe loader. Reject unknown keys. Never use `pickle`, `shelve`, `marshal`, `joblib` with untrusted input. Do not store trusted state in the repository. Do not import modules, load shared objects, register plugins, or execute Python from repository files. Regex patterns, JSON paths, JMESPath, Jinja, SQL, and JavaScript expressions are also executable languages; reject them unless there is a specific, minimal allowlist and a safe engine.

```python
import yaml

def load_rules(text: str) -> dict:
    if not isinstance(text, str):
        raise PolicyViolation("rule source must be text")
    if len(text.encode("utf-8")) > 1_048_576:
        raise PolicyViolation("rule file too large")
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise PolicyViolation("rule document must be a mapping")
    for key in data:
        if key not in {"version", "claims", "verifier", "params", "expected"}:
            raise PolicyViolation(f"unknown rule key: {key}")
    return data
```

**Test.** Add a YAML payload containing `!!python/object/apply:os.system ["touch /tmp/pwned"]` and assert `safe_load` either raises or produces a harmless mapping; importantly, assert `os.system` is never called. Add a payload containing `__reduce__`, a Python pickle header, and a rule that requests a plugin file. Add fuzzed binary documents and assert all produce typed errors. Add tests for unknown keys, extra nested objects, deep structures, and custom tags. Do not add a test that demonstrates successful gadget execution.

### 6. Resource exhaustion and availability attacks

**Attack.** A transcript or repo rule is gigabytes; a `gzip -9` archive expands explosively; a regex such as `(a+)+$` consumes CPU on non-matching input; a rule spawns unlimited child processes; a verifier produces unbounded stdout; a malicious symlink causes unbounded recursion. This maps to CWE-770, CWE-1333, and related resource-control weaknesses.

**Fix.** Apply layered limits before parsing: input byte cap, maximum line length, maximum nesting depth, maximum claim count, maximum field length, maximum output bytes, process wall-clock timeout, output read timeout, process group kill, maximum open file descriptors, and an aggregate task concurrency limit. ReDoS mitigation is not merely “limit CPU”: use a bounded, well-reviewed engine and avoid ambiguous overlapping quantifiers. Python 3.11+ `re` supports `re.timeout`; set it to a low per-pattern budget. For older versions or higher assurance, compile patterns from a trusted catalog, bound repetition, and run matching in a worker with a deadline.

```python
import re
import signal

_PATTERN_TIMEOUT = 0.25

def safe_match(pattern: str, value: str) -> bool:
    if not isinstance(pattern, str) or not isinstance(value, str):
        raise PolicyViolation("pattern and value must be strings")
    if len(pattern) > 256 or len(value) > 65_536:
        raise PolicyViolation("pattern or value exceeds limits")
    compiled = re.compile(pattern, flags=0)
    if hasattr(signal, "siginterrupt"):
        pass
    try:
        return compiled.match(value, timeout=_PATTERN_TIMEOUT) is not None
    except TimeoutError as exc:
        raise PolicyViolation("regex exceeded time budget") from exc
```

**Test.** Construct the canonical ReDoS input `("a" * 30) + "!"` for `(a+)+$`, plus zip bombs, deeply nested JSON/YAML, a million tiny claims, long lines, a process that forks children, a child that writes 10 GiB to stdout, and a symlink loop. Assert each test is terminated or rejected within the limit. Add a regression that measures CPU time and fails if it exceeds a tight bound. Test deadline propagation: a child that ignores SIGTERM should still be killed by a process-group SIGKILL after grace.

### 7. Subprocess environment, cwd, and file descriptor leakage

**Attack.** The child inherits `PATH`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `PYTHONPATH`, `GIT_DIR`, `GIT_CONFIG`, `HOME`, `http_proxy`, `AWS_*`/`GH_TOKEN`, SSH agent sockets, or open file descriptors. The `cwd` is outside the repo or is attacker-writable. The child connects to the network. This maps to CWE-426 and information disclosure.

**Fix.** Pass `env={}` unless a specific verifier requires a variable, in which case set only that variable to a constant allowlisted value. Always pass `cwd=` to a canonical repository directory that has been verified as the workspace. Pass `close_fds=True`. Explicitly close or replace stdin, stdout, and stderr. Remove `pass_fds` unless a specific fd contract is needed. Use `sys.platform` to select and harden the process-killing implementation; on POSIX, use a dedicated process group so descendants are killed, and explicitly reap children to avoid zombies.

```python
import os
import signal
import subprocess

def _limits_preexec() -> None:
    os.setpgrp()
    try:
        signal.signal(signal.SIGRTMIN + 0, signal.SIG_IGN)
    except (ValueError, AttributeError):
        pass

def start_isolated(args, work_dir, output_limit):
    return subprocess.Popen(
        args,
        cwd=work_dir,
        env={},
        shell=False,
        close_fds=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        start_new_session=True,
        preexec_fn=_limits_preexec,
    )
```

**Test.** Print the child’s environment and assert it contains only explicitly configured keys. Run `printenv`, `env`, and `git config --show-origin --list` under the sandbox; assert no secret-looking variables appear. Check that `GIT_*` is unset and the cwd is the repo root. Use a network egress test that attempts a TCP connection to a known internal service; if it succeeds, fail the build. Note that process-level network blocking is platform-specific: enforce it outside Python with Linux namespaces, containers, seccomp, or CI runners when the threat model requires it.

### 8. Temporary-file races and disclosure

**Attack.** A predictable temporary filename is created with a mode allowing group/other access, replaced by a symlink, or leaked into CI logs. This maps to several permission and race weaknesses.

**Fix.** Use `tempfile.TemporaryDirectory(delete=True)` as a context manager and place all intermediates inside it. Python documents that `mkstemp` creates the file securely when `O_EXCL` is properly implemented, and that `mkdtemp` creates a directory restricted to the user ID [4]. For a named file, use `mkstemp` and `os.fdopen`, set permissions before writing sensitive data, and avoid `mktemp`. Remove evidence files on failure and do not log paths under `/tmp`. The high-level interfaces provide automatic cleanup and are preferred [4].

```python
import tempfile
import os

def make_private_intermediate(suffix: str):
    directory = tempfile.mkdtemp(prefix="verifier-", suffix=".d")
    os.chmod(directory, 0o700)
    fd, path = tempfile.mkstemp(dir=directory, suffix=suffix)
    os.chmod(path, 0o600)
    return os.fdopen(fd, "wb"), path
```

**Test.** Inspect directory permissions after creation and assert mode `0o700`; inspect file mode and assert `0o600`. Run a concurrent attacker process that predicts and pre-creates the next temporary name; assert `mkstemp` raises rather than opening the attacker’s file. Test abrupt exit paths to confirm the context manager removes intermediates.

### 9. Secret and PII leakage into bundles, logs, and CI artifacts

**Attack.** A repo’s transcript contains an API key; a command prints the environment; an error serializes an exception containing a path, stack trace, or secret; Markdown includes raw evidence; SARIF properties are copied without review; logs are copied into a public Gist. OWASP’s logging guidance says passwords, connection strings, keys, payment data, and PII should not be recorded directly; they should be removed, masked, sanitized, hashed, or encrypted [10].

**Fix.** Build a strict evidence schema with explicit fields: `claim_id`, `verifier`, `result`, `message`, `truncated_evidence_reference`, `duration_ms`, and `error_type`. Do not include `stdout`, `stderr`, file contents, command argv, exception messages, repository paths, environment, model prompts, or transcript snippets by default. Redact with deterministic allowlists before serialization: high-entropy strings, known key patterns, email, token prefixes, and common cloud-secret formats. Truncate to a safe fixed length after redaction. Generate a SHA-256 digest of raw evidence and store it in an access-controlled location; publish only the digest and a bounded excerpt. Fail closed if the redactor cannot classify a value. In CI, mask the same patterns in logs, set log levels conservatively, and use workflow permissions that prevent public upload.

**Test.** Include `.env`, `.git/config`, a token such as `a GitHub-style personal access token`, an AWS-like value, a private key, an SSH URL, an email, and an exception whose message includes a secret. Parse the final JSON, SARIF, and Markdown with regex and AST where possible; assert no secret appears. Add negative tests that confirm legitimate short evidence and non-secret hex strings are not over-redacted into unusable output. Test redaction ordering: if the tool first formats an error and then redacts, the test must fail.

### 10. Exit-code and CI semantics

**Attack.** A verifier times out but the tool returns 0; an unsupported rule is skipped silently; an infrastructure error is reported as “claims verified”; a single low-severity notice fails the pipeline while a command-injection attempt is reported as neutral.

**Fix.** Define a stable contract. Exit `0` means all applicable rules evaluated and met policy; `1` means one or more findings or input policy violations; `2` means infrastructure failure such as config error, permission error, timeout, or redaction failure. A rule whose verifier is unknown is `error`, not `pass`. CI annotations should distinguish `error`, `warning`, and `note`, but the final conclusion must not be `pass` when `error` is present. Write results incrementally to a temporary file and replace the artifact atomically so a canceled job cannot publish a partial SARIF file. Include schema version, tool driver version, policy commit, start/end times, rule ids, and evidence digests. Do not allow “treat as non-blocking” to suppress security-critical error categories.

**Test.** Run verifiers that pass, fail, error, timeout, and are unknown. Assert exit codes, SARIF `result.level`, and conclusion match the matrix. Corrupt the output after writing and assert the old artifact is not overwritten with invalid JSON. Interrupt the process and assert no published artifact claims success.

## 3. Priority 2: configuration and claim parsing must be safer than the code they describe

**Declarative configuration is executable input as soon as the tool assigns meaning to a key.** Configuration must be versioned, short, and enumerable. Use a schema such as:

```yaml
version: 1
claims:
  - id: no_internal_token_in_readme
    verifier: file.literal_absent
    params:
      - README.md
    expected:
      absent_literal: GH_TOKEN
```

This example is intentionally limited. `version`, `claims`, `id`, `verifier`, `params`, and `expected.absent_literal` are the only permitted keys. There must be no `command`, `entrypoint`, `script`, `hook`, `python`, `shell`, `cwd`, `env`, `import`, `plugin`, `regex_flags`, or `extension` field. Parsing uses `yaml.safe_load` followed by an explicit schema validator. Unknown keys, additional properties, deeply nested objects, and YAML merge keys are rejected.

**Claim text is evidence, not authority.** The transcript may contain statements that look like instructions: “ignore previous rules,” “run this command,” or “the verifier should be `bash`.” The parser must not extract field names from such instructions. Use a fixed JSON Schema with `additionalProperties: false`. Constrain strings with length and character patterns; require `claim_id` and `verifier` from the catalog; and map `verifier` to a handler through a dictionary literal in code. Never call `globals()`, `locals()`, `getattr(obj, name_from_input)`, or `importlib` with an extracted value.

**Regex is a programming language and must be treated as one.** If the product genuinely needs user-influenced matching, maintain a small trusted library of patterns and select by id. Do not compile repository strings at runtime. Set Python’s `re.timeout` and an overall matcher timeout; bound input size and repetition; avoid overlapping groups, exponential backtracking, backreferences where avoidable, and recursive patterns. CWE-1333 states that backtracking becomes a weakness when backtracking attempts are exponential in input length and the attacker can supply a long, non-matching input [9]. Test each pattern with generated adversarial strings.

## 4. Priority 2: safe subprocess execution is a complete contract, not a flag

**`shell=False` prevents shell interpretation but does not validate meaning.** The application must enforce executable allowlist, fixed template, argument allowlist, value allowlist, cwd, environment, fds, time, memory/CPU, output size, and post-condition checks. A useful invariant is: if a byte from the repository can change an executable name, option, flag, regex, path root, or log emission, that is a design bug.

Use `subprocess.run` for ordinary execution and reserve `Popen` for streaming output under a strict byte cap. The Python documentation explicitly places responsibility for quoting metacharacters on the application when `shell=True`, and it documents `timeout` plus `TimeoutExpired` [5]. For this tool, `shell=True` should not exist in the production call graph. A security review must fail the change if a new callsite introduces it.

**Cap all pipes before the child can wedge the parent.** If stdout is `PIPE`, read with `communicate(timeout=...)` and bound the accumulator. A safer pattern spools to a private temporary file, stops after the limit, and never allocates attacker-controlled size in memory. On timeout, terminate the process group and then `kill()`; wait with a bounded reaper. Always record `returncode`, bytes written, and wall time, but publish only redacted fields.

**Executable identity must be explicit and stable.** Store allowed executables as absolute paths, e.g. `/usr/bin/git`. Resolve once at policy load and compare real paths. Reject `/proc/self/exe`, `/dev/fd/`, repository paths, versioned names such as `python3.11`, and names discovered through `PATH`. Do not use `shutil.which` on untrusted names. This reduces CWE-426 search-path confusion.

## 5. Priority 2: repository isolation requires physical containment, not trust

**The repository root is a sandbox input, not a trusted workspace.** Clone into a dedicated directory owned by the executing user; verify the directory is inside an isolated workspace; and do not clone over an existing directory supplied by an attacker. Use a fixed destination name, not one derived from the remote URL. Treat `.git/config`, `.git/hooks`, and any executable hook as out of scope by default. Disable hook execution, avoid running repository git configuration, and never execute files found by traversing the tree.

**Walk the repository with an adversarial walker.** Use `os.scandir` or `pathlib`, but track symlinks, directories, and visited device/inode pairs to stop loops. Reject any symlink whose resolved target leaves the repository, points to a device file, or has unexpected permissions. Do not follow symlinks when copying evidence. `shutil` warns that archive extraction from untrusted sources can create files outside the destination through absolute names or `..` components [6]; use the same discipline for any future unpacking feature, and disable it by default.

**Physical containment must be external whenever execution is permitted.** A pure-Python sandbox cannot reliably contain a determined malicious child. Run the verifier in a Linux container or VM with read-only root, no capabilities, no new privileges, private PID/IPC/network/mount namespaces, dropped caps, seccomp, a low CPU/memory quota, and no mounted secrets. CI runners should be ephemeral. Network egress should be denied by default; verifier catalogs requiring remote access are rejected unless an explicit, separately approved policy enables them.

## 6. Priority 3: evidence artifacts must be safe to publish before they are convenient

**A publishable bundle is a public interface.** JSON, SARIF, and Markdown should be generated from a single canonical evidence model. SARIF 2.1.0 should be emitted with `version`, `runs[].tool.driver`, `rules`, and `results` conforming to the published schema. Do not invent custom properties that contain raw output, and do not declare schema conformance when the output is not validated. Validate the final document with a JSON Schema check and a SARIF validator in CI.

**Markdown rendering is a template, not formatted user text.** Use a safe template engine with autoescaping or explicit literal output. Never `format()` transcript text into a shell command, HTML page, log line, or Markdown link. Restrict Markdown to a small feature subset. Treat claim text as literal text, not CommonMark. Keep excerpts short and redacted; reference full evidence by content digest stored in a private location.

**The publish stage must be atomic and permissioned.** Write to `TemporaryDirectory`, set mode `0o700` for the directory and `0o600` for files, validate the artifact, then atomically replace the public destination. The final location should not be world-writable. The CLI should support `--dry-run --write-artifact=/private/path` and fail if the destination is outside an approved output directory. CI upload steps should require the artifact to validate and should use a token scoped to the minimum write permission.

## 7. Minimum secure architecture

**The architecture has one execution chokepoint and one publication chokepoint.** The following sketch separates concerns and prevents repository files from directly influencing process construction or artifact rendering.

```text
+-----------------------------+        +----------------------------+
| Untrusted git repo          |        | Untrusted transcript      |
| YAML rule files             |        | Natural-language claims    |
+-------------+---------------+        +-------------+--------------+
              |                                        |
              | bounded read / schema validation       | bounded read
              v                                        v
   +--------------------+                    +--------------------+
   | Repository path    |                    | Claim parser       |
   | canonicalizer      |                    | fixed JSON schema  |
   | symlink/TOCTOU     |                    | claim catalog      |
   +---------+----------+                    +---------+----------+
             |                                       |
             | repo path + validated claim            |
             v                                       v
   +----------------------------------------------------+
   | Policy engine                                      |
   | verifier allowlist, params allowlist,              |
   | environment allowlist, resource budgets             |
   +---------+------------------------------------------+
             | approved command template only
             v
   +----------------------------------------------------+
   | Isolated runner                                    |
   | shell=False, list argv, empty env, fixed cwd,      |
   | close_fds, deadline, output cap, process group     |
   +---------+------------------------------------------+
             | redacted evidence only
             v
   +----------------------------------------------------+
   | Bundle builder                                     |
   | canonical JSON model, redaction, truncation,        |
   | SARIF/Markdown rendering, validation, digest       |
   +---------+------------------------------------------+
             | atomic replace to approved path
             v
   +----------------------------------------------------+
   | Output artifact (JSON / SARIF / Markdown)          |
   +----------------------------------------------------+
```

The repository and transcript loaders never import a verifier. The policy engine never executes anything. The runner never reads claim text except as a bounded parameter already validated by the policy engine. The bundle builder never reopens a repository path and never receives stdout/stderr unless it has already been redacted. This separation makes code review tractable: an auditor can inspect one file for all subprocess calls.

A minimal implementation should contain approximately these modules:

| Module | Responsibility | Must not contain |
|---|---|---|
| `ingest/repo.py` | clone, canonicalize, walk, reject symlink escapes | subprocess calls to repo hooks |
| `ingest/transcript.py` | size limits, decoding, deterministic extraction | model prompt construction |
| `config/schema.py` | YAML safe load, JSON Schema, unknown-key rejection | dynamic dispatch |
| `policy/catalog.py` | verifier, param, env, and path allowlists | repository-derived identifiers |
| `runner/process.py` | isolated subprocess execution and resource control | shell, dynamic executables, net access |
| `evidence/redact.py` | deterministic secret/PII redaction and truncation | filesystem reads |
| `output/{json,sarif,markdown}.py` | validated artifact rendering | raw command output or exception strings |
| `cli/main.py` | argument parsing, orchestration, exit-code mapping | business logic |

## 8. Dependency supply-chain and build hygiene

**Dependencies extend the trusted computing base.** Maintain a lockfile with exact versions and hashes. Install with `python -m pip install --require-hashes -r requirements.lock`. Use a separate constraints file for development tools. Keep build environments isolated and prevent repository code from influencing installation—do not run `pip install -e .`, `python setup.py`, or pre-commit hooks from the untrusted repository.

Use `pip-audit` and dependency-review tooling in CI. Run `bandit -r src -ll` and maintain a baseline for newly introduced high-confidence issues. Add Semgrep rules that forbid `shell=True`, `yaml.load(`, `pickle.load(`, `eval(`, `exec(`, `compile(`, `importlib.import_module(`, `os.system`, `subprocess.run(input_from_config)`, and logging of full subprocess output. Treat a new subprocess import as a required security-review event. Generate an SBOM; verify hashes; and reject transitive dependencies that are not allowlisted.

**Tests and CI can be attack targets.** Do not pass repository secrets to the test process; redact them in runner environment configuration. Pin runner images, use ephemeral credentials, and rotate tokens. The CLI should support `--policy-manifest` containing executable hashes and reject a policy that references an unpinned executable. Run a destructive repository test suite in an isolated VM rather than on a developer laptop.

A recommended pre-merge gate is:

1. `ruff check`, `mypy --strict` on changed modules.
2. `bandit -r src -ll` and Semgrep with custom rules.
3. `pip-audit` against locked dependencies.
4. `pytest` with adversarial fixtures and coverage of security-critical branches.
5. SBOM generation and hash verification.
6. SARIF schema validation.
7. A red-team job that attempts command injection, path escape, symlink escape, ReDoS, decompression, config-code execution, and log leakage.
8. Separate approval for any change to `policy/catalog.py`, `runner/process.py`, or allowed dependencies.

## 9. Concrete tests that prove the controls work

**Property tests should generate malformed inputs; adversarial tests should demonstrate the failure mode.** A test suite that asserts “the happy path works” is insufficient. The tests below are minimum regression requirements.

| Control | Test | Expected assertion |
|---|---|---|
| Command allowlist | Repo rule requests `rm`, `bash`, or unknown verifier | `PolicyViolation`, no subprocess |
| Argument injection | Parameter `-aR`, `--exec`, `@x`, `..` | rejected before `Popen` |
| Shell safety | All subprocess callsites inspected or mocked | zero `shell=True`; zero string interpolation |
| Path traversal | `../.gitconfig`, `/etc/hostname`, `a/link->/` | rejected with CWE-22/CWE-59 explanation |
| TOCTOU | Symlink swapped between resolve and open | fresh validation fails; no escape |
| YAML | Malicious custom tag and Python object | no object construction or side effect |
| Deserialization | Pickle, marshal, joblib payloads | unsupported media/parse error |
| Plugin import | Config requests module/class path | rejected; no import attempted |
| Regex | Catastrophic patterns plus long mismatch | terminates within time budget |
| Resource | Huge input, huge output, fork loop | bounded memory, killed within timeout |
| Tempfile | Concurrent attacker predicts name | atomic creation succeeds or raises |
| Permissions | Inspect temp dir/file modes | `0o700`/`0o600`, no world-readable artifact |
| Environment | Child dumps env, `git config` | empty or fixed allowlisted variables |
| Network | Verifier attempts socket connection | blocked or test fails closed |
| Redaction | Artifact contains key/token/PII patterns | no secret in JSON, SARIF, Markdown, or log |
| Exit semantics | Timeout, config error, unknown rule, pass | correct non-zero exit; no false pass |
| Atomicity | Crash mid-write | no partial public artifact |

Use `pytest` with `tmp_path`, `monkeypatch`, and capability-scoped tests. Mark tests requiring filesystem symlinks, root privileges, or Linux namespaces explicitly and skip them on unsupported platforms. For subprocess inspection, use a fake executable on a private `PATH` and assert its exact argv and environment. Integration tests should run a real verifier against synthetic inputs, not attacker-controlled repositories.

**Failure-injection is as important as input fuzzing.** Inject `OSError` on `resolve`, `open`, `os.replace`, and `wait`. Inject a delay that causes `communicate` to time out. Inject an output stream that never ends. Inject a redaction failure. In every case, assert the tool fails closed, cleans private intermediates, and does not publish a passing result.

## 10. Anti-patterns that make the tool dangerous

1. **`os.system`, `subprocess.call(f"git ... {x}")`, or `shell=True`.** The application constructs attacker-controlled commands. The fix is fixed templates and list argv, not escaping.
2. **Accepting `command:` from the repo.** Any repository-provided command string is remote code execution. Use a versioned catalog instead.
3. **Using `shlex.quote` as a substitute for command design.** Quoting does not stop option injection, malicious executable names, or unsafe tool semantics.
4. **Validating a path once and reopening its string.** This creates a TOCTOU window. Resolve and open in one secure operation or revalidate immediately before each use.
5. **Using `pathlib.Path("repo") / user_string` without `resolve`.** `is_relative_to` may be string-based and does not resolve symlinks; `..` and symlinks remain exploitable.
6. **Following repository symlinks outside the workspace.** Symlink escapes can read secrets, overwrite files, or point to device nodes.
7. **`yaml.load(text)` without a safe loader or schema.** YAML custom tags can construct arbitrary objects. Use `safe_load` plus a validator.
8. **`pickle.loads` for transcript cache, rules, or checkpoints.** This is unsafe deserialization and can enable gadget chains.
9. **`eval`, `exec`, `compile`, or dynamic plugin imports.** These turn repository strings into runtime behavior.
10. **Regex or JSONPath supplied by repo config.** These are executable mini-languages. Keep patterns in a trusted allowlist.
11. **No timeouts, output caps, or process limits.** This enables fork bombs, ReDoS, memory exhaustion, and slowloris-style stalls.
12. **`mktemp` plus open, or a predictable output filename.** This invites symlink and pre-creation attacks; use `TemporaryDirectory`, `mkstemp`, and atomic replace.
13. **Inheriting environment or cwd.** Secrets, `LD_PRELOAD`, `GIT_*`, `PYTHONPATH`, and agent sockets can change behavior.
14. **World-readable evidence or `/tmp` artifacts.** Sensitive repo contents and redaction failures can be exposed to local users.
15. **Printing raw stdout, stderr, stack traces, or prompts.** This creates log injection and secret-leakage paths.
16. **Skipping unknown rules or treating config errors as warnings.** This makes policy bypass easy and breaks assurance.
17. **Returning exit 0 after timeout, missing executable, or schema failure.** This corrupts CI conclusions.
18. **Trusting the transcript’s instructions.** Natural-language “commands,” “rules,” or “tool suggestions” are attacker-influenced content.
19. **Running git hooks or repository executables.** `.git/hooks`, `package.json` scripts, Makefiles, and similar are not verification policy.
20. **Assuming containerization makes unsafe APIs safe.** Containers add containment but do not repair shell injection, path traversal, or secret disclosure.
21. **Running with a credentialed user.** The tool should have no SSH key, cloud token, npm token, or CI write token unless a specific approved step needs it.
22. **Publishing first and redacting later.** Once in CI logs or artifacts, a secret may be replicated. Redact before serialization.
23. **Using file type or extension to decide execution.** Magic bytes, permissions, shebangs, and extensions are all untrusted signals.
24. **Allowing user input to add a verifier at runtime without operator approval.** This collapses the trust boundary between the operator and the repository.
25. **Using `shutil.rmtree` or `shutil.unpack_archive` on attacker-controlled trees without inspection.** These can follow symlinks or write outside the target.

## 11. Secure defaults for the first release

**The first release should do less and be obviously safe.** Version 1 must not execute arbitrary shell commands, import repository code, support custom plugins, accept regex or JSONPath from config, extract claims using a repository-supplied model prompt, or publish raw evidence. It should support a fixed set of in-process checks—such as literal presence/absence, JSON schema validity, line length, and file size—and one or two allowlisted read-only git commands.

A repository rule must declare `version: 1` and be validated by a pinned schema. The tool must refuse unsupported future schema versions. Executables must be absolute, hashed, and on the allowlist. Network access must be off. CI upload must be opt-in and must fail without a validated artifact. These restrictions can be relaxed only through a reviewed policy change; they must not be toggled by repository configuration.

**Secure defaults belong in code, CLI flags, and CI policy.** Set `PYTHONWARNINGS=error`, `PYTHONDONTWRITEBYTECODE=1`, and a non-interactive locale. Do not expose repository environment variables to the runner. Fail on first policy violation by default; require an explicit, separately approved batch mode for non-security findings. Require `--policy-file` to be outside the repository. Log only event type, rule id, duration, and a redacted outcome. Publish only artifacts generated from the canonical, validated evidence model.

## 12. Acceptance criteria for “safe by default”

**The tool is ready for adversarial repositories only when it demonstrably contains execution and disclosure.** The following acceptance criteria should be mandatory:

- Zero production calls to `shell=True`, `eval`, `exec`, `compile`, `pickle`, `importlib.import_module`, `os.system`, or unsafe archive extraction.
- Every subprocess invocation passes through one reviewed function with a fixed command template.
- Every repository-derived value used as an argument, path, or parameter passes an explicit allowlist and type check.
- Every path use resolves symlinks and checks physical containment immediately before access.
- Every command has an executable allowlist, cwd, empty or fixed environment, `close_fds=True`, wall-clock timeout, output cap, and descendant-kill behavior.
- Every external process runs in an isolated environment with no network and no mounted secrets.
- Every artifact is redacted, schema-valid, and written atomically with private permissions.
- Every error path fails closed and does not publish a passing result.
- Tests reproduce command injection, option injection, traversal, symlink escape, TOCTOU, deserialization, ReDoS, resource exhaustion, tempfile race, and secret leakage.
- A change to any trust-boundary module requires two reviewers, one of whom is a security reviewer, plus red-team test evidence.

This baseline does not eliminate every theoretical risk. It establishes enforceable boundaries: data cannot become code, claims cannot choose tools, paths cannot leave the repository, processes cannot inherit authority, and artifacts cannot disclose secrets. The residual risks are process isolation escape, platform-specific race conditions, undisclosed vulnerabilities in dependencies, and deliberate operator override. Those risks should be managed through container or VM isolation, vulnerability monitoring, signed policy releases, and a published threat model—not by adding more flexible configuration.

## References

[1] https://cwe.mitre.org/data/definitions/78.html
> "The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command before it is sent to a downstream component."

[2] https://cwe.mitre.org/data/definitions/88.html
> "An adversary could supply a filename like '-aR', producing the 'ls -l -aR' command (CWE-88), thereby getting a full recursive listing of the entire directory and all of its sub-directories."

[3] https://docs.python.org/3/library/pathlib.html
> "Path.resolve(strict=False)¶ Make the path absolute, resolving any symlinks. … “..” components are also eliminated."

[4] https://docs.python.org/3/library/tempfile.html
> "Creates a temporary file in the most secure manner possible. There are no race conditions in the file’s creation, assuming that the platform properly implements the os.O_EXCL flag for os.open()."

[5] https://docs.python.org/3/library/subprocess.html
> "If shell is True, it is the application’s responsibility to ensure that all whitespace and metacharacters are quoted appropriately to avoid shell injection vulnerabilities."

[6] https://docs.python.org/3/library/shutil.html
> "Never extract archives from untrusted sources without prior inspection. It is possible that files are created outside of the path specified in the extract_dir argument."

[7] https://cwe.mitre.org/data/definitions/22.html
> "By using special elements such as '..' and '/' separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system."

[8] https://cwe.mitre.org/data/definitions/59.html
> "Some potential factors are race conditions, permissions, and predictability."

[9] https://cwe.mitre.org/data/definitions/1333.html
> "Backtracking becomes a weakness if all of these conditions are met: The number of possible backtracking attempts is exponential relative to the length of the input."

[10] https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
> "The following should usually not be recorded directly in the logs, but instead should be removed, masked, sanitized, hashed, or encrypted."

[11] https://cwe.mitre.org/data/definitions/502.html
> "Making an assumption that the code in the deserialized object is valid is dangerous and can enable exploitation."
