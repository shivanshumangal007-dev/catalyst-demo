# VulnReach

Reachability-based vulnerability triage for Python projects. Given a Python
project and its vulnerability alerts (advisories for pinned dependencies),
VulnReach decides for each alert whether the vulnerable code can actually be
reached from the project's code.

## Problem

Not every vulnerability alert affects your project. An advisory may flag a
package you depend on, but if the vulnerable function is never called from your
code, the alert is noise. VulnReach answers the question: *can the vulnerable
code be reached from my project?* It outputs one verdict per alert:

| Verdict   | Meaning                                                              | OpenVEX status   |
|-----------|----------------------------------------------------------------------|------------------|
| reachable | A static call path exists from project code to a vulnerable function | `affected`       |
| not_reachable | No path exists, and no dynamic feature could hide one             | `not_affected`   |
| uncertain | Dynamic Python features could hide a path                            | `under_investigation` |

Per the project's hard rule, VulnReach never emits `not_reachable` when
reachability cannot be ruled out — when in doubt, it reports `uncertain`.  A
false "safe" is the worst possible failure.

Every verdict carries evidence (the call path with `file:line` per hop), a
confidence level (`high`/`medium`/`low`) with a reason, and a human-readable
explanation.

## Architecture (text diagram)

```
 alerts.json                                  OpenVEX document
   |                                              ^
   v                                              |
+---------+     +----------------+     +----------------+     +----------+
|  CLI    | --> | Fix-commit     | --> | Call graph     | --> | Analyzer |
|  scan   |     | resolution     |     | builder (ast)  |     | (reach)  |
+---------+     +----------------+     +----------------+     +----------+
   |              (OSV client)    |  project + dep     |  entry pts --> vuln fns
   |                              |  over-approx edges   |  dynamic sites
   v                              +----------------+     |
+---------+                       |                |     v
| Cache   | <---------------------+ report.json    | +-----------+
| (sqlite)|     advisory -> vuln fn  | report.vex.json| | PR Chat   |
+---------+     call graph JSON   |    (OpenVEX)   | | Agent     |
                                  +----------------+     +-----------+
                                                                   |
                                                                   v
                                                          FastAPI app (app.py)
                                                          /chat, /verdicts, UI
```

## Pipeline

1. **Ingest alert** — package, version, advisory ID (OSV / PyPA / GHSA / CVE).
2. **Resolve the fix commit** — direct link, PR reference, tag diff, or not
   found; resolution method recorded with a confidence score.
3. **Diff → vulnerable functions** — parse the fix diff, map changed lines to
   enclosing functions/methods via `ast` on the pre-fix file.
4. **Call graph** — own `ast`-based walker over the project + installed
   dependency (`networkx` DiGraph), over-approximating when unsure.
5. **Reachability** — shortest path from entry points to any vulnerable
   function; entry points include module-level code, `__main__`,
   framework-decorated functions, and console_scripts.
6. **Dynamic features** — `getattr`, `importlib.import_module`/`__import__`
   with non-literal names, `eval`/`exec`, plugin loading (entry points /
   `pkgutil`), `**kwargs` dispatch, dict-of-callables, unsafe `pickle`/`yaml`
   — downgrade to `uncertain` when they could hide a path.
7. **Emit** — `report.json` and an OpenVEX v0.2.0 document (`report.vex.json`).
8. **PR chat agent + FastAPI UI** — debate a verdict on a PR, quote `file:line`
   evidence, record user assumptions.

## Installation

```bash
pip install -e .
```

Requires Python 3.11+.

## CLI

```bash
vulnreach scan <project_path> --alerts alerts.json --out-dir out/
```

Options:
- `--out-dir` — directory for `report.json` and `report.vex.json` (default: `out`)
- `--only-uncertain` — list only verdicts needing human review
- `--no-cache` — disable the sqlite cache (always re-resolve)
- `--isolated` — run the analysis inside an isolated Docker container

Exit code `1` if any verdict is `reachable` (suitable for CI).

`alerts.json` example:

```json
[
  { "package": "requests", "version": "2.25.0", "advisory_id": "GHSA-cc3m-4wpp-2x39", "aliases": ["CVE-2020-26137"] }
]
```

## PR chat agent & FastAPI UI

The agent (`vulnreach/agent/pr_chat.py`) debates a verdict using only evidence
from the report. It quotes `file:line` hops from the call path, never claims
certainty it does not have, and can re-run the analyzer when a user challenges
a `not_reachable` verdict or supplies new information (recorded as a
user-asserted assumption).

### Rule-based fallback (no LLM)

A built-in `RuleBasedLLMClient` works without any model endpoint, for demos
and offline use:

```python
from vulnreach.agent.pr_chat import PRChatAgent, RuleBasedLLMClient, build_pr_comment

agent = PRChatAgent(verdict, analyzer, project_path, alert,
                    vuln_funcs, fix_commit, call_graph)
print(agent.respond("Is lib.vulnerable_function reachable?"))
print(build_pr_comment(agent.verdict))
```

### Pluggable LLM

Implement `LLMClient.chat(messages)` to wire up your own model endpoint.

### FastAPI app

```bash
pip install -e ".[app]"
uvicorn app:app --reload
```

* `GET /verdicts` — list stored verdicts
* `POST /chat` — `{verdict_id, message}` → agent reply
* `GET /` — minimal single-page HTML chat UI

## Demo

A scripted PR scenario with three verdicts (reachable, not_reachable, uncertain)
and a conversation showing the agent changing its answer after the user supplies
new information:

```bash
PYTHONPATH=. python demo/run_conversation.py
```

## Caching

Analysis results are cached in a local SQLite file (`~/.cache/vulnreach/store.sqlite`)
keyed by `package@version`:

1. advisory → vulnerable functions (with confidence + resolution method)
2. the package's internal call graph, serialized as JSON

Cache entries use hash-based invalidation that incorporates `package@version`
plus the analyzer version, so a new analyzer version automatically invalidates
stale entries. Popular packages are therefore analyzed once and reused across
projects. Cache hits are logged. Use `--no-cache` to bypass.

## How isolation works (`--isolated`)

When `--isolated` is passed, `vulnreach scan` runs the entire analysis inside a
Docker container (`vulnreach/sandbox/docker_runner.py`):

1. **Image build (network on)** — an image is built from `Dockerfile`, which
   installs VulnReach and its dependencies. Network is available only during
   this build step.
2. **Analysis run (network off)** — the container runs `vulnreach scan` with
   `--network none`, so no network is available during analysis.
3. **Read-only project mount** — the target project is mounted read-only
   (`:ro`); only the output directory is writable.
4. **Non-root user** — the container runs as `1000:1000`.
5. **Limits** — CPU (`--cpus`) and memory (`--memory`) limits plus a timeout
   are enforced.
6. **Static analysis only** — the target project's code is **never imported or
   executed**. VulnReach parses it with `ast` to build a call graph and assess
   reachability. The container executes only VulnReach itself, never the
   project under analysis. VulnReach does not need the project's dependencies
   installed because it never imports them.

```bash
vulnreach scan ./myproject --alerts alerts.json --out-dir out/ --isolated
```

Docker must be installed on the host.

## Outputs

- `out/report.json` — all verdicts with evidence, fix commits, and alerts.
- `out/report.vex.json` — OpenVEX v0.2.0 document mapping each verdict to
  `affected` / `not_affected` / `under_investigation`.

## Tests

```bash
pytest
```

## Design answers

### (a) Fix commit → vulnerable functions and confidence

The fix commit is resolved from the OSV record in priority order:
`direct_link` (0.95) → `pr_reference` via GitHub API (0.70) → `tag_diff`
comparing last-vulnerable/first-fixed release tags (0.50) → `not_found`.
The diff is parsed with `unidiff`; changed lines are mapped to enclosing
functions/methods via `ast` on the pre-fix file. Qualified names include the
module path and class (e.g. `yaml.constructor.FullConstructor.construct_python_object`).
Confidence starts at the commit resolution confidence, loses 0.1 for a private
function changed only by formatting-looking lines, and gains 0.05 if the
function name appears in the advisory text. If no fix commit is found,
`functions_unknown=True` and the analyzer must emit `uncertain`, never
`not_reachable`.

### (b) Handling dynamic Python honestly

Dynamic features are detected per-file (getattr/setattr with non-literal
names, importlib/`__import__` non-literal, eval/exec, entry_points /
pkg_resources / pkgutil plugin loading, `globals()[name]()`, `**kwargs`
forwarding, dict-of-callables dispatch, unsafe pickle/yaml). They are recorded
as `DynamicSite` objects with file:line. The analyzer downgrades to
`uncertain` whenever any dynamic site exists in reachable code — it never
emits `not_reachable` when reachability cannot be ruled out. The PR chat agent
likewise never claims certainty: it says "uncertain" when dynamic features
block proof, and records user assumptions (e.g. "getattr only ever receives
'safe_load'") as caveats on the verdict.

### (c) Caching strategy

Two caches keyed by `package@version`, both with hash-based invalidation that
incorporates the analyzer version:

* **advisory_functions**: fix commit + vulnerable functions per advisory
* **callgraph**: the dependency's internal call graph as JSON

On a hit, the cached result is reused (popular packages analyzed once,
reused across projects). On a miss, the full pipeline runs and the result is
stored. Cache hits are logged. `--no-cache` disables the store entirely.

## Known limitations

* **Static only**: VulnReach does not execute code. Runtime code generation,
  heavily dynamic dispatch, or native extensions may hide paths that static
  analysis cannot see (correctly reported as `uncertain`).
* **Dependency resolution**: installed dependency sources are located via
  `importlib.metadata`; editable installs or namespace packages may not be
  found.
* **GitHub API**: PR/issue resolution requires network and may need
  `GITHUB_TOKEN` for higher rate limits.
* **Over-approximation**: unresolved calls add edges to all functions with a
  matching name, which can produce false positives (reachable when it's not).
  These edges are flagged and downgrade confidence to `medium`.
* **Multi-package scans**: the call graph includes ALL alert dependency packages,
  so every alert's vulnerable functions are resolved against the same graph
  (no package is silently omitted).

## Project layout

```
vulnreach/
  cli.py              # CLI + full pipeline
  models.py           # Pydantic data models
  advisories/         # OSV client + fix-commit resolution
  callgraph/          # call graph builder + dynamic feature detector
  diffing/            # diff -> vulnerable functions
  reachability/       # reachability analyzer
  cache/              # SQLite cache store
  sandbox/            # isolated Docker runner
  vex/                # OpenVEX document generation
  agent/              # PR conversation agent
tests/
  fixtures/           # synthetic apps (reachable / indirect / not_reachable / dynamic)
demo/
  fixtures/           # demo apps (reachable / not_reachable / dynamic)
  pr_scenario.py      # three-verdict demo scenario
  run_conversation.py # scripted PR chat conversation
app.py                # FastAPI app (/chat, /verdicts, UI)
Dockerfile
pyproject.toml
README.md
```
