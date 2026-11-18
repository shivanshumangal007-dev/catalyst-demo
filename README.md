# VulnReach

Reachability-based vulnerability triage for Python projects. Given a Python
project and its vulnerability alerts (advisories for pinned dependencies),
VulnReach decides for each alert whether the vulnerable code can actually be
reached from the project's code.

## Verdicts

| Verdict   | Meaning                                                              | OpenVEX status   |
|-----------|----------------------------------------------------------------------|------------------|
| reachable | A static call path exists from project code to a vulnerable function | `affected`       |
| not_reachable | No path exists, and no dynamic feature could hide one             | `not_affected`   |
| uncertain | Dynamic Python features could hide a path                            | `under_investigation` |

Per the project's hard rule, VulnReach never emits `not_reachable` when
reachability cannot be ruled out — when in doubt, it reports `uncertain`.

Every verdict carries evidence (the call path with `file:line` per hop), a
confidence level (`high`/`medium`/`low`) with a reason, and a human-readable
explanation.

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
   installs the project's pinned dependencies from its requirements. Network is
   available only during this build step.
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
   project under analysis.

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
tests/
  fixtures/           # synthetic apps (reachable / indirect / not_reachable / dynamic)
Dockerfile
pyproject.toml
README.md
```
