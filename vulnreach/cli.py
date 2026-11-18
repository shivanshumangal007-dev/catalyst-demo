"""Command-line interface for VulnReach.

``vulnreach scan <project_path> --alerts alerts.json --out-dir out/`` runs the
full pipeline:

1. Load alerts
2. Resolve fix commits (OSV) — results are cached per ``package@version`` so
   popular packages are analyzed once and reused across projects
3. Convert fix commits to vulnerable functions (diff -> functions) — cached too
4. Build a call graph of the project (+ dependency) — the dependency subgraph
   is cached per ``package@version``
5. Analyze reachability for each alert
6. Emit report.json (all verdicts) and report.vex.json (OpenVEX document)
7. Print a readable terminal table

Exit code 1 if any verdict is ``reachable`` (for CI use).

With ``--isolated``, steps 1-7 run inside a Docker container: the project is
mounted read-only, dependencies are installed at build time, and analysis runs
with ``--network none`` as a non-root user. Analysis is static only (``ast``);
the target project's code is never imported or executed.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import logging
import sys
from pathlib import Path
from typing import Any

from vulnreach.advisories.fix_commit import FixCommit, FixCommitResolver
from vulnreach.advisories.osv_client import OSVClient
from vulnreach.callgraph.builder import CallGraphBuilder, CallGraphResult, CallNode
from vulnreach.callgraph.dynamic_detector import DynamicDetector
from vulnreach.cache.store import CacheStore
from vulnreach.diffing.diff_to_functions import DiffToFunctions
from vulnreach.models import Alert, PathHop, Verdict, VulnerableFunction
from vulnreach.reachability.analyzer import ReachabilityAnalyzer
from vulnreach.vex.openvex import build_document, write_vex

logger = logging.getLogger("vulnreach")


def load_alerts(path: Path) -> list[dict[str, Any]]:
    """Load alerts from a JSON file (a list, or a single object wrapped in a list)."""
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    raise ValueError(f"alerts file {path} must contain a JSON object or list of objects")


def _project_purl(project_path: Path) -> str:
    """Best-effort project purl from pyproject.toml / setup.cfg; falls back to dir name."""
    pyproject = project_path / "pyproject.toml"
    if pyproject.exists():
        try:
            import tomllib

            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            name = data.get("project", {}).get("name")
            version = data.get("project", {}).get("version")
            if name:
                return f"pkg:pypi/{name}@{version or '0.0.0'}"
        except Exception:
            pass
    setup_cfg = project_path / "setup.cfg"
    if setup_cfg.exists():
        try:
            import configparser

            cp = configparser.ConfigParser()
            cp.read(setup_cfg, encoding="utf-8")
            if cp.has_section("metadata"):
                name = cp.get("metadata", "name", fallback=None)
                version = cp.get("metadata", "version", fallback=None)
                if name:
                    return f"pkg:pypi/{name}@{version or '0.0.0'}"
        except Exception:
            pass
    return f"pkg:pypi/{project_path.name}@0.0.0"


def _vuln_function_from_dict(d: dict[str, Any]) -> VulnerableFunction:
    return VulnerableFunction(
        module=d["module"],
        qualified_name=d["qualified_name"],
        file_path=d["file_path"],
        confidence=float(d.get("confidence", 0.5)),
    )


def _fix_commit_from_dict(d: dict[str, Any]) -> FixCommit:
    return FixCommit(
        repo_url=d.get("repo_url"),
        sha=d.get("sha"),
        resolution_method=d.get("resolution_method", "not_found"),  # type: ignore[arg-type]
        confidence=float(d.get("confidence", 0.0)),
    )


def _run_pipeline(
    project_path: Path,
    alerts: list[dict[str, Any]],
    cache: CacheStore,
) -> tuple[list[Verdict], list[FixCommit], CallGraphResult]:
    """Run the full analysis pipeline with caching.

    For each alert, the advisory -> vulnerable functions resolution is looked up
    in the cache first (keyed by ``package@version``).  On a miss it is resolved
    via OSV + fix commit + diff parsing and stored.  The dependency call graph
    subgraph is cached and reused when available.
    """
    client = OSVClient()
    resolver = FixCommitResolver()
    diff_to_funcs = DiffToFunctions()

    # Identify the target dependency from the first alert (the vulnerable package).
    first_package = alerts[0].get("package", "") if alerts else ""
    first_version = alerts[0].get("version", "") if alerts else ""

    # ---- Call graph: use cached dependency subgraph when available.
    builder = CallGraphBuilder(project_path)
    dependency_name = first_package or None
    dependency_version = first_version or None
    call_graph: CallGraphResult | None = None

    if dependency_name and dependency_version:
        cached_cg = cache.get(dependency_name, dependency_version, "callgraph")
        if cached_cg is not None:
            logger.info("reusing cached call graph for %s@%s", dependency_name, dependency_version)
            nodes, edges = CacheStore.deserialize_graph(cached_cg)
            builder.build(dependency_name=dependency_name, include_dependency=False)
            builder.add_cached_subgraph(nodes, edges)
            # Dependency module-level code runs on import, so treat it as an
            # entry point too (keeps cached graphs sound for reachability).
            dep_module_node = CallNode(
                qualname=f"{dependency_name}.<module>", file="", line=1
            )
            if dep_module_node not in builder.entry_points:
                builder.entry_points.append(dep_module_node)
            # Dynamic sites are still detected from dependency source files so
            # that cached graphs never hide a dynamic blocker (soundness).
            dynamic_sites = _detect_dynamic_in_dependency(dependency_name)
        else:
            graph_result = builder.build(dependency_name=dependency_name)
            call_graph = graph_result
            dynamic_sites = graph_result.dynamic_sites
            # Cache the dependency subgraph for reuse across projects.
            dep_nodes, dep_edges = _extract_dependency_subgraph(
                graph_result.graph, dependency_name
            )
            cache.put(
                dependency_name,
                dependency_version,
                "callgraph",
                CacheStore.serialize_graph(dep_nodes, dep_edges),
            )
    else:
        call_graph = builder.build()
        dynamic_sites = call_graph.dynamic_sites

    if call_graph is None:
        # Construct from builder state after cached-subgraph path.
        call_graph = CallGraphResult(
            graph=builder.graph,
            entry_points=builder.entry_points,
            dynamic_sites=dynamic_sites,
            name_index=builder._name_index,
            unparsed_files=list(builder.unparsed_files),
            unresolved_calls=list(builder.unresolved_calls),
        )

    analyzer = ReachabilityAnalyzer(call_graph, project_path)

    verdicts: list[Verdict] = []
    fix_commits: list[FixCommit] = []

    for alert_data in alerts:
        package = alert_data.get("package", "")
        version = alert_data.get("version", "")
        advisory_id = alert_data.get("advisory_id", "")

        # ---- Advisory -> vulnerable functions (cached per package@version).
        functions_unknown = False
        cached_advisory = cache.get(package, version, "advisory_functions", advisory_id)
        if cached_advisory is not None:
            fix = _fix_commit_from_dict(cached_advisory["fix_commit"])
            vuln_funcs = [_vuln_function_from_dict(d) for d in cached_advisory.get("vulnerable_functions", [])]
            functions_unknown = bool(cached_advisory.get("functions_unknown", False))
        else:
            record = client.fetch_advisory(advisory_id) if advisory_id else None
            fix = resolver.resolve(record or {})
            summary = record.get("summary", "") if record else ""
            vuln_funcs = diff_to_funcs.functions_for_commit(fix, summary)
            functions_unknown = diff_to_funcs.functions_unknown
            cache.put(
                package,
                version,
                "advisory_functions",
                {
                    "fix_commit": fix.model_dump(),
                    "vulnerable_functions": [
                        {
                            "module": vf.module,
                            "qualified_name": vf.qualified_name,
                            "file_path": vf.file_path,
                            "confidence": vf.confidence,
                        }
                        for vf in vuln_funcs
                    ],
                    "functions_unknown": functions_unknown,
                },
                advisory_id,
            )

        fix_commits.append(fix)

        alert = Alert(
            package=package,
            version=version,
            advisory_id=advisory_id,
            aliases=alert_data.get("aliases", []),
        )

        verdict = analyzer.analyze_alert(alert, vuln_funcs, functions_unknown, fix)
        verdicts.append(verdict)

    return verdicts, fix_commits, call_graph


def _extract_dependency_subgraph(graph, dependency_name: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Extract nodes/edges whose module starts with the dependency name."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    dep_prefix = dependency_name + "."
    for node in graph.nodes:
        if node.qualname == f"{dependency_name}.<module>" or node.qualname.startswith(dep_prefix):
            nodes.append({"qualname": node.qualname, "file": node.file, "line": node.line})
    for source, target, data in graph.edges(data=True):
        if (
            source.qualname == f"{dependency_name}.<module>"
            or source.qualname.startswith(dep_prefix)
        ) and (
            target.qualname == f"{dependency_name}.<module>"
            or target.qualname.startswith(dep_prefix)
        ):
            edges.append(
                {
                    "source": source.qualname,
                    "target": target.qualname,
                    "over_approx": bool(data.get("over_approx", False)),
                }
            )
    return nodes, edges


def _detect_dynamic_in_dependency(dependency_name: str) -> list:
    """Detect dynamic sites in an installed dependency's source files.

    Reads dependency sources from site-packages (importlib.metadata) and scans
    them statically; the dependency code is never imported or executed.
    """
    detector = DynamicDetector()
    try:
        dist = importlib.metadata.distribution(dependency_name)
    except importlib.metadata.PackageNotFoundError:
        return []
    try:
        base = dist.locate_file("")
    except Exception:
        base = None
    if base is None or not base.is_dir():
        try:
            mod = __import__(dependency_name)
            base = Path(getattr(mod, "__file__", "") or "").parent
        except Exception:
            return []
    sites: list = []
    for py in sorted(base.rglob("*.py")):
        if any(part in {".git", "__pycache__", "tests", "test"} for part in py.parts):
            continue
        try:
            source = py.read_text(encoding="utf-8")
        except OSError:
            continue
        sites.extend(detector.detect_in_source(str(py), source))
    return sites


def _print_table(verdicts: list[Verdict], only_uncertain: bool) -> None:
    """Print a readable terminal table of verdicts."""
    rows = []
    for v in verdicts:
        if only_uncertain and v.status != "uncertain":
            continue
        path = v.call_path
        first_hop = f"{path[0].function}@{path[0].file}:{path[0].line}" if path else "-"
        last_hop = f"{path[-1].function}@{path[-1].file}:{path[-1].line}" if path else "-"
        rows.append(
            (
                v.alert.advisory_id,
                f"{v.alert.package}@{v.alert.version}",
                v.status,
                v.confidence,
                first_hop,
                last_hop,
            )
        )

    if not rows:
        print("(no matching verdicts)")
        return

    header = ("advisory", "package", "verdict", "confidence", "first hop", "last hop")
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(header)]

    def fmt(row):
        return "  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row))

    print(fmt(header))
    print(fmt(("-" * w for w in widths)))
    for row in rows:
        print(fmt(row))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vulnreach", description="VulnReach reachability analyzer")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a project for reachable vulnerabilities")
    scan.add_argument("project_path", type=Path, help="Path to the Python project to scan")
    scan.add_argument(
        "--alerts",
        type=Path,
        required=True,
        help="Path to a JSON file containing vulnerability alerts",
    )
    scan.add_argument(
        "--out-dir",
        type=Path,
        default=Path("out"),
        help="Directory for report.json and report.vex.json (default: out)",
    )
    scan.add_argument(
        "--only-uncertain",
        action="store_true",
        help="Only list uncertain verdicts (needs human review)",
    )
    scan.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable the sqlite cache (always re-resolve)",
    )
    scan.add_argument(
        "--isolated",
        action="store_true",
        help="Run the analysis inside an isolated Docker container",
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        project_path: Path = args.project_path
        if not project_path.exists():
            print(f"error: project path does not exist: {project_path}", file=sys.stderr)
            return 1
        if not args.alerts.exists():
            print(f"error: alerts file does not exist: {args.alerts}", file=sys.stderr)
            return 1

        if args.isolated:
            from vulnreach.sandbox.docker_runner import DockerRunner

            try:
                runner = DockerRunner()
                report = runner.run_isolated(project_path, args.alerts, args.out_dir)
            except RuntimeError as exc:
                # Isolation failures are user-facing configuration/runtime
                # errors, not crashes: report them and exit non-zero.
                print(f"error: isolated analysis failed: {exc}", file=sys.stderr)
                return 1
            verdicts = [Verdict.model_validate(v) for v in report.get("verdicts", [])]
            _print_table(verdicts, args.only_uncertain)
            if any(v.status == "reachable" for v in verdicts):
                return 1
            return 0

        alerts = load_alerts(args.alerts)
        cache = CacheStore(enabled=not args.no_cache)
        verdicts, fix_commits, _call_graph = _run_pipeline(project_path, alerts, cache)

        # Write outputs
        out_dir: Path = args.out_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        report = {
            "alerts": alerts,
            "fix_commits": [fc.model_dump() for fc in fix_commits],
            "verdicts": [v.model_dump() for v in verdicts],
        }
        (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

        project_purl = _project_purl(project_path)
        vex_doc = build_document(verdicts, author="vulnreach", project_purl=project_purl)
        write_vex(out_dir / "report.vex.json", vex_doc)

        # Print table
        _print_table(verdicts, args.only_uncertain)

        # Exit code: 1 if any reachable verdict
        if any(v.status == "reachable" for v in verdicts):
            return 1
        return 0

    parser.error("unknown command")
    return 1


if __name__ == "__main__":
    sys.exit(main())
