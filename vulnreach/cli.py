"""Command-line interface for VulnReach.

``vulnreach scan <project_path> --alerts alerts.json --out-dir out/`` runs the
full pipeline:

1. Load alerts
2. Resolve fix commits (OSV) -- results are cached per ``package@version`` so
   popular packages are analyzed once and reused across projects
3. Convert fix commits to vulnerable functions (diff -> functions) -- cached too
4. Build a call graph of the project (+ all alert dependency packages)
5. Analyze reachability for each alert against the shared graph
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
from vulnreach.callgraph.builder import CallGraphBuilder, CallGraphResult, CallNode, _CallVisitor
from vulnreach.callgraph.dynamic_detector import DynamicDetector
from vulnreach.cache.store import CacheStore
from vulnreach.diffing.diff_to_functions import DiffToFunctions, VulnerableFunction
from vulnreach.models import Alert, PathHop, Verdict
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
    cache_enabled: bool = True,
    vuln_functions_overrides: dict[str, list[str]] | None = None,
) -> tuple[list[Verdict], list[FixCommit], CallGraphResult]:
    """Run the full analysis pipeline with caching.

    For each alert, the advisory -> vulnerable functions resolution is looked up
    in the cache first (keyed by ``package@version``).  On a miss it is resolved
    via OSV + fix commit + diff parsing and stored.

    One shared call graph is built that includes *all* alert dependency
    packages, so every alert's vulnerable functions can be resolved against the
    same graph (fixes F-15: multi-alert scans only modeled the first package).
    """
    client = OSVClient(enabled=cache_enabled)
    resolver = FixCommitResolver(enabled=cache_enabled)
    diff_to_funcs = DiffToFunctions()

    # ---- Collect all unique alert packages for the shared call graph.
    dep_packages: dict[str, str] = {}
    for alert_data in alerts:
        pkg = alert_data.get("package", "")
        ver = alert_data.get("version", "")
        if pkg and pkg not in dep_packages:
            dep_packages[pkg] = ver

    # ---- Build one call graph including every alert dependency package.
    builder = CallGraphBuilder(project_path)
    call_graph: CallGraphResult | None = None
    dynamic_sites: list[Any] = []

    if dep_packages:
        # Check cache for every package; build missing ones.
        missing_packages: list[tuple[str, str]] = []
        cached_nodes: list[dict[str, Any]] = []
        cached_edges: list[dict[str, Any]] = []

        for pkg, ver in dep_packages.items():
            cached_cg = cache.get(pkg, ver, "callgraph")
            if cached_cg is not None:
                logger.info("reusing cached call graph for %s@%s", pkg, ver)
                nodes, edges = CacheStore.deserialize_graph(cached_cg)
                cached_nodes.extend(nodes)
                cached_edges.extend(edges)
            else:
                missing_packages.append((pkg, ver))

        # Build the graph with all missing packages at once.
        builder.build(dependency_name=None, include_dependency=False)
        # Track every alert package as a dependency so unresolved dependency
        # calls are detected (previously _dependency_names was empty here, so
        # unresolved_calls was always empty in the CLI pipeline).
        builder._dependency_names = set(dep_packages.keys())
        if missing_packages:
            # Collect dependency files for all missing packages.
            all_dep_files: list[tuple[str, Path]] = []
            for pkg, ver in missing_packages:
                dep_files = builder._collect_dependency_files(pkg)
                all_dep_files.extend(dep_files)

            # Parse and collect definitions for dependency files.
            for module, path in all_dep_files:
                tree = builder._parse_file(path)
                if tree is None:
                    continue
                builder._files.append((module, path, tree))
                builder._collect_definitions(module, tree)

            # Initialize per-module bookkeeping for all files (project + deps).
            builder._dynamic_imports = {
                module: set() for module, _, _ in builder._files
            }
            builder._dict_bindings = {module: {} for module, _, _ in builder._files}

            # Dynamic detection for all files.
            detector = DynamicDetector()
            all_dynamic = detector.detect(project_path, builder._files)
            builder._dynamic_site_index = {}
            for site in all_dynamic:
                builder._dynamic_site_index[(site.file, site.line)] = site
            dynamic_sites.extend(all_dynamic)

            # Re-run call resolution on ALL files (project + dependencies) so
            # cross-package edges (e.g. main() -> dep.api.public) are resolved.
            for module, path, tree in builder._files:
                module_node = CallNode(
                    qualname=f"{module}.<module>",
                    file=builder._display_file(path),
                    line=1,
                )
                if not builder.graph.has_node(module_node):
                    builder.graph.add_node(module_node)
                builder._name_index.setdefault("<module>", []).append(module_node)
                visitor = _CallVisitor(builder, module, path, module_node)
                visitor.visit(tree)
                builder._accounted_calls.update(visitor.accounted_calls)
                builder._all_call_sites.extend(visitor.all_call_sites)

            # Compute unresolved calls.
            for file_path, line, _rendered in builder._all_call_sites:
                if (file_path, line) not in builder._accounted_calls:
                    pass  # _add_call_edge / _CallVisitor already recorded dep-targeted ones

            # Cache each package's subgraph.
            for pkg, ver in missing_packages:
                dep_prefix = pkg + "."
                dep_nodes: list[dict[str, Any]] = []
                dep_edges: list[dict[str, Any]] = []
                for node in builder.graph.nodes:
                    if (
                        node.qualname == f"{pkg}.<module>"
                        or node.qualname.startswith(dep_prefix)
                    ):
                        dep_nodes.append(
                            {"qualname": node.qualname, "file": node.file, "line": node.line}
                        )
                for source, target, data in builder.graph.edges(data=True):
                    if (
                        source.qualname == f"{pkg}.<module>"
                        or source.qualname.startswith(dep_prefix)
                    ) and (
                        target.qualname == f"{pkg}.<module>"
                        or target.qualname.startswith(dep_prefix)
                    ):
                        dep_edges.append(
                            {
                                "source": source.qualname,
                                "target": target.qualname,
                                "over_approx": bool(data.get("over_approx", False)),
                            }
                        )
                cache.put(
                    pkg,
                    ver,
                    "callgraph",
                    CacheStore.serialize_graph(dep_nodes, dep_edges),
                )

        # Add cached subgraphs to the graph.  Nodes are also registered in
        # _file_functions so _find_node / _resolve_name_call can locate them
        # precisely (cold and warm cache runs must produce identical verdicts).
        for node in cached_nodes:
            call_node = CallNode(
                qualname=node["qualname"],
                file=node.get("file", ""),
                line=int(node.get("line", 1)),
            )
            builder.graph.add_node(call_node)
            builder._name_index.setdefault(call_node.qualname.split(".")[-1], []).append(
                call_node
            )
            # Register in _file_functions for precise resolution.
            parts = call_node.qualname.split(".")
            if len(parts) > 1:
                mod_name = parts[0]
                func_qual = ".".join(parts[1:])
                builder._file_functions.setdefault(mod_name, {})[call_node.qualname] = call_node
        for edge in cached_edges:
            source = builder._find_node(edge["source"])
            target = builder._find_node(edge["target"])
            if source is None or target is None:
                continue
            builder.graph.add_edge(
                source, target, over_approx=bool(edge.get("over_approx", False))
            )

        # Re-resolve project calls now that every dependency node (freshly parsed
        # or restored from cache) is registered in ``_file_functions``.  Without
        # this, project -> dependency call edges resolved during the project-only
        # build (before dep nodes existed) are lost on warm cache runs, breaking
        # cold/warm verdict equivalence (F-06).  Re-visiting also recomputes
        # ``unresolved_calls`` so a call that was unresolved before the cache was
        # restored (but is now resolvable) no longer forces ``uncertain``.
        builder.unresolved_calls = []
        builder._accounted_calls = set()
        builder._all_call_sites = []
        for module, path, tree in builder._files:
            module_node = CallNode(
                qualname=f"{module}.<module>",
                file=builder._display_file(path),
                line=1,
            )
            if not builder.graph.has_node(module_node):
                builder.graph.add_node(module_node)
            visitor = _CallVisitor(builder, module, path, module_node)
            visitor.visit(tree)
            builder._accounted_calls.update(visitor.accounted_calls)
            builder._all_call_sites.extend(visitor.all_call_sites)

        # Dependency module-level code runs on import -> entry point.
        for pkg in dep_packages:
            dep_module_node = CallNode(qualname=f"{pkg}.<module>", file="", line=1)
            if dep_module_node not in builder.entry_points:
                builder.entry_points.append(dep_module_node)

        call_graph = CallGraphResult(
            graph=builder.graph,
            entry_points=builder.entry_points,
            dynamic_sites=dynamic_sites,
            name_index=builder._name_index,
            unparsed_files=list(builder.unparsed_files),
            unresolved_calls=list(builder.unresolved_calls),
        )
    else:
        call_graph = builder.build()
        dynamic_sites = call_graph.dynamic_sites

    analyzer = ReachabilityAnalyzer(call_graph, project_path)

    verdicts: list[Verdict] = []
    fix_commits: list[FixCommit] = []

    for alert_data in alerts:
        package = alert_data.get("package", "")
        version = alert_data.get("version", "")
        advisory_id = alert_data.get("advisory_id", "")

        # ---- User-supplied vulnerable-function override (offline/demo mode).
        # maps advisory_id -> list of qualified vulnerable function names.
        override_names = (vuln_functions_overrides or {}).get(advisory_id)
        user_supplied = False
        if override_names is not None:
            # Offline override: skip OSV/fix-commit/diff entirely.  Confidence is
            # capped at "manual" (medium) because the fix commit was not
            # independently resolved, and the verdict notes the user supply.
            user_supplied = True
            vuln_funcs = [
                VulnerableFunction(
                    module=name.rsplit(".", 1)[0] if "." in name else "",
                    qualified_name=name,
                    file_path="",
                    confidence=0.95,
                )
                for name in override_names
            ]
            functions_unknown = False
            fix = FixCommit(
                repo_url=None, sha=None,
                resolution_method="not_found", confidence=0.0,
            )
        else:
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
                # Add public entry points (public functions calling changed private
                # functions) as additional vulnerable targets -- they are likely user
                # entry points that reach the vulnerable code.
                for ep in diff_to_funcs.public_entry_points:
                    if ep not in vuln_funcs:
                        vuln_funcs.append(ep)
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

        verdict = analyzer.analyze_alert(
            alert, vuln_funcs, functions_unknown, fix, user_supplied_functions=user_supplied
        )
        verdicts.append(verdict)

    return verdicts, fix_commits, call_graph


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
    scan.add_argument(
        "--vuln-functions",
        type=Path,
        help="Offline override: JSON mapping advisory_id -> list of qualified "
        "vulnerable function names (bypasses OSV/fix-commit/diff).",
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

            runner = DockerRunner()
            try:
                report = runner.run_isolated(project_path, args.alerts, args.out_dir)
            except RuntimeError as exc:
                print(f"error: isolated analysis failed: {exc}", file=sys.stderr)
                return 1
            verdicts = [Verdict.model_validate(v) for v in report.get("verdicts", [])]
            _print_table(verdicts, args.only_uncertain)
            if any(v.status == "reachable" for v in verdicts):
                return 1
            return 0

        alerts = load_alerts(args.alerts)
        cache = CacheStore(enabled=not args.no_cache)
        overrides: dict[str, list[str]] = {}
        if args.vuln_functions:
            try:
                overrides = json.loads(args.vuln_functions.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                print(f"error: could not read --vuln-functions {args.vuln_functions}: {exc}", file=sys.stderr)
                return 1
        verdicts, fix_commits, _call_graph = _run_pipeline(
            project_path,
            alerts,
            cache,
            cache_enabled=not args.no_cache,
            vuln_functions_overrides=overrides,
        )

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
