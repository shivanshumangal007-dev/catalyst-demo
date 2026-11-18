"""Command-line interface for VulnReach.

``vulnreach scan <project_path> --alerts alerts.json --out-dir out/`` runs the
full pipeline:

1. Load alerts
2. Resolve fix commits (OSV)
3. Convert fix commits to vulnerable functions (diff -> functions)
4. Build a call graph of the project (+ dependency)
5. Analyze reachability for each alert
6. Emit report.json (all verdicts) and report.vex.json (OpenVEX document)
7. Print a readable terminal table

Exit code 1 if any verdict is ``reachable`` (for CI use).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from vulnreach.advisories.fix_commit import FixCommit, FixCommitResolver
from vulnreach.advisories.osv_client import OSVClient
from vulnreach.callgraph.builder import CallGraphBuilder
from vulnreach.diffing.diff_to_functions import DiffToFunctions
from vulnreach.models import Alert, PathHop, Verdict
from vulnreach.reachability.analyzer import ReachabilityAnalyzer
from vulnreach.vex.openvex import build_document, write_vex


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


def _run_pipeline(
    project_path: Path,
    alerts: list[dict[str, Any]],
) -> tuple[list[Verdict], list[FixCommit]]:
    """Run the full analysis pipeline and return (verdicts, fix_commits)."""
    client = OSVClient()
    resolver = FixCommitResolver()
    diff_to_funcs = DiffToFunctions()
    builder = CallGraphBuilder(project_path)
    call_graph = builder.build()
    analyzer = ReachabilityAnalyzer(call_graph, project_path)

    verdicts: list[Verdict] = []
    fix_commits: list[FixCommit] = []

    for alert_data in alerts:
        advisory_id = alert_data.get("advisory_id", "")
        record = client.fetch_advisory(advisory_id) if advisory_id else None
        fix = resolver.resolve(record or {})
        fix_commits.append(fix)

        summary = record.get("summary", "") if record else ""
        vuln_funcs = diff_to_funcs.functions_for_commit(fix, summary)
        functions_unknown = diff_to_funcs.functions_unknown

        alert = Alert(
            package=alert_data.get("package", ""),
            version=alert_data.get("version", ""),
            advisory_id=advisory_id,
            aliases=alert_data.get("aliases", []),
        )

        verdict = analyzer.analyze_alert(alert, vuln_funcs, functions_unknown, fix)
        verdicts.append(verdict)

    return verdicts, fix_commits


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

    widths = [max(len(str(r[i])) for r in rows + [header]) for i, header in enumerate(
        ("advisory", "package", "verdict", "confidence", "first hop", "last hop")
    )]
    header = ("advisory", "package", "verdict", "confidence", "first hop", "last hop")

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

    args = parser.parse_args(argv)

    if args.command == "scan":
        project_path: Path = args.project_path
        if not project_path.exists():
            print(f"error: project path does not exist: {project_path}", file=sys.stderr)
            return 1
        if not args.alerts.exists():
            print(f"error: alerts file does not exist: {args.alerts}", file=sys.stderr)
            return 1

        alerts = load_alerts(args.alerts)
        verdicts, fix_commits = _run_pipeline(project_path, alerts)

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
