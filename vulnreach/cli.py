"""Command-line interface for VulnReach.

Stage 1: ``vulnreach scan <project_path> --alerts alerts.json`` loads alerts,
resolves fix commits, and prints one JSON result per alert.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vulnreach.advisories.fix_commit import FixCommitResolver
from vulnreach.advisories.osv_client import OSVClient


def load_alerts(path: Path) -> list[dict]:
    """Load alerts from a JSON file (a list, or a single object wrapped in a list)."""
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    raise ValueError(f"alerts file {path} must contain a JSON object or list of objects")


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

    args = parser.parse_args(argv)

    if args.command == "scan":
        project_path: Path = args.project_path
        if not project_path.exists():
            print(f"error: project path does not exist: {project_path}", file=sys.stderr)
            return 1

        alerts = load_alerts(args.alerts)
        client = OSVClient()
        resolver = FixCommitResolver()

        results = []
        for alert in alerts:
            advisory_id = alert.get("advisory_id", "")
            record = client.fetch_advisory(advisory_id) if advisory_id else None
            fix = resolver.resolve(record or {})
            results.append(
                {
                    "package": alert.get("package"),
                    "version": alert.get("version"),
                    "advisory_id": advisory_id,
                    "fix_commit": fix.model_dump(),
                }
            )

        for result in results:
            print(json.dumps(result))
        return 0

    parser.error("unknown command")
    return 1


if __name__ == "__main__":
    sys.exit(main())
