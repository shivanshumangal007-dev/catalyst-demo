"""Debug fix-commit resolution for the alerts in alerts.json.

For each advisory it prints: the raw OSV response (id, summary, package, affected),
every reference URL, which resolution branch ran, and the final result (or why
not_found).  OSV/HTTP failures are logged as ERROR so they are never silently
mistaken for "no advisory".
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.DEBUG,
    format="%(levelname)s %(name)s: %(message)s",
)

from vulnreach.advisories.osv_client import OSVClient  # noqa: E402
from vulnreach.advisories.fix_commit import FixCommitResolver  # noqa: E402


def main() -> int:
    alerts_path = ROOT / "alerts.json"
    alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
    client = OSVClient(enabled=True)
    resolver = FixCommitResolver(enabled=True)

    for alert in alerts:
        pkg = alert.get("package")
        ver = alert.get("version")
        aid = alert.get("advisory_id")
        print("=" * 80)
        print(f"ALERT: {pkg}@{ver}  advisory={aid}")
        print("=" * 80)

        record = client.fetch_advisory(aid)
        if record is None:
            print(f"[RESULT] {aid}: not_found (OSV fetch returned None -- see ERROR logs above)")
            continue

        # Raw OSV response (trimmed to the fields that drive resolution).
        affected = record.get("affected") or []
        print("\n-- raw OSV response --")
        print(json.dumps(record, indent=2)[:3000])

        print("\n-- reference URLs --")
        for ref in record.get("references") or []:
            print(f"  [{ref.get('type')}] {ref.get('url')}")
        if not record.get("references"):
            print("  (none)")

        for aff in affected:
            pkginfo = aff.get("package") or {}
            print("\n-- affected --")
            print("  package:", pkginfo.get("name"), "|", pkginfo.get("ecosystem"),
                  "| repository:", pkginfo.get("repository"))
            for rng in aff.get("ranges") or []:
                print("  range:", rng.get("type"), [ev for ev in rng.get("events") or []])

        fix = resolver.resolve(record or {})
        print("\n-- resolution result --")
        print(f"  method:   {fix.resolution_method}")
        print(f"  sha:      {fix.sha}")
        print(f"  repo_url: {fix.repo_url}")
        print(f"  confidence: {fix.confidence}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
