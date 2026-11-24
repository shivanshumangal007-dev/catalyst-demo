"""Phase 4/8 probe: multi-alert pipeline only models the first alert's package."""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_work.harness import make  # noqa: E402
from vulnreach.cache.store import CacheStore  # noqa: E402
from vulnreach.cli import _run_pipeline  # noqa: E402


class FakeDist:
    def __init__(self, base: Path) -> None:
        self.base = Path(base)

    def locate_file(self, rel: str) -> Path:
        return self.base / rel


def make_dep(root: Path, name: str, vuln_name: str) -> Path:
    pkg = root / name
    (pkg / "__init__.py").parent.mkdir(parents=True, exist_ok=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "core.py").write_text(f"def {vuln_name}():\n    return 1\n", encoding="utf-8")
    (pkg / "api.py").write_text(
        f"from .core import {vuln_name}\ndef public():\n    return {vuln_name}()\n",
        encoding="utf-8",
    )
    return pkg


def seed_advisory(cache: CacheStore, package: str, module: str, vuln: str) -> None:
    cache.put(
        package,
        "1.0.0",
        "advisory_functions",
        {
            "fix_commit": {
                "repo_url": "https://github.com/o/r",
                "sha": "a" * 40,
                "resolution_method": "direct_link",
                "confidence": 0.95,
            },
            "vulnerable_functions": [
                {
                    "module": module,
                    "qualified_name": f"{module}.{vuln}",
                    "file_path": "core.py",
                    "confidence": 0.95,
                }
            ],
            "functions_unknown": False,
        },
        advisory_id=f"ADV-{package}",
    )


if __name__ == "__main__":
    tmp = Path(tempfile.mkdtemp(prefix="vr_pipeline_"))
    try:
        depA = make_dep(tmp, "depa", "vuln_a")
        depB = make_dep(tmp, "depb", "vuln_b")
        project = make(
            "pipeline_multi",
            {
                "main.py": (
                    "from depa.api import public as public_a\n"
                    "from depb.api import public as public_b\n"
                    "public_a()\n"
                    "public_b()\n"
                )
            },
        )
        cache = CacheStore(db_path=tmp / "store.sqlite")
        seed_advisory(cache, "depa", "depa.core", "vuln_a")
        seed_advisory(cache, "depb", "depb.core", "vuln_b")
        alerts = [
            {"package": "depa", "version": "1.0.0", "advisory_id": "ADV-depa"},
            {"package": "depb", "version": "1.0.0", "advisory_id": "ADV-depb"},
        ]
        dists = {
            "depa": FakeDist(depA),
            "depb": FakeDist(depB),
        }

        def fake_dist(name):
            if name in dists:
                return dists[name]
            import importlib.metadata
            raise importlib.metadata.PackageNotFoundError(name)

        with patch("importlib.metadata.distribution", side_effect=fake_dist):
            verdicts, fixes, graph = _run_pipeline(project, alerts, cache)
            print("order [depa, depb] (graph models depa only):")
            for v in verdicts:
                print(f"  {v.alert.package:6s} {v.alert.advisory_id:10s} -> {v.status:13s} conf={v.confidence}")
            print("  graph dep nodes:",
                  sorted({n.qualname.split('.')[0] for n in graph.graph.nodes if not n.qualname.startswith(('main', '<'))}))

            # Reverse the order: the pipeline models depb only, so depa flips.
            verdicts2, _, _ = _run_pipeline(project, list(reversed(alerts)), cache)
            print("order [depb, depa] (graph models depb only):")
            for v in verdicts2:
                print(f"  {v.alert.package:6s} {v.alert.advisory_id:10s} -> {v.status:13s} conf={v.confidence}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
