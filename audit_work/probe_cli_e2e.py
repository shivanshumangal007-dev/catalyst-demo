"""Phase 8 probe: CLI end-to-end, cold vs warm cache, exit codes, outputs."""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vulnreach.advisories.fix_commit import FixCommit  # noqa: E402
from vulnreach.cache.store import CacheStore  # noqa: E402
from vulnreach.cli import main  # noqa: E402
from vulnreach.models import VulnerableFunction  # noqa: E402

FIX = FixCommit(repo_url="https://github.com/o/r", sha="a" * 40,
                resolution_method="direct_link", confidence=0.95)
LIB = "def vulnerable():\n    return 1\n\ndef safe():\n    return 2\n"


class FakeDist:
    def __init__(self, base: Path) -> None:
        self.base = Path(base)

    def locate_file(self, rel: str) -> Path:
        return self.base / rel


def make_project(root: Path, files: dict[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for rel, src in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src, encoding="utf-8")
    return root


def make_dep(root: Path) -> Path:
    pkg = root / "mydep"
    (pkg / "__init__.py").parent.mkdir(parents=True, exist_ok=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "core.py").write_text("def vulnerable():\n    return 1\n")
    (pkg / "api.py").write_text("from .core import vulnerable\ndef public():\n    return vulnerable()\n")
    return pkg


def patched_run(project: Path, alerts: Path, out: Path, store: Path,
                dep: Path | None, vf: VulnerableFunction, *extra: str) -> int:
    class FakeOSV:
        def __init__(self, *a, **k):
            pass

        def fetch_advisory(self, advisory_id):
            return {"id": advisory_id, "summary": "", "affected": [], "references": []}

    class FakeResolver:
        def __init__(self, *a, **k):
            pass

        def resolve(self, record):
            return FIX

    class FakeDiff:
        def __init__(self, *a, **k):
            self.functions_unknown = False
            self.public_entry_points = []

        def functions_for_commit(self, fix, summary=""):
            return [vf]

    dists = {"mydep": FakeDist(dep)} if dep else {}

    def fake_dist(name):
        if name in dists:
            return dists[name]
        import importlib.metadata
        raise importlib.metadata.PackageNotFoundError(name)

    class CacheForCLI(CacheStore):
        def __init__(self, *a, **k):
            super().__init__(db_path=store, **{x: y for x, y in k.items() if x != "db_path"})

    with patch("vulnreach.cli.OSVClient", FakeOSV), \
         patch("vulnreach.cli.FixCommitResolver", FakeResolver), \
         patch("vulnreach.cli.DiffToFunctions", FakeDiff), \
         patch("importlib.metadata.distribution", side_effect=fake_dist), \
         patch("vulnreach.cli.CacheStore", CacheForCLI):
        return main(["scan", str(project), "--alerts", str(alerts), "--out-dir", str(out), *extra])


def summarize(out: Path) -> dict:
    report = json.loads((out / "report.json").read_text())
    vex = json.loads((out / "report.vex.json").read_text())
    return {
        "verdicts": [(v["alert"]["advisory_id"], v["status"], v["confidence"]) for v in report["verdicts"]],
        "vex_status": [s.get("status") for s in vex["statements"]],
        "files": sorted(p.name for p in out.iterdir()),
    }


if __name__ == "__main__":
    tmp = Path(tempfile.mkdtemp(prefix="vr_cli_"))
    try:
        dep = make_dep(tmp / "deps")

        # Fixture A: project -> dependency public -> dependency vulnerable.
        proj_a = make_project(tmp / "a", {
            "main.py": "from mydep.api import public\npublic()\n",
        })
        alerts_a = tmp / "a.json"
        alerts_a.write_text(json.dumps([
            {"package": "mydep", "version": "1.0.0", "advisory_id": "ADV-A"}
        ]))
        vf_a = VulnerableFunction(module="mydep.core", qualified_name="mydep.core.vulnerable",
                                  file_path="mydep/core.py", confidence=0.95)
        out_a_cold = tmp / "out_a_cold"
        out_a_warm = tmp / "out_a_warm"
        store = tmp / "store.sqlite"
        code_cold = patched_run(proj_a, alerts_a, out_a_cold, store, dep, vf_a)
        code_warm = patched_run(proj_a, alerts_a, out_a_warm, store, dep, vf_a)
        print("== Fixture A: dependency cold vs warm ==")
        print("cold exit:", code_cold, summarize(out_a_cold))
        print("warm exit:", code_warm, summarize(out_a_warm))
        print("reports identical:",
              (out_a_cold / "report.json").read_text() == (out_a_warm / "report.json").read_text())

        # Fixture B: direct call in the project.
        proj_b = make_project(tmp / "b", {
            "lib.py": LIB,
            "main.py": "import lib\nlib.vulnerable()\n",
        })
        alerts_b = tmp / "b.json"
        alerts_b.write_text(json.dumps([
            {"package": "lib", "version": "1.0.0", "advisory_id": "ADV-B"}
        ]))
        vf_b = VulnerableFunction(module="lib", qualified_name="lib.vulnerable",
                                  file_path="lib.py", confidence=0.95)
        out_b = tmp / "out_b"
        code_b = patched_run(proj_b, alerts_b, out_b, tmp / "store_b.sqlite", None, vf_b)
        print("\n== Fixture B: direct project call ==")
        print("exit:", code_b, summarize(out_b))

        # Fixture C: reachable construct in an assignment (should be reachable).
        proj_c = make_project(tmp / "c", {
            "lib.py": LIB,
            "main.py": "import lib\nresult = lib.vulnerable()\n",
        })
        alerts_c = tmp / "c.json"
        alerts_c.write_text(json.dumps([
            {"package": "lib", "version": "1.0.0", "advisory_id": "ADV-C"}
        ]))
        out_c = tmp / "out_c"
        code_c = patched_run(proj_c, alerts_c, out_c, tmp / "store_c.sqlite", None, vf_b)
        print("\n== Fixture C: call in assignment ==")
        print("exit:", code_c, summarize(out_c))

        # --no-cache: two runs must both be reachable (no callgraph reuse).
        out_nc1 = tmp / "out_nc1"
        out_nc2 = tmp / "out_nc2"
        code_nc1 = patched_run(proj_a, alerts_a, out_nc1, tmp / "store_nc.sqlite", dep, vf_a, "--no-cache")
        code_nc2 = patched_run(proj_a, alerts_a, out_nc2, tmp / "store_nc.sqlite", dep, vf_a, "--no-cache")
        print("\n== --no-cache ==")
        print("run1 exit:", code_nc1, summarize(out_nc1)["verdicts"])
        print("run2 exit:", code_nc2, summarize(out_nc2)["verdicts"])

        # Output files exist.
        print("\noutputs:", sorted(p.name for p in out_a_cold.iterdir()))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
