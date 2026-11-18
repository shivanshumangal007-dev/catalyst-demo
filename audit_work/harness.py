"""Audit harness: build tiny fixtures and print exact analyzer verdicts."""
from __future__ import annotations

import shutil
import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnreach.advisories.fix_commit import FixCommit
from vulnreach.callgraph.builder import CallGraphBuilder
from vulnreach.models import Alert, VulnerableFunction
from vulnreach.reachability.analyzer import ReachabilityAnalyzer

ROOT = Path(__file__).resolve().parent / "fixtures"

FIX = FixCommit(
    repo_url="https://github.com/o/r",
    sha="a" * 40,
    resolution_method="direct_link",
    confidence=0.95,
)


def make(name: str, files: dict[str, str]) -> Path:
    d = ROOT / name
    if d.exists():
        shutil.rmtree(d)
    for rel, src in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(src), encoding="utf-8")
    return d


def analyze(project: Path, vf_qual: str | None, vf_file: str | None = "lib.py",
            funcs_unknown: bool = False, vuln_funcs=None, dep: str | None = None,
            package: str = "lib"):
    b = CallGraphBuilder(project)
    g = b.build(dependency_name=dep)
    a = ReachabilityAnalyzer(g, project)
    if vuln_funcs is None:
        vuln_funcs = [] if vf_qual is None else [
            VulnerableFunction(module="lib", qualified_name=vf_qual,
                               file_path=vf_file or "lib.py", confidence=0.95)
        ]
    v = a.analyze_alert(Alert(package=package, version="1.0.0", advisory_id="A-1"),
                        vuln_funcs, funcs_unknown, FIX)
    return v, g


def show(label: str, project: Path, *args, **kw):
    v, g = analyze(project, *args, **kw)
    path = " -> ".join(f"{h.function}@{h.file}:{h.line}" for h in v.call_path)
    print(f"{label:38s} {v.status:13s} conf={v.confidence:6s} path={path or '-'}")
    if v.dynamic_blockers:
        print(f"{'':38s} blockers={v.dynamic_blockers[:2]}")
    return v, g


LIB = """
def vulnerable():
    return 1

def safe():
    return 2
"""

if __name__ == "__main__":
    pass
