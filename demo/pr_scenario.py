"""Synthetic PR scenario for the VulnReach PR chat agent demo.

Three fixture apps produce three verdicts derived from the real analyzer:

* ``demo/fixtures/app_reachable``  - calls the vulnerable function directly  → reachable
* ``demo/fixtures/app_not_reachable`` - imports the package but only uses safe functions → not_reachable
* ``demo/fixtures/app_dynamic``    - uses getattr(lib, name) with a config-driven name → uncertain

Run the scripted conversation:

    python demo/run_conversation.py
"""

from __future__ import annotations

from pathlib import Path

from vulnreach.advisories.fix_commit import FixCommit
from vulnreach.callgraph.builder import CallGraphBuilder
from vulnreach.models import Alert, VulnerableFunction
from vulnreach.reachability.analyzer import ReachabilityAnalyzer

FIXTURES = Path(__file__).resolve().parent / "fixtures"

DIRECT_LINK = FixCommit(
    repo_url="https://github.com/owner/lib",
    sha="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    resolution_method="direct_link",
    confidence=0.95,
)
PR_REF = FixCommit(
    repo_url="https://github.com/owner/lib",
    sha="b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1",
    resolution_method="pr_reference",
    confidence=0.7,
)


def _build(app_name: str, fix_commit: FixCommit, advisory_id: str) -> dict:
    """Build a scenario entry by running the real analyzer on a fixture app.

    Verdicts are derived from `analyzer.analyze_alert()`, not hard-coded
    (F-41).
    """
    project = FIXTURES / app_name
    builder = CallGraphBuilder(project)
    call_graph = builder.build()
    analyzer = ReachabilityAnalyzer(call_graph, project)
    vuln_funcs = [VulnerableFunction(
        module="lib", qualified_name="lib.vulnerable_function",
        file_path="lib.py", confidence=0.95
    )]
    alert = Alert(package="lib", version="1.0.0", advisory_id=advisory_id, aliases=[])
    verdict = analyzer.analyze_alert(alert, vuln_funcs, False, fix_commit)
    return {
        "verdict": verdict,
        "analyzer": analyzer,
        "project_path": str(project),
        "alert": alert,
        "vulnerable_functions": vuln_funcs,
        "fix_commit": fix_commit,
        "call_graph": call_graph,
    }


def build_scenario() -> dict[str, dict]:
    """Build the three-demo-verdict scenario with full analysis context."""
    scenario: dict[str, dict] = {}

    # ---- 1. reachable: app_reachable calls lib.vulnerable_function directly.
    scenario["reachable"] = _build("app_reachable", DIRECT_LINK, "DEMO-REACHABLE-1")

    # ---- 2. not_reachable: app_not_reachable imports lib but only uses safe_function.
    scenario["not_reachable"] = _build("app_not_reachable", DIRECT_LINK, "DEMO-SAFE-1")

    # ---- 3. uncertain: app_dynamic uses getattr(lib, name) with config-driven name.
    scenario["uncertain"] = _build("app_dynamic", PR_REF, "DEMO-DYNAMIC-1")

    return scenario
