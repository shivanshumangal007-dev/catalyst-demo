"""Synthetic PR scenario for the VulnReach PR chat agent demo.

Three fixture apps produce three verdicts:

* ``demo/reachable``  - calls the vulnerable function directly  → reachable
* ``demo/safe``       - imports the package but only uses safe functions → not_reachable
* ``demo/dynamic``    - uses getattr(lib, name) with a config-driven name → uncertain

Run the scripted conversation:

    python demo/run_conversation.py
"""

from __future__ import annotations

import json
from pathlib import Path

from vulnreach.advisories.fix_commit import FixCommit
from vulnreach.callgraph.builder import CallGraphBuilder
from vulnreach.models import Alert, PathHop, Verdict
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


def _build_context(app_name: str):
    """Build the analyzer context (graph + entry points) for a fixture app."""
    project = FIXTURES / app_name
    builder = CallGraphBuilder(project)
    call_graph = builder.build()
    analyzer = ReachabilityAnalyzer(call_graph, project)
    return project, analyzer, call_graph


def _make_verdict(
    *,
    package: str,
    version: str,
    advisory_id: str,
    status: str,
    confidence: str,
    call_path: list[PathHop] | None = None,
    reasons: list[str] | None = None,
    dynamic_blockers: list[str] | None = None,
    explanation: str = "",
    fix_commit: FixCommit,
) -> Verdict:
    alert = Alert(package=package, version=version, advisory_id=advisory_id, aliases=[])
    return Verdict(
        alert=alert,
        status=status,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        call_path=call_path or [],
        reasons=reasons or [],
        dynamic_blockers=dynamic_blockers or [],
        explanation=explanation,
    )


def build_scenario() -> dict[str, dict]:
    """Build the three-demo-verdict scenario with full analysis context."""
    scenario: dict[str, dict] = {}

    # ---- 1. reachable: app_reachable calls lib.vulnerable_function directly.
    project, analyzer, call_graph = _build_context("app_reachable")
    reachable_path = [
        PathHop(file="main.py", line=3, function="app_reachable.main.<module>"),
        PathHop(file="lib.py", line=1, function="lib.vulnerable_function"),
    ]
    scenario["reachable"] = {
        "verdict": _make_verdict(
            package="lib",
            version="1.0.0",
            advisory_id="DEMO-REACHABLE-1",
            status="reachable",
            confidence="high",
            call_path=reachable_path,
            reasons=[
                "Static call path from main.py:3 to lib.vulnerable_function@lib.py:1",
            ],
            dynamic_blockers=[],
            explanation=(
                "Reachable: lib@1.0.0 (DEMO-REACHABLE-1) — the vulnerable function "
                "lib.vulnerable_function is reachable from project code via main.py:3."
            ),
            fix_commit=DIRECT_LINK,
        ),
        "analyzer": analyzer,
        "project_path": str(project),
        "alert": Alert(package="lib", version="1.0.0", advisory_id="DEMO-REACHABLE-1"),
        "vulnerable_functions": [],
        "fix_commit": DIRECT_LINK,
        "call_graph": call_graph,
    }

    # ---- 2. not_reachable: app_not_reachable imports lib but only uses safe_function.
    project, analyzer, call_graph = _build_context("app_not_reachable")
    scenario["not_reachable"] = {
        "verdict": _make_verdict(
            package="lib",
            version="1.0.0",
            advisory_id="DEMO-SAFE-1",
            status="not_reachable",
            confidence="high",
            reasons=[
                "No static call path from any entry point to lib.vulnerable_function",
                "No dynamic features that could conceal a path",
            ],
            dynamic_blockers=[],
            explanation=(
                "Not reachable: lib@1.0.0 (DEMO-SAFE-1) — no static call path from "
                "project code to lib.vulnerable_function, and no dynamic features."
            ),
            fix_commit=DIRECT_LINK,
        ),
        "analyzer": analyzer,
        "project_path": str(project),
        "alert": Alert(package="lib", version="1.0.0", advisory_id="DEMO-SAFE-1"),
        "vulnerable_functions": [],
        "fix_commit": DIRECT_LINK,
        "call_graph": call_graph,
    }

    # ---- 3. uncertain: app_dynamic uses getattr(lib, name) with config-driven name.
    project, analyzer, call_graph = _build_context("app_dynamic")
    scenario["uncertain"] = {
        "verdict": _make_verdict(
            package="lib",
            version="1.0.0",
            advisory_id="DEMO-DYNAMIC-1",
            status="uncertain",
            confidence="medium",
            reasons=[
                "No static call path from any entry point to lib.vulnerable_function",
                "Dynamic Python features could hide a reachable path",
            ],
            dynamic_blockers=[
                "main.py:5 [getattr] getattr(lib, <non-literal>)"
            ],
            explanation=(
                "Uncertain: lib@1.0.0 (DEMO-DYNAMIC-1) is not reachable via any static "
                "call path, but getattr(lib, name) with a non-literal name could conceal "
                "a path to lib.vulnerable_function."
            ),
            fix_commit=PR_REF,
        ),
        "analyzer": analyzer,
        "project_path": str(project),
        "alert": Alert(package="lib", version="1.0.0", advisory_id="DEMO-DYNAMIC-1"),
        "vulnerable_functions": [],
        "fix_commit": PR_REF,
        "call_graph": call_graph,
    }

    return scenario
