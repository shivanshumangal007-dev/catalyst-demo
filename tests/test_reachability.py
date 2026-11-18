"""Reachability + dynamic-feature tests using fixture apps.

Each fixture app lives under ``tests/fixtures/<app>/`` and is analysed end-to-end
(call graph build -> reachability analysis) to assert the exact verdict.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnreach.advisories.fix_commit import FixCommit
from vulnreach.callgraph.builder import CallGraphBuilder
from vulnreach.callgraph.dynamic_detector import DynamicDetector
from vulnreach.models import Alert, VulnerableFunction
from vulnreach.reachability.analyzer import ReachabilityAnalyzer

FIXTURES = Path(__file__).resolve().parent / "fixtures"

DIRECT_LINK = FixCommit(
    repo_url="https://github.com/owner/repo",
    sha="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    resolution_method="direct_link",
    confidence=0.95,
)
PR_REF = FixCommit(
    repo_url="https://github.com/owner/repo",
    sha="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    resolution_method="pr_reference",
    confidence=0.7,
)


def _vuln_function(file_path: str = "lib.py") -> VulnerableFunction:
    return VulnerableFunction(
        module="lib",
        qualified_name="lib.vulnerable_function",
        file_path=file_path,
        confidence=0.95,
    )


def _alert() -> Alert:
    return Alert(package="lib", version="1.0.0", advisory_id="TEST-1")


def _analyze(app_name: str, fix_commit: FixCommit = DIRECT_LINK, functions_unknown: bool = False):
    project = FIXTURES / app_name
    builder = CallGraphBuilder(project)
    graph = builder.build()
    analyzer = ReachabilityAnalyzer(graph, project)
    return analyzer.analyze_alert(
        alert=_alert(),
        vulnerable_functions=[_vuln_function()],
        functions_unknown=functions_unknown,
        fix_commit=fix_commit,
    )


# ------------------------------------------------------------------ reachable


def test_app_reachable_direct_call():
    verdict = _analyze("app_reachable")
    assert verdict.status == "reachable"
    assert verdict.confidence == "high"
    assert len(verdict.call_path) >= 2
    assert any(h.function == "lib.vulnerable_function" for h in verdict.call_path)
    assert not verdict.dynamic_blockers
    assert "Reachable" in verdict.explanation


def test_app_indirect_through_helpers():
    verdict = _analyze("app_indirect")
    assert verdict.status == "reachable"
    assert len(verdict.call_path) >= 3
    functions = [h.function for h in verdict.call_path]
    assert "lib.vulnerable_function" in functions
    assert verdict.confidence in {"high", "medium"}


# ------------------------------------------------------------------ not reachable


def test_app_not_reachable():
    verdict = _analyze("app_not_reachable")
    assert verdict.status == "not_reachable"
    assert verdict.confidence == "high"  # fix commit was direct_link
    assert verdict.call_path == []
    assert not verdict.dynamic_blockers
    assert "Not reachable" in verdict.explanation


def test_app_not_reachable_medium_confidence_without_direct_link():
    verdict = _analyze("app_not_reachable", fix_commit=PR_REF)
    assert verdict.status == "not_reachable"
    assert verdict.confidence == "medium"


# ------------------------------------------------------------------ dynamic


def test_app_dynamic_is_uncertain():
    verdict = _analyze("app_dynamic")
    assert verdict.status == "uncertain"
    assert verdict.call_path == []
    assert verdict.dynamic_blockers, "expected dynamic blockers"
    assert any("getattr" in b for b in verdict.dynamic_blockers)
    assert "uncertain" in verdict.explanation.lower() or "dynamic" in verdict.explanation.lower()


def test_dynamic_detector_flags_getattr():
    detector = DynamicDetector()
    source = 'import lib\nname = "vulnerable_function"\ngetattr(lib, name)()\n'
    sites = detector.detect_in_source("app_dynamic/main.py", source)
    kinds = {s.kind for s in sites}
    assert "getattr" in kinds


# ------------------------------------------------------------------ functions_unknown -> uncertain, never not_reachable


def test_functions_unknown_is_uncertain():
    verdict = _analyze("app_reachable", functions_unknown=True)
    assert verdict.status == "uncertain"
    assert verdict.call_path == []
    assert "could not determine vulnerable functions" in verdict.reasons[0]


# ------------------------------------------------------------------ no fixture is wrongly marked not_reachable


def test_no_fixture_wrongly_marked_not_reachable():
    """Soundness check: reachable/uncertain fixtures must never be not_reachable."""
    for app_name in ("app_reachable", "app_indirect", "app_dynamic"):
        verdict = _analyze(app_name)
        assert verdict.status != "not_reachable", f"{app_name} wrongly marked not_reachable"
