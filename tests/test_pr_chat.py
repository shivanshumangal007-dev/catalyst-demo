"""Tests for the PR conversation agent (rule-based, no LLM needed)."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnreach.agent.pr_chat import (
    LLMClient,
    PRChatAgent,
    RuleBasedLLMClient,
    build_pr_comment,
)
from vulnreach.advisories.fix_commit import FixCommit
from vulnreach.callgraph.builder import CallGraphBuilder
from vulnreach.models import Alert, PathHop, Verdict
from vulnreach.reachability.analyzer import ReachabilityAnalyzer

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"

DIRECT_LINK = FixCommit(
    repo_url="https://github.com/owner/lib",
    sha="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    resolution_method="direct_link",
    confidence=0.95,
)


def _build_analyzer(app_name: str):
    project = FIXTURES / app_name
    builder = CallGraphBuilder(project)
    call_graph = builder.build()
    return ReachabilityAnalyzer(call_graph, project), str(project), call_graph


def _make_verdict(status, confidence, call_path=None, dynamic_blockers=None, explanation=""):
    alert = Alert(package="lib", version="1.0.0", advisory_id="TEST-1")
    return Verdict(
        alert=alert,
        status=status,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        call_path=call_path or [],
        reasons=[],
        dynamic_blockers=dynamic_blockers or [],
        explanation=explanation,
    )


def _agent_for(verdict, analyzer, project_path, call_graph):
    return PRChatAgent(
        verdict=verdict,
        analyzer=analyzer,
        project_path=project_path,
        alert=verdict.alert,
        vulnerable_functions=[],
        fix_commit=DIRECT_LINK,
        call_graph=call_graph,
        llm_client=RuleBasedLLMClient,
    )


# ------------------------------------------------------------------ build_pr_comment


def test_build_pr_comment_reachable():
    call_path = [
        PathHop(file="main.py", line=3, function="main.<module>"),
        PathHop(file="lib.py", line=1, function="lib.vuln"),
    ]
    v = _make_verdict(
        "reachable", "high", call_path=call_path,
        explanation="Reachable: path found",
    )
    comment = build_pr_comment(v)
    assert "## VulnReach verdict: lib@1.0.0" in comment
    assert "- **Verdict:** reachable" in comment
    assert "- **Confidence:** high" in comment
    assert "main.py:3" in comment
    assert "lib.py:1" in comment
    assert "lib.vuln" in comment
    assert "Upgrade" in comment


def test_build_pr_comment_not_reachable():
    v = _make_verdict("not_reachable", "high", explanation="Not reachable")
    comment = build_pr_comment(v)
    assert "- **Verdict:** not_reachable" in comment
    assert "No call path" in comment
    assert "No action required" in comment


def test_build_pr_comment_uncertain():
    v = _make_verdict(
        "uncertain", "medium",
        dynamic_blockers=["main.py:5 [getattr] getattr(lib, name)"],
        explanation="Uncertain",
    )
    comment = build_pr_comment(v)
    assert "- **Verdict:** uncertain" in comment
    assert "Dynamic blockers" in comment
    assert "getattr" in comment
    assert "Manual review required" in comment


# ------------------------------------------------------------------ rule-based replies


def test_reachable_reply_quotes_call_path():
    analyzer, project_path, call_graph = _build_analyzer("app_reachable")
    call_path = [
        PathHop(file="main.py", line=3, function="app_reachable.main.<module>"),
        PathHop(file="lib.py", line=1, function="lib.vulnerable_function"),
    ]
    v = _make_verdict("reachable", "high", call_path=call_path,
                      explanation="Reachable")
    agent = _agent_for(v, analyzer, project_path, call_graph)
    reply = agent.respond("Is the vuln reachable?")
    assert "REACHABLE" in reply
    assert "main.py:3" in reply
    assert "lib.vulnerable_function" in reply


def test_not_reachable_reply_no_path():
    analyzer, project_path, call_graph = _build_analyzer("app_not_reachable")
    v = _make_verdict("not_reachable", "high", explanation="Not reachable")
    agent = _agent_for(v, analyzer, project_path, call_graph)
    reply = agent.respond("Is it reachable?")
    assert "NOT reachable" in reply
    assert "no static call path" in reply.lower()


def test_uncertain_reply_lists_blockers():
    analyzer, project_path, call_graph = _build_analyzer("app_dynamic")
    v = _make_verdict(
        "uncertain", "medium",
        dynamic_blockers=["main.py:5 [getattr] getattr(lib, <non-literal>)"],
        explanation="Uncertain",
    )
    agent = _agent_for(v, analyzer, project_path, call_graph)
    reply = agent.respond("Is it reachable?")
    assert "UNCERTAIN" in reply
    assert "getattr" in reply
    assert "cannot rule out" in reply.lower()


# ------------------------------------------------------------------ challenge not_reachable


def test_challenge_not_reachable_stays_not_reachable():
    analyzer, project_path, call_graph = _build_analyzer("app_not_reachable")
    v = _make_verdict("not_reachable", "high", explanation="Not reachable")
    agent = _agent_for(v, analyzer, project_path, call_graph)
    reply = agent.respond("I think lib.vulnerable_function is reachable — check again.")
    assert "not_reachable" in reply.lower() or "not reachable" in reply.lower()
    # Agent never flips to reachable without evidence.


def test_never_claims_certainty_without_evidence():
    analyzer, project_path, call_graph = _build_analyzer("app_dynamic")
    v = _make_verdict("uncertain", "medium", dynamic_blockers=["x:1 getattr"],
                      explanation="Uncertain")
    agent = _agent_for(v, analyzer, project_path, call_graph)
    reply = agent.respond("Is it safe?")
    assert "uncertain" in reply.lower()
    assert "cannot rule out" in reply.lower()


# ------------------------------------------------------------------ user assumptions


def test_user_assumption_recorded_and_dependency_stated():
    analyzer, project_path, call_graph = _build_analyzer("app_dynamic")
    v = _make_verdict(
        "uncertain", "medium",
        dynamic_blockers=["main.py:5 [getattr] getattr(lib, <non-literal>)"],
        explanation="Uncertain",
    )
    agent = _agent_for(v, analyzer, project_path, call_graph)
    reply = agent.respond("That getattr only ever receives 'safe_load' from config.")
    assert "assumption" in reply.lower()
    assert "safe_load" in reply
    assert "depends" in reply.lower()
    assert len(agent.assumptions) == 1
    assert agent.assumptions[0].assumption == "That getattr only ever receives 'safe_load' from config."


# ------------------------------------------------------------------ LLMClient interface


def test_llm_client_is_abstract():
    with pytest.raises(TypeError):
        LLMClient()


def test_rule_based_client_works_without_llm():
    analyzer, project_path, call_graph = _build_analyzer("app_reachable")
    call_path = [PathHop(file="main.py", line=3, function="main.<module>")]
    v = _make_verdict("reachable", "high", call_path=call_path)
    agent = _agent_for(v, analyzer, project_path, call_graph)
    client = RuleBasedLLMClient(agent)
    reply = client.chat([{"role": "user", "content": "Is it reachable?"}])
    assert "REACHABLE" in reply
