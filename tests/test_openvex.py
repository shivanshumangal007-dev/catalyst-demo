"""Tests for OpenVEX document generation and validation rules."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import pytest

from vulnreach.models import Alert, PathHop, Verdict
from vulnreach.vex.openvex import build_document, build_statement, write_vex


def _reachable_verdict() -> Verdict:
    return Verdict(
        alert=Alert(package="requests", version="2.25.0", advisory_id="GHSA-1"),
        status="reachable",
        confidence="high",
        call_path=[
            PathHop(file="main.py", line=5, function="app.main"),
            PathHop(file="lib.py", line=10, function="lib.vulnerable_fn"),
        ],
        reasons=["call path from app.main to lib.vulnerable_fn"],
        dynamic_blockers=[],
        explanation="Reachable: static call path found",
    )


def _not_reachable_verdict() -> Verdict:
    return Verdict(
        alert=Alert(package="django", version="3.1.0", advisory_id="CVE-2021-0001"),
        status="not_reachable",
        confidence="high",
        call_path=[],
        reasons=["no call path to vulnerable code"],
        dynamic_blockers=[],
        explanation="Not reachable: no static call path",
    )


def _uncertain_verdict() -> Verdict:
    return Verdict(
        alert=Alert(package="yaml", version="6.0", advisory_id="PYSEC-1"),
        status="uncertain",
        confidence="medium",
        call_path=[],
        reasons=["no static call path"],
        dynamic_blockers=["main.py:12 [getattr] getattr(lib, name)"],
        explanation="Uncertain: dynamic features may hide a path",
    )


PROJECT_PURL = "pkg:pypi/demo-app@1.0.0"


# ------------------------------------------------------------------ build_statement


def test_reachable_maps_to_affected_with_action_statement():
    stmt = build_statement(_reachable_verdict(), PROJECT_PURL)
    assert stmt["status"] == "affected"
    assert stmt["products"] == [PROJECT_PURL]
    assert stmt["subcomponents"] == ["pkg:pypi/requests@2.25.0"]
    assert stmt["vulnerability"] == "GHSA-1"
    assert "action_statement" in stmt
    assert "Upgrade requests" in stmt["action_statement"]
    assert "app.main@main.py:5" in stmt["action_statement"]
    assert "lib.vulnerable_fn@lib.py:10" in stmt["action_statement"]
    assert stmt.get("impact_statement") == "app.main@main.py:5 -> lib.vulnerable_fn@lib.py:10"


def test_not_reachable_maps_to_not_affected_with_justification():
    stmt = build_statement(_not_reachable_verdict(), PROJECT_PURL)
    assert stmt["status"] == "not_affected"
    assert stmt["justification"] == "vulnerable_code_not_in_execute_path"
    assert "impact_statement" in stmt
    assert stmt["subcomponents"] == ["pkg:pypi/django@3.1.0"]


def test_uncertain_maps_to_under_investigation_with_status_notes():
    stmt = build_statement(_uncertain_verdict(), PROJECT_PURL)
    assert stmt["status"] == "under_investigation"
    assert "status_notes" in stmt
    assert "getattr" in stmt["status_notes"]
    assert "main.py:12" in stmt["status_notes"]


def test_purl_without_version():
    from vulnreach.vex.openvex import _purl

    assert _purl("requests") == "pkg:pypi/requests"
    assert _purl("requests", "2.25.0") == "pkg:pypi/requests@2.25.0"


# ------------------------------------------------------------------ validation


def test_affected_without_action_statement_raises():
    v = _reachable_verdict()
    # Strip action_statement by building a verdict whose path is empty -> but
    # build_statement always adds action_statement for reachable.  Instead,
    # construct a raw statement dict and pass to _validate_statement via a
    # verdict that would produce an affected statement without action.
    from vulnreach.vex.openvex import _validate_statement

    with pytest.raises(ValueError, match="action_statement"):
        _validate_statement(
            {
                "vulnerability": "GHSA-1",
                "products": [PROJECT_PURL],
                "subcomponents": ["pkg:pypi/requests@2.25.0"],
                "status": "affected",
            }
        )


def test_not_affected_without_justification_raises():
    from vulnreach.vex.openvex import _validate_statement

    with pytest.raises(ValueError, match="justification"):
        _validate_statement(
            {
                "vulnerability": "GHSA-1",
                "products": [PROJECT_PURL],
                "subcomponents": ["pkg:pypi/django@3.1.0"],
                "status": "not_affected",
            }
        )


def test_not_affected_with_bad_justification_raises():
    from vulnreach.vex.openvex import _validate_statement

    with pytest.raises(ValueError, match="justification"):
        _validate_statement(
            {
                "vulnerability": "GHSA-1",
                "products": [PROJECT_PURL],
                "subcomponents": ["pkg:pypi/django@3.1.0"],
                "status": "not_affected",
                "justification": "made-up-justification",
            }
        )


# ------------------------------------------------------------------ build_document


def test_build_document_structure():
    doc = build_document(
        [_reachable_verdict(), _not_reachable_verdict(), _uncertain_verdict()],
        author="vulnreach",
        project_purl=PROJECT_PURL,
    )
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert doc["@id"].startswith("urn:uuid:")
    UUID(doc["@id"].split(":")[2])  # raises if not a valid UUID
    assert doc["author"] == "vulnreach"
    assert doc["timestamp"].endswith("Z")
    assert doc["version"] == 1
    assert len(doc["statements"]) == 3
    statuses = {s["status"] for s in doc["statements"]}
    assert statuses == {"affected", "not_affected", "under_investigation"}


def test_build_document_custom_id():
    doc = build_document(
        [_reachable_verdict()],
        author="audit",
        project_purl=PROJECT_PURL,
        document_id="urn:uuid:00000000-0000-0000-0000-000000000001",
    )
    assert doc["@id"] == "urn:uuid:00000000-0000-0000-0000-000000000001"
    assert doc["author"] == "audit"


# ------------------------------------------------------------------ write_vex


def test_write_vex(tmp_path):
    doc = build_document([_reachable_verdict()], author="vulnreach", project_purl=PROJECT_PURL)
    out = tmp_path / "report.vex.json"
    write_vex(out, doc)
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert len(data["statements"]) == 1


def test_write_vex_creates_parent_dirs(tmp_path):
    doc = build_document([_reachable_verdict()], author="vulnreach", project_purl=PROJECT_PURL)
    out = tmp_path / "nested" / "dir" / "report.vex.json"
    write_vex(out, doc)
    assert out.exists()
