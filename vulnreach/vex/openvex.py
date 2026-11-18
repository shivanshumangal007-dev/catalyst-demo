"""OpenVEX document generation for VulnReach.

Maps :class:`VulnReach.models.Verdict` to OpenVEX v0.2.0 statements:

* ``reachable``   -> status ``affected``      (action_statement = upgrade advice + call path)
* ``not_reachable`` -> status ``not_affected`` (justification = vulnerable_code_not_in_execute_path)
* ``uncertain``   -> status ``under_investigation`` (status_notes = which dynamic feature blocks certainty)

Products and subcomponents use purl: ``pkg:pypi/<name>@<version>``.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vulnreach.models import Verdict

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

# Justifications allowed for status "not_affected" per OpenVEX v0.2.0.
NOT_AFFECTED_JUSTIFICATIONS = {
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_not_present",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_protections_already_in_place",
    "other",
}


def _purl(package: str, version: str | None = None) -> str:
    if version:
        return f"pkg:pypi/{package}@{version}"
    return f"pkg:pypi/{package}"


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_statement(verdict: Verdict, project_purl: str) -> dict[str, Any]:
    """Build a single OpenVEX statement from a :class:`Verdict`."""
    alert = verdict.alert
    subcomponent_purl = _purl(alert.package, alert.version)

    statement: dict[str, Any] = {
        "vulnerability": alert.advisory_id,
        "products": [project_purl],
        "subcomponents": [subcomponent_purl],
    }

    if verdict.status == "reachable":
        statement["status"] = "affected"
        path_evidence = (
            " -> ".join(f"{h.function}@{h.file}:{h.line}" for h in verdict.call_path)
            if verdict.call_path
            else "no path recorded"
        )
        statement["action_statement"] = (
            f"Upgrade {alert.package} from {alert.version} to a patched version. "
            f"Vulnerable code is reachable via: {path_evidence}"
        )
        if verdict.call_path:
            statement["impact_statement"] = path_evidence

    elif verdict.status == "not_reachable":
        statement["status"] = "not_affected"
        statement["justification"] = "vulnerable_code_not_in_execute_path"
        statement["impact_statement"] = (
            "; ".join(verdict.reasons)
            if verdict.reasons
            else "no call path to vulnerable code"
        )

    elif verdict.status == "uncertain":
        statement["status"] = "under_investigation"
        blockers = (
            "; ".join(verdict.dynamic_blockers)
            if verdict.dynamic_blockers
            else "dynamic features may hide a call path"
        )
        statement["status_notes"] = blockers
        statement["impact_statement"] = (
            "; ".join(verdict.reasons)
            if verdict.reasons
            else "reachability could not be determined"
        )

    _validate_statement(statement)
    return statement


def _validate_statement(statement: dict[str, Any]) -> None:
    """Validate statement-level OpenVEX requirements; raise on violation."""
    status = statement.get("status")
    if status == "not_affected":
        justification = statement.get("justification")
        if not justification or justification not in NOT_AFFECTED_JUSTIFICATIONS:
            raise ValueError(
                'not_affected statement must have a justification from '
                f"{sorted(NOT_AFFECTED_JUSTIFICATIONS)}, got {justification!r}"
            )
    if status == "affected":
        if not statement.get("action_statement"):
            raise ValueError("affected statement must have an action_statement")


def build_document(
    verdicts: list[Verdict],
    author: str,
    project_purl: str,
    document_id: str | None = None,
) -> dict[str, Any]:
    """Build a complete OpenVEX v0.2.0 document."""
    statements = [build_statement(v, project_purl) for v in verdicts]
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": document_id or f"urn:uuid:{uuid.uuid4()}",
        "author": author,
        "timestamp": _iso_now(),
        "version": 1,
        "statements": statements,
    }


def write_vex(path: str | Path, document: dict[str, Any]) -> None:
    """Write an OpenVEX document to ``path`` as pretty JSON."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(document, indent=2), encoding="utf-8")
