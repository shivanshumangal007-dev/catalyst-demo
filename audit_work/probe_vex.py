"""Phase 3 probe: validate generated OpenVEX against the published JSON schema."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import jsonschema  # noqa: E402

from vulnreach.models import Alert, PathHop, Verdict  # noqa: E402
from vulnreach.vex.openvex import (  # noqa: E402
    NOT_AFFECTED_JUSTIFICATIONS,
    build_document,
    build_statement,
)

SCHEMA = Path(__file__).resolve().parent / "openvex_schema.json"
SPEC_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}


def verdict(status: str, package: str = "PyYAML", version: str = "5.4") -> Verdict:
    return Verdict(
        alert=Alert(package=package, version=version, advisory_id="GHSA-test-0000-0000"),
        status=status,  # type: ignore[arg-type]
        confidence="high",
        call_path=[PathHop(file="main.py", line=3, function="main")] if status == "reachable" else [],
        reasons=["fixture reason"],
        dynamic_blockers=["main.py:9 [getattr] getattr(obj, <non-literal>)"] if status == "uncertain" else [],
        explanation="fixture",
    )


if __name__ == "__main__":
    schema = json.loads(SCHEMA.read_text())
    doc = build_document(
        [verdict("reachable"), verdict("not_reachable"), verdict("uncertain")],
        author="vulnreach", project_purl="pkg:pypi/demo@1.0.0",
    )
    print("generated document:")
    print(json.dumps(doc, indent=2)[:1400])
    print("...")

    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(doc))
    print("SCHEMA:", "VALID" if not errors else f"INVALID ({len(errors)} errors)")
    for exc in errors:
        print("  path:", "/".join(str(p) for p in exc.absolute_path) or "<root>")
        print("   ", exc.message)

    print("\nper-status validation:")
    for status in ("reachable", "not_reachable", "uncertain"):
        one = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "urn:uuid:00000000-0000-0000-0000-000000000000",
            "author": "vulnreach",
            "timestamp": "2026-01-01T00:00:00Z",
            "version": 1,
            "statements": [build_statement(verdict(status), "pkg:pypi/demo@1.0.0")],
        }
        errs = list(jsonschema.Draft202012Validator(schema).iter_errors(one))
        print(f"  {status:14s}: {len(errs)} schema error(s)")
        for e in errs:
            print("    -", "/".join(str(p) for p in e.absolute_path) or "<root>", "|", e.message)

    stmt = build_statement(verdict("not_reachable"), "pkg:pypi/demo@1.0.0")
    print("\nnot_affected justification emitted:", stmt["justification"])
    print("allowed by code:", sorted(NOT_AFFECTED_JUSTIFICATIONS))
    print("spec labels:   ", sorted(SPEC_JUSTIFICATIONS))
    print("extra in code: ", sorted(NOT_AFFECTED_JUSTIFICATIONS - SPEC_JUSTIFICATIONS))
    print("missing in code:", sorted(SPEC_JUSTIFICATIONS - NOT_AFFECTED_JUSTIFICATIONS))

    print("\nstatement shape:")
    print("  vulnerability type:", type(stmt["vulnerability"]).__name__)
    print("  products types:   ", [type(p).__name__ for p in stmt["products"]])
    print("  subcomponents:    ", stmt.get("subcomponents"))
    print("  top-level subcomponents key present:", "subcomponents" in stmt)
    print("  purl emitted:     ", stmt["subcomponents"][0] if stmt.get("subcomponents") else None)

    # Purl normalization checks (PEP 503-style).
    for pkg in ("PyYAML", "zope.interface", "my_pkg"):
        s = build_statement(verdict("reachable", package=pkg), "pkg:pypi/demo@1.0.0")
        print(f"  purl for {pkg!r}: {s['subcomponents'][0]}")
