"""Cache integration tests for the CLI pipeline."""

from __future__ import annotations

import importlib.metadata
import json
from pathlib import Path

import pytest

from vulnreach.cache.store import CacheStore
from vulnreach.cli import _run_pipeline

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _write_alerts(tmp_path, package="lib", version="1.0.0", advisory_id="TEST-1"):
    alerts_file = tmp_path / "alerts.json"
    alerts_file.write_text(
        json.dumps([{"package": package, "version": version, "advisory_id": advisory_id}])
    )
    with alerts_file.open() as f:
        return json.load(f)


def test_pipeline_stores_and_reuses_advisory_cache(tmp_path, caplog):
    project = FIXTURES / "app_reachable"
    alerts = _write_alerts(tmp_path)

    cache_db = tmp_path / "cache.sqlite"
    store1 = CacheStore(db_path=cache_db)
    verdicts1, _, _ = _run_pipeline(project, alerts, store1)
    # First run: no cache hit; functions_unknown because no OSV record for TEST-1.
    assert verdicts1[0].status == "uncertain"

    # Second run with a fresh store on the same db -> cache hit.
    store2 = CacheStore(db_path=cache_db)
    with caplog.at_level("INFO", logger="vulnreach.cache"):
        verdicts2, _, _ = _run_pipeline(project, alerts, store2)
    assert any("cache hit" in r.getMessage() for r in caplog.records)
    assert verdicts2[0].status == verdicts1[0].status


def test_no_cache_bypasses_store(tmp_path):
    project = FIXTURES / "app_reachable"
    alerts = _write_alerts(tmp_path)
    store = CacheStore(enabled=False)
    verdicts, _, _ = _run_pipeline(project, alerts, store)
    assert verdicts[0].status == "uncertain"


# ------------------------------------------------------------------ F-06: cold/warm cache equivalence


def test_cold_and_warm_cache_agree(tmp_path, monkeypatch):
    """Cold and warm cache runs must produce identical verdicts (F-06)."""
    # Set up a dependency package with a vulnerable function.
    dep = tmp_path / "mydep"
    (dep / "__init__.py").parent.mkdir(parents=True)
    (dep / "__init__.py").write_text("")
    (dep / "core.py").write_text("def vulnerable():\n    return 1\n")
    (dep / "api.py").write_text("from .core import vulnerable\ndef public():\n    return vulnerable()\n")
    project = tmp_path / "proj"
    project.mkdir()
    (project / "main.py").write_text("from mydep.api import public\npublic()\n")

    alerts = [
        {"package": "mydep", "version": "1.0.0", "advisory_id": "ADV-1"},
    ]

    class FakeDist:
        def locate_file(self, rel):
            return dep / rel

    monkeypatch.setattr(
        "importlib.metadata.distribution", lambda name: FakeDist()
        if name == "mydep"
        else (_ for _ in ()).throw(
            importlib.metadata.PackageNotFoundError(name)
        ),
    )

    cache_db = tmp_path / "cache.sqlite"

    # Cold run.
    store_cold = CacheStore(db_path=cache_db)
    verdicts_cold, _, _ = _run_pipeline(project, alerts, store_cold)

    # Warm run with the same cache db.
    store_warm = CacheStore(db_path=cache_db)
    verdicts_warm, _, _ = _run_pipeline(project, alerts, store_warm)

    # Verdicts must be identical.
    assert [v.status for v in verdicts_cold] == [v.status for v in verdicts_warm]
    assert [v.confidence for v in verdicts_cold] == [
        v.confidence for v in verdicts_warm
    ]


# ------------------------------------------------------------------ F-15: multi-alert packages all in graph


def test_multi_alert_all_packages_in_graph(tmp_path, monkeypatch):
    """Every alert package must be in the call graph, not just the first."""
    # Set up two dependency packages, each with a vulnerable function.
    for pkg_name in ("depa", "depb"):
        p = tmp_path / pkg_name
        p.mkdir(parents=True)
        (p / "__init__.py").write_text("")
        (p / "core.py").write_text(f"def {pkg_name}_vuln():\n    return 1\n")
        (p / "api.py").write_text(
            f"from .core import {pkg_name}_vuln\ndef public():\n    return {pkg_name}_vuln()\n"
        )
    project = tmp_path / "proj"
    project.mkdir()
    (project / "main.py").write_text(
        "from depa.api import public as a\nfrom depb.api import public as b\na()\nb()\n"
    )

    alerts = [
        {"package": "depa", "version": "1.0.0", "advisory_id": "ADV-depa"},
        {"package": "depb", "version": "1.0.0", "advisory_id": "ADV-depb"},
    ]

    class FakeDist:
        def __init__(self, base):
            self.base = base

        def locate_file(self, rel):
            return self.base / rel

    dists = {"depa": FakeDist(tmp_path / "depa"), "depb": FakeDist(tmp_path / "depb")}

    def fake_dist(name):
        if name in dists:
            return dists[name]
        import importlib.metadata

        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr("importlib.metadata.distribution", fake_dist)

    # Pre-populate the cache with advisory functions so functions_unknown=False.
    cache_db = tmp_path / "cache.sqlite"
    store = CacheStore(db_path=cache_db)
    FIX_COMMIT = {
        "repo_url": "https://github.com/example/dep",
        "sha": "a" * 40,
        "resolution_method": "direct_link",
        "confidence": 0.95,
    }
    for pkg_name in ("depa", "depb"):
        store.put(
            pkg_name,
            "1.0.0",
            "advisory_functions",
            {
                "fix_commit": FIX_COMMIT,
                "vulnerable_functions": [
                    {
                        "module": f"{pkg_name}.core",
                        "qualified_name": f"{pkg_name}.core.{pkg_name}_vuln",
                        "file_path": f"{pkg_name}/core.py",
                        "confidence": 0.95,
                    }
                ],
                "functions_unknown": False,
            },
            advisory_id=f"ADV-{pkg_name}",
        )

    verdicts, _, call_graph = _run_pipeline(project, alerts, store)

    # Both packages must appear in the graph.
    all_qualnames = {n.qualname for n in call_graph.graph.nodes}
    assert any("depa." in q for q in all_qualnames), "depa missing from graph"
    assert any("depb." in q for q in all_qualnames), "depb missing from graph"

    # Both verdicts must be reachable (both packages are called).
    assert [v.status for v in verdicts] == ["reachable", "reachable"]


# ------------------------------------------------------------------ F-06: cold/warm equivalence with an override (no network)


def test_override_cold_warm_byte_identical(tmp_path, monkeypatch, caplog):
    """Cold and warm cache runs on an override-based fixture must produce
    byte-identical verdicts, and the warm run must log a cache hit.

    The override (``--vuln-functions``) bypasses OSV/fix-commit/diff, so the
    only thing cached across runs is the dependency call graph.  A warm run
    must therefore log a "cache hit" for the dependency callgraph and emit the
    exact same verdicts as the cold run.  (F-06)
    """
    # dependency: dep.api.public -> dep.core.vulnerable
    dep_root = tmp_path / "dep_root"
    (dep_root / "dep").mkdir(parents=True)
    (dep_root / "dep" / "__init__.py").write_text("")
    (dep_root / "dep" / "core.py").write_text("def vulnerable():\n    return 1\n")
    (dep_root / "dep" / "api.py").write_text(
        "from .core import vulnerable\ndef public():\n    return vulnerable()\n"
    )
    project = tmp_path / "proj"
    project.mkdir()
    (project / "main.py").write_text("from dep.api import public\npublic()\n")

    alerts = [
        {"package": "dep", "version": "1.0.0", "advisory_id": "A-1"},
    ]
    overrides = {"A-1": ["dep.core.vulnerable"]}

    class FakeDist:
        def locate_file(self, rel):
            return dep_root / rel

    monkeypatch.setattr(
        "importlib.metadata.distribution",
        lambda name: FakeDist() if name == "dep" else (_ for _ in ()).throw(
            importlib.metadata.PackageNotFoundError(name)
        ),
    )

    cache_db = tmp_path / "cache.sqlite"

    # Cold run: fresh cache, dependency graph built and stored.
    store_cold = CacheStore(db_path=cache_db)
    verdicts_cold, _, _ = _run_pipeline(
        project, alerts, store_cold, cache_enabled=True,
        vuln_functions_overrides=overrides,
    )
    cold_bytes = json.dumps(
        [v.model_dump() for v in verdicts_cold], sort_keys=True
    ).encode("utf-8")
    assert verdicts_cold[0].status == "reachable"

    # Warm run: same cache db -> dependency callgraph cache hit.
    store_warm = CacheStore(db_path=cache_db)
    with caplog.at_level("INFO", logger="vulnreach.cache"):
        verdicts_warm, _, _ = _run_pipeline(
            project, alerts, store_warm, cache_enabled=True,
            vuln_functions_overrides=overrides,
        )
    warm_bytes = json.dumps(
        [v.model_dump() for v in verdicts_warm], sort_keys=True
    ).encode("utf-8")

    assert warm_bytes == cold_bytes, "warm cache changed the verdicts"
    assert verdicts_warm[0].status == "reachable"
    assert any("cache hit" in r.getMessage() for r in caplog.records), "expected a cache hit on the warm run"

