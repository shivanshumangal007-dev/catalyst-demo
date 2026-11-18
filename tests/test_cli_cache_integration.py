"""Cache integration tests for the CLI pipeline."""

from __future__ import annotations

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
