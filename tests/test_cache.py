"""Tests for the SQLite cache store."""

from __future__ import annotations

import logging

import pytest

from vulnreach.cache.store import CacheStore


def test_put_get_roundtrip(tmp_path):
    store = CacheStore(db_path=tmp_path / "store.sqlite")
    value = {
        "fix_commit": {"sha": "abc", "resolution_method": "direct_link", "confidence": 0.95},
        "vulnerable_functions": [{"qualified_name": "lib.vuln"}],
        "functions_unknown": False,
    }
    store.put("requests", "2.25.0", "advisory_functions", value, advisory_id="GHSA-1")
    got = store.get("requests", "2.25.0", "advisory_functions", advisory_id="GHSA-1")
    assert got == value


def test_get_miss_returns_none(tmp_path):
    store = CacheStore(db_path=tmp_path / "store.sqlite")
    assert store.get("requests", "2.25.0", "advisory_functions", advisory_id="GHSA-1") is None


def test_callgraph_serialize_deserialize():
    nodes = [{"qualname": "lib.vuln", "file": "lib.py", "line": 5}]
    edges = [{"source": "app.main", "target": "lib.vuln", "over_approx": False}]
    data = CacheStore.serialize_graph(nodes, edges)
    back_nodes, back_edges = CacheStore.deserialize_graph(data)
    assert back_nodes == nodes
    assert back_edges == edges


def test_get_invalidated_by_analyzer_version(tmp_path):
    store_v1 = CacheStore(db_path=tmp_path / "store.sqlite", analyzer_version="1.0.0")
    store_v1.put("requests", "2.25.0", "advisory_functions", {"x": 1}, advisory_id="GHSA-1")
    # New analyzer version -> cache should be invalidated (miss).
    store_v2 = CacheStore(db_path=tmp_path / "store.sqlite", analyzer_version="2.0.0")
    assert store_v2.get("requests", "2.25.0", "advisory_functions", advisory_id="GHSA-1") is None


def test_disable_cache(tmp_path):
    store = CacheStore(db_path=tmp_path / "store.sqlite", enabled=False)
    store.put("requests", "2.25.0", "advisory_functions", {"x": 1}, advisory_id="GHSA-1")
    assert store.get("requests", "2.25.0", "advisory_functions", advisory_id="GHSA-1") is None


def test_cache_hit_logged(tmp_path, caplog):
    store = CacheStore(db_path=tmp_path / "store.sqlite")
    store.put("requests", "2.25.0", "advisory_functions", {"x": 1}, advisory_id="GHSA-1")
    with caplog.at_level(logging.INFO, logger="vulnreach.cache"):
        store.get("requests", "2.25.0", "advisory_functions", advisory_id="GHSA-1")
    assert any("cache hit" in r.getMessage() for r in caplog.records)


def test_content_hash_includes_version():
    h1 = CacheStore.content_hash("requests", "2.25.0", "1.0.0")
    h2 = CacheStore.content_hash("requests", "2.25.0", "2.0.0")
    h3 = CacheStore.content_hash("requests", "2.24.0", "1.0.0")
    assert h1 != h2
    assert h1 != h3
