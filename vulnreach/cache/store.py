"""SQLite cache for VulnReach analysis results.

Caches, keyed by ``package@version``:

* (a) ``advisory -> vulnerable functions`` — the resolved fix commit
  (resolution method, sha, confidence) plus the list of vulnerable functions
  and the ``functions_unknown`` flag.
* (b) ``the package's internal call graph`` serialized as JSON.

Hash-based invalidation incorporates ``package@version`` together with the
analyzer version, so a new analyzer version automatically invalidates stale
entries.  Cache hits are logged so operators can see reuse in action.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("vulnreach.cache")

ANALYZER_VERSION = "1.0.0"

SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cache_kind ON cache(kind);
"""


class CacheStore:
    """Persistent sqlite cache for analysis results."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        analyzer_version: str = ANALYZER_VERSION,
        enabled: bool = True,
    ) -> None:
        self.enabled = enabled
        self.analyzer_version = analyzer_version
        if self.enabled:
            self.db_path = Path(db_path) if db_path else Path.home() / ".cache" / "vulnreach" / "store.sqlite"
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_db()
        else:
            self.db_path = None

    # ------------------------------------------------------------------ schema

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(SCHEMA)

    # ------------------------------------------------------------------ keys / hashing

    @staticmethod
    def content_hash(package: str, version: str, analyzer_version: str) -> str:
        """Content hash derived from package@version + analyzer version."""
        payload = f"{package}@{version}|{analyzer_version}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _make_key(self, package: str, version: str, kind: str, advisory_id: str | None = None) -> str:
        suffix = f"#{advisory_id}" if advisory_id else ""
        return f"{package}@{version}#{kind}{suffix}"

    def _expected_hash(self, package: str, version: str) -> str:
        return self.content_hash(package, version, self.analyzer_version)

    # ------------------------------------------------------------------ get / put

    def get(
        self,
        package: str,
        version: str,
        kind: str,
        advisory_id: str | None = None,
    ) -> Any | None:
        """Return cached value, or ``None`` on miss / invalidation."""
        if not self.enabled:
            return None
        key = self._make_key(package, version, kind, advisory_id)
        expected_hash = self._expected_hash(package, version)
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT value, analyzer_version, content_hash FROM cache WHERE key = ?",
                    (key,),
                ).fetchone()
        except sqlite3.Error:
            return None
        if row is None:
            logger.info("cache miss: %s", key)
            return None
        value, stored_av, stored_hash = row
        if stored_av != self.analyzer_version or stored_hash != expected_hash:
            logger.info("cache invalidated (analyzer version/hash mismatch): %s", key)
            self._delete(key)
            return None
        logger.info("cache hit: %s", key)
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None

    def put(
        self,
        package: str,
        version: str,
        kind: str,
        value: Any,
        advisory_id: str | None = None,
    ) -> None:
        """Persist ``value`` (JSON-serializable) in the cache."""
        if not self.enabled:
            return
        key = self._make_key(package, version, kind, advisory_id)
        content_hash = self._expected_hash(package, version)
        payload = json.dumps(value, default=str)
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO cache "
                    "(key, kind, value, analyzer_version, content_hash, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (key, kind, payload, self.analyzer_version, content_hash, time.time()),
                )
        except sqlite3.Error:
            pass

    def _delete(self, key: str) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM cache WHERE key = ?", (key,))
        except sqlite3.Error:
            pass

    # ------------------------------------------------------------------ graph helpers

    @staticmethod
    def serialize_graph(
        nodes: list[dict[str, Any]], edges: list[dict[str, Any]]
    ) -> dict[str, Any]:
        return {"nodes": nodes, "edges": edges}

    @staticmethod
    def deserialize_graph(
        data: Any,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        if not data:
            return [], []
        return data.get("nodes", []), data.get("edges", [])
