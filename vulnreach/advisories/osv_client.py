"""Client for the OSV vulnerability database API.

Provides cached, timeout-safe access to ``https://api.osv.dev``:

* ``GET /vulns/{id}`` — fetch a single advisory by OSV ID
* ``POST /query`` — query advisories affecting a package at a version

HTTP responses are cached in a local SQLite file so repeated lookups and the
test suite never hit the network unless explicitly allowed. 404s and timeouts
are handled cleanly and return ``None``.
"""

from __future__ import annotations

import json
import sqlite3
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


OSV_BASE = "https://api.osv.dev/v1"
DEFAULT_TIMEOUT = 20


class OSVClient:
    """Thin, cached client over the OSV REST API."""

    def __init__(self, cache_db: str | Path | None = None, timeout: int = DEFAULT_TIMEOUT, enabled: bool = True) -> None:
        self.timeout = timeout
        self.enabled = enabled
        self.cache_db = Path(cache_db) if cache_db else Path.home() / ".cache" / "vulnreach" / "osv.sqlite"
        self.cache_db.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.cache_db) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS http_cache (
                    key TEXT PRIMARY KEY,
                    response TEXT NOT NULL,
                    fetched_at REAL NOT NULL
                )
                """
            )

    # ------------------------------------------------------------------ cache

    def _read_cache(self, key: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        try:
            with sqlite3.connect(self.cache_db) as conn:
                row = conn.execute(
                    "SELECT response FROM http_cache WHERE key = ?", (key,)
                ).fetchone()
            if row is None:
                return None
            return json.loads(row[0])
        except (sqlite3.Error, json.JSONDecodeError):
            return None

    def _write_cache(self, key: str, data: dict[str, Any]) -> None:
        if not self.enabled:
            return
        try:
            with sqlite3.connect(self.cache_db) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO http_cache (key, response, fetched_at) VALUES (?, ?, ?)",
                    (key, json.dumps(data), time.time()),
                )
        except sqlite3.Error:
            pass

    # ------------------------------------------------------------------ HTTP

    def _get(self, url: str) -> dict[str, Any] | None:
        """GET a URL (with sqlite cache). Returns parsed JSON or None on miss/error/404."""
        cached = self._read_cache(url)
        if cached is not None:
            return cached
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
            data = json.loads(body)
            self._write_cache(url, data)
            return data
        except urllib.error.HTTPError:
            # 404 and other HTTP errors: treat as "no advisory" rather than failing.
            return None
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            return None

    def _post(self, url: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        """POST JSON to a URL (with sqlite cache)."""
        cache_key = "POST:" + url + ":" + json.dumps(payload, sort_keys=True)
        cached = self._read_cache(cache_key)
        if cached is not None:
            return cached
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
            result = json.loads(body)
            self._write_cache(cache_key, result)
            return result
        except urllib.error.HTTPError:
            return None
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            return None

    # ------------------------------------------------------------------ public API

    def fetch_advisory(self, advisory_id: str) -> dict[str, Any] | None:
        """Fetch a single advisory by OSV ID.

        Returns ``None`` on 404, network error, or invalid JSON.
        """
        url = f"{OSV_BASE}/vulns/{advisory_id}"
        return self._get(url)

    def query_by_package(self, package: str, version: str) -> dict[str, Any] | None:
        """Query advisories affecting ``package`` at ``version`` via POST /query."""
        url = f"{OSV_BASE}/query"
        payload = {
            "package": {"ecosystem": "PyPI", "name": package},
            "version": version,
        }
        return self._post(url, payload)

    @staticmethod
    def extract_advisory_data(record: dict[str, Any]) -> dict[str, Any]:
        """Extract aliases, reference URLs, and affected ranges from an OSV record."""
        aliases = record.get("aliases") or []
        references = record.get("references") or []
        reference_urls = [ref.get("url") for ref in references if ref.get("url")]
        return {
            "advisory_id": record.get("id"),
            "aliases": list(aliases),
            "references": references,
            "reference_urls": [u for u in reference_urls if u],
            "summary": record.get("summary", ""),
            "details": record.get("details", ""),
            "affected": record.get("affected", []) or [],
        }
