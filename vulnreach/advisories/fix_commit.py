"""Resolve a fix commit from an OSV advisory record.

Resolution order (first match wins):

1. ``direct_link`` (confidence 0.95): a GIT range event ``fixed`` value, or a
   reference of type ``FIX``/``WEB``/``ADVISORY`` that contains ``/commit/<sha>``.
2. ``pr_reference`` (confidence 0.70): a reference pointing at a GitHub pull
   request or issue; the merge commit is resolved via the GitHub API.
3. ``tag_diff`` (confidence 0.50): compare the git tags of the last-vulnerable
   and first-fixed releases using :mod:`packaging.version`.
4. ``not_found``: return ``None`` sha.

An optional ``GITHUB_TOKEN`` env var is used for GitHub API calls. All HTTP
responses are cached in a local SQLite file.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from packaging.version import Version, InvalidVersion

from vulnreach.models import FixCommit

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
COMMIT_URL_RE = re.compile(r"/commit/([0-9a-fA-F]{5,40})")
BARE_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
GITHUB_URL_RE = re.compile(r"^https?://github.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:/.*)?$")
PACKAGE_REF_RE = re.compile(r"github.com/([^/]+)/([^/]+?)(?:\.git)?/?$")

# Reference types that may carry a direct commit URL.
DIRECT_REF_TYPES = {"FIX", "WEB", "ADVISORY"}

logger = logging.getLogger("vulnreach.fix_commit")


class FixCommitResolver:
    """Resolve the fix commit for an OSV advisory record."""

    def __init__(self, cache_db: str | Path | None = None, enabled: bool = True) -> None:
        self.cache_db = Path(cache_db) if cache_db else Path.home() / ".cache" / "vulnreach" / "fixcommit.sqlite"
        self.enabled = enabled
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

    # ------------------------------------------------------------------ entry point

    def resolve(self, record: dict[str, Any]) -> FixCommit:
        """Return the best-effort fix commit for ``record``."""
        advisory_id = record.get("id", "<unknown>")
        repo_url = self._repo_url_from_record(record)
        logger.info(
            "fix_commit.resolve %s: repo_url=%s, refs=%s",
            advisory_id,
            repo_url,
            [ref.get("url") for ref in (record.get("references") or []) if ref.get("url")],
        )
        result = self._direct_link(record)
        if result is not None:
            logger.info("fix_commit.resolve %s -> direct_link %s (confidence 0.95)", advisory_id, result.sha)
            return result
        result = self._pr_reference(record)
        if result is not None:
            logger.info("fix_commit.resolve %s -> pr_reference %s (confidence 0.70)", advisory_id, result.sha)
            return result
        result = self._tag_diff(record)
        if result is not None:
            logger.info("fix_commit.resolve %s -> tag_diff %s (confidence 0.50)", advisory_id, result.sha)
            return result
        logger.warning("fix_commit.resolve %s -> not_found (no fix commit could be resolved)", advisory_id)
        return FixCommit(resolution_method="not_found", confidence=0.0)

    # ------------------------------------------------------------------ method 1: direct link

    def _direct_link(self, record: dict[str, Any]) -> FixCommit | None:
        """Find a fix commit embedded directly in the OSV record."""
        affected = record.get("affected") or []
        repo_url = self._repo_url_from_record(record)

        for aff in affected:
            if repo_url is None:
                repo_url = self._repo_url_from_affected(aff)
            for rng in aff.get("ranges") or []:
                if rng.get("type") != "GIT":
                    continue
                for event in rng.get("events") or []:
                    fixed = event.get("fixed")
                    sha = self._sha_from_fixed_event(fixed)
                    if sha:
                        logger.info(
                            "direct_link: GIT range fixed event -> sha=%s repo=%s", sha, repo_url
                        )
                        return FixCommit(
                            repo_url=repo_url,
                            sha=sha,
                            resolution_method="direct_link",
                            confidence=0.95,
                        )
            if not any(rng.get("type") == "GIT" for rng in aff.get("ranges") or []):
                logger.debug("direct_link: no GIT range in affected entry")

        # Any reference of type FIX / WEB / ADVISORY containing /commit/<sha>.
        for ref in record.get("references") or []:
            ref_type = ref.get("type", "").upper()
            url = ref.get("url") or ""
            if ref_type not in DIRECT_REF_TYPES:
                continue
            m = COMMIT_URL_RE.search(url)
            if m:
                resolved_repo = self._github_repo_url(url) or repo_url
                logger.info(
                    "direct_link: %s reference commit URL %s -> sha=%s repo=%s",
                    ref_type, url, m.group(1), resolved_repo,
                )
                return FixCommit(
                    repo_url=resolved_repo,
                    sha=m.group(1),
                    resolution_method="direct_link",
                    confidence=0.95,
                )
            logger.debug("direct_link: %s reference %s has no /commit/<sha>", ref_type, url)
        logger.debug("direct_link: no GIT fixed event or commit reference found")
        return None

    @staticmethod
    def _sha_from_fixed_event(fixed: Any) -> str | None:
        if not isinstance(fixed, str):
            return None
        m = COMMIT_URL_RE.search(fixed)
        if m:
            return m.group(1)
        if BARE_SHA_RE.match(fixed):
            return fixed
        return None

    @staticmethod
    def _repo_url_from_affected(aff: dict[str, Any]) -> str | None:
        """Extract repo URL from an affected entry, including PACKAGE refs."""
        repo = aff.get("package", {}).get("repository")
        if repo:
            return repo
        # PACKAGE reference URL (e.g. GitHub repository of the package).
        for ref in aff.get("references") or []:
            if ref.get("type", "").upper() == "PACKAGE":
                url = ref.get("url") or ""
                m = PACKAGE_REF_RE.search(url)
                if m:
                    return f"https://github.com/{m.group(1)}/{m.group(2)}"
        return None

    # ------------------------------------------------------------------ method 2: PR / issue reference

    def _pr_reference(self, record: dict[str, Any]) -> FixCommit | None:
        """Resolve a fix commit via a GitHub PR/issue reference."""
        for ref in record.get("references") or []:
            url = ref.get("url") or ""
            parsed = self._parse_github_pr_issue(url)
            if parsed is None:
                continue
            owner, repo, number, kind = parsed
            sha: str | None = None
            if kind == "pull":
                sha = self._github_merge_commit(owner, repo, number)
            elif kind == "issue":
                sha = self._merge_commit_from_issue(owner, repo, number)
            if sha:
                return FixCommit(
                    repo_url=f"https://github.com/{owner}/{repo}",
                    sha=sha,
                    resolution_method="pr_reference",
                    confidence=0.7,
                )
        return None

    @staticmethod
    def _parse_github_pr_issue(url: str) -> tuple[str, str, int, str] | None:
        m = re.match(r"^https://github.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/(pull|issues)/(\d+)(?:/.*)?$", url)
        if not m:
            return None
        return m.group(1), m.group(2), int(m.group(4)), m.group(3)

    def _github_merge_commit(self, owner: str, repo: str, pr_number: int) -> str | None:
        """Return the merge commit SHA for a pull request via the GitHub API."""
        data = self._github_api_get(f"repos/{owner}/{repo}/pulls/{pr_number}/merge")
        if not data:
            return None
        sha = data.get("sha")
        return str(sha) if isinstance(sha, str) and BARE_SHA_RE.match(sha) else None

    def _merge_commit_from_issue(self, owner: str, repo: str, issue_number: int) -> str | None:
        """Best-effort: find a linked PR in an issue and return its merge commit."""
        data = self._github_api_get(f"repos/{owner}/{repo}/issues/{issue_number}")
        if not data:
            return None
        body = data.get("body") or ""
        m = re.search(r"https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/(\d+)", body)
        if not m:
            return None
        return self._github_merge_commit(owner, repo, int(m.group(1)))

    # ------------------------------------------------------------------ method 3: tag diff

    def _tag_diff(self, record: dict[str, Any]) -> FixCommit | None:
        """Best-effort fix commit from last-vulnerable / first-fixed release tags."""
        affected = record.get("affected") or []
        repo_url = self._repo_url_from_record(record)
        last_vuln: str | None = None
        first_fixed: str | None = None

        for aff in affected:
            if repo_url is None:
                repo_url = self._repo_url_from_affected(aff)
            for rng in aff.get("ranges") or []:
                if rng.get("type") != "ECOSYSTEM":
                    continue
                for event in rng.get("events") or []:
                    introduced = event.get("introduced")
                    fixed = event.get("fixed")
                    if isinstance(introduced, str):
                        last_vuln = self._max_version(last_vuln, introduced)
                    if isinstance(fixed, str):
                        first_fixed = self._min_version(first_fixed, fixed)

        if not repo_url:
            logger.warning(
                "tag_diff: no repository URL available for %s (no package.repository or PACKAGE ref); cannot clone/diff",
                record.get("id", "<unknown>"),
            )
            return None
        if not (last_vuln and first_fixed):
            logger.debug(
                "tag_diff: incomplete ecosystem range (last_vuln=%s, first_fixed=%s)",
                last_vuln,
                first_fixed,
            )
            return None

        sha = self._git_tag_diff_commit(repo_url, last_vuln, first_fixed)
        if sha is None:
            logger.warning("tag_diff: could not resolve tag diff commit for %s@%s..%s", repo_url, last_vuln, first_fixed)
            return None
        logger.info("tag_diff: resolved %s..%s -> %s", last_vuln, first_fixed, sha)
        return FixCommit(
            repo_url=repo_url,
            sha=sha,
            resolution_method="tag_diff",
            confidence=0.5,
        )

    @staticmethod
    def _parse_version(v: str) -> Version | None:
        try:
            return Version(v)
        except InvalidVersion:
            return None

    @classmethod
    def _max_version(cls, current: str | None, candidate: str) -> str:
        if current is None:
            return candidate
        cur = cls._parse_version(current)
        cand = cls._parse_version(candidate)
        if cur is None or cand is None:
            return max(current, candidate)
        return candidate if cand > cur else current

    @classmethod
    def _min_version(cls, current: str | None, candidate: str) -> str:
        if current is None:
            return candidate
        cur = cls._parse_version(current)
        cand = cls._parse_version(candidate)
        if cur is None or cand is None:
            return min(current, candidate)
        return candidate if cand < cur else current

    def _git_tag_diff_commit(self, repo_url: str, last_vuln: str, first_fixed: str) -> str | None:
        """Fetch tags and return the commit the first-fixed tag points to.

        Uses ``--no-tags`` then explicitly fetches the tags we need so a shallow
        clone still resolves tag refs.
        """
        try:
            with tempfile.TemporaryDirectory() as td:
                clone = subprocess.run(
                    ["git", "clone", "--depth", "1", "--no-single-branch", "--quiet", repo_url, td],
                    capture_output=True,
                    timeout=120,
                )
                if clone.returncode != 0:
                    return None
                # Fetch the specific tags we need (shallow clone may not include them).
                for tag in {last_vuln, first_fixed}:
                    fetch = subprocess.run(
                        ["git", "fetch", "--depth", "1", "--quiet", "--tags", repo_url, f"{tag}:{tag}"],
                        capture_output=True,
                        cwd=td,
                        timeout=60,
                    )
                    if fetch.returncode != 0:
                        return None
                rev = subprocess.run(
                    ["git", "rev-list", "-n", "1", first_fixed],
                    capture_output=True,
                    text=True,
                    cwd=td,
                    timeout=30,
                )
                if rev.returncode != 0:
                    return None
                sha = rev.stdout.strip()
                return sha or None
        except (OSError, subprocess.SubprocessError):
            return None

    # ------------------------------------------------------------------ GitHub API + helpers

    def _github_api_get(self, path: str) -> dict[str, Any] | None:
        """GET a GitHub API v3 path, cached in sqlite."""
        url = f"https://api.github.com/{path}"
        cache_key = "GH:" + url
        cached = self._read_cache(cache_key)
        if cached is not None:
            return cached
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "vulnreach"}
        if GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = resp.read().decode("utf-8")
            data = json.loads(body)
            if not isinstance(data, dict):
                return None
            self._write_cache(cache_key, data)
            return data
        except urllib.error.HTTPError:
            return None
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            return None

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

    @staticmethod
    def _repo_url_from_record(record: dict[str, Any]) -> str | None:
        affected = record.get("affected") or []
        for aff in affected:
            repo = FixCommitResolver._repo_url_from_affected(aff)
            if repo:
                return repo
        return None

    @staticmethod
    def _github_repo_url(url: str) -> str | None:
        m = GITHUB_URL_RE.match(url)
        if not m:
            return None
        return f"https://github.com/{m.group(1)}/{m.group(2)}"
