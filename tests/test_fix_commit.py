"""Tests for fix-commit resolution with mocked HTTP (no network)."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from vulnreach.advisories.fix_commit import FixCommitResolver


class _MockResponse:
    """Minimal file-like response object imitating urllib.urlopen's result."""

    def __init__(self, body: bytes, status: int = 200) -> None:
        self._body = body
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_MockResponse":
        return self

    def __exit__(self, *args: object) -> bool:
        return False


def _make_urlopen(routes: dict[str, bytes]):
    """Return a urlopen stub that matches URLs by substring against ``routes``."""

    def opener(req, timeout=None):
        url = getattr(req, "full_url", str(req))
        for pattern, body in routes.items():
            if pattern in url:
                return _MockResponse(body)
        raise AssertionError(f"No mock route for URL: {url}")

    return opener


# ------------------------------------------------------------------ direct link


def test_direct_link_from_git_range(tmp_path):
    """A GIT range ``fixed`` event with /commit/<sha> resolves with direct_link."""
    record = {
        "id": "GHSA-test-direct-1",
        "aliases": ["CVE-2021-0001"],
        "affected": [
            {
                "package": {
                    "ecosystem": "PyPI",
                    "name": "example-pkg",
                    "repository": "https://github.com/owner/example-pkg",
                },
                "ranges": [
                    {
                        "type": "GIT",
                        "events": [
                            {"fixed": "https://github.com/owner/example-pkg/commit/abc123def4567890"},
                        ],
                    }
                ],
            }
        ],
        "references": [],
    }
    resolver = FixCommitResolver(cache_db=tmp_path / "cache.sqlite")
    fix = resolver.resolve(record)

    assert fix.resolution_method == "direct_link"
    assert fix.sha == "abc123def4567890"
    assert fix.confidence == 0.95
    assert fix.repo_url == "https://github.com/owner/example-pkg"


def test_direct_link_from_fix_reference(tmp_path):
    """A reference of type FIX containing /commit/<sha> resolves with direct_link."""
    record = {
        "id": "GHSA-test-direct-2",
        "affected": [],
        "references": [
            {"type": "FIX", "url": "https://github.com/owner/repo/commit/deadbeefcafebabedeadbeefcafebee1"}
        ],
    }
    resolver = FixCommitResolver(cache_db=tmp_path / "cache.sqlite")
    fix = resolver.resolve(record)

    assert fix.resolution_method == "direct_link"
    assert fix.sha == "deadbeefcafebabedeadbeefcafebee1"
    assert fix.confidence == 0.95


# ------------------------------------------------------------------ PR reference


def test_pr_reference_resolves_merge_commit(tmp_path):
    """A PR reference resolves to its merge commit via the GitHub API."""
    record = {
        "id": "GHSA-test-pr-1",
        "affected": [],
        "references": [{"type": "FIX", "url": "https://github.com/owner/repo/pull/42"}],
    }
    merge_body = json.dumps({"sha": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"}).encode("utf-8")
    routes = {"api.github.com/repos/owner/repo/pulls/42/merge": merge_body}

    with patch("urllib.request.urlopen", side_effect=_make_urlopen(routes)):
        resolver = FixCommitResolver(cache_db=tmp_path / "cache.sqlite")
        fix = resolver.resolve(record)

    assert fix.resolution_method == "pr_reference"
    assert fix.sha == "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
    assert fix.confidence == 0.7
    assert fix.repo_url == "https://github.com/owner/repo"


# ------------------------------------------------------------------ not found


def test_not_found_when_no_signal(tmp_path):
    """An advisory with no fix signal resolves to not_found with no sha."""
    record = {"id": "GHSA-test-none", "affected": [], "references": []}
    resolver = FixCommitResolver(cache_db=tmp_path / "cache.sqlite")
    fix = resolver.resolve(record)

    assert fix.resolution_method == "not_found"
    assert fix.sha is None
    assert fix.repo_url is None
    assert fix.confidence == 0.0
