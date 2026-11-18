"""Core data models for VulnReach.

All models use Pydantic for validation and serialization. Status and confidence
values are closed literals so a verdict can never be emitted without an explicit,
auditable classification.
"""

from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Literal


class Alert(BaseModel):
    """A vulnerability alert for a pinned dependency."""

    package: str
    version: str
    advisory_id: str
    aliases: list[str] = Field(default_factory=list)


class FixCommit(BaseModel):
    """A resolved fix commit for an advisory."""

    repo_url: str | None = None
    sha: str | None = None
    resolution_method: Literal["direct_link", "pr_reference", "tag_diff", "not_found"] = "not_found"
    confidence: float = 0.0


class VulnerableFunction(BaseModel):
    """A function identified as vulnerable in the pre-fix version of a file."""

    module: str
    qualified_name: str
    file_path: str
    confidence: float


class PathHop(BaseModel):
    """One hop in a call-path: a file:line location and the function there."""

    file: str
    line: int
    function: str


class Verdict(BaseModel):
    """Reachability verdict for a single alert.

    Every verdict carries evidence (the call path) and a confidence level with a
    short reason. When reachability cannot be ruled out, status must be
    ``uncertain`` rather than ``not_reachable``.
    """

    alert: Alert
    status: Literal["reachable", "not_reachable", "uncertain"]
    confidence: Literal["high", "medium", "low"]
    call_path: list[PathHop] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    dynamic_blockers: list[str] = Field(default_factory=list)
    explanation: str = ""
