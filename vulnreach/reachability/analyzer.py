"""Reachability analysis for VulnReach.

For each alert (plus the vulnerable functions resolved from its fix commit) the
analyzer decides whether the vulnerable code can be reached from project code:

1. ``functions_unknown``            -> ``uncertain`` (we cannot rule anything out)
2. unresolved call sites            -> ``uncertain`` (a hidden call could reach the target)
3. static call path to a vulnerable function -> ``reachable`` (shortest path)
4. no static path, but dynamic sites could hide one -> ``uncertain``
5. no static path and no dynamic sites -> ``not_reachable``

Every verdict carries evidence (the call path, file:line per hop), a confidence
level with a short reason, and a human-readable explanation.  Per the project's
hard rule, we never emit ``not_reachable`` when reachability cannot be ruled out.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Literal

import networkx as nx

from vulnreach.advisories.fix_commit import FixCommit
from vulnreach.callgraph.builder import CallGraphResult, CallNode
from vulnreach.callgraph.dynamic_detector import DynamicSite
from vulnreach.models import Alert, PathHop, Verdict

# Vulnerable-function extraction below this confidence is too weak to support a
# negative (``not_reachable``) claim.  Fix-commit resolution methods are 0.95
# (direct link), 0.7 (PR reference) and 0.5 (tag diff); anything weaker than a
# PR reference is treated as unknown.
MIN_TARGET_CONFIDENCE = 0.7


class ReachabilityAnalyzer:
    """Decide reachability for alerts using a pre-built call graph."""

    def __init__(self, call_graph: CallGraphResult, project_path: str | Path) -> None:
        self.call_graph = call_graph
        self.project_path = Path(project_path).resolve()
        self.graph: nx.DiGraph = call_graph.graph
        self.entry_points: list[CallNode] = call_graph.entry_points
        self.dynamic_sites: list[DynamicSite] = call_graph.dynamic_sites

    # ------------------------------------------------------------------ public

    def analyze_alert(
        self,
        alert: Alert,
        vulnerable_functions: list,
        functions_unknown: bool,
        fix_commit: FixCommit,
    ) -> Verdict:
        """Return a :class:`Verdict` for a single alert.

        ``vulnerable_functions`` is a list of :class:`VulnerableFunction`.  When
        ``functions_unknown`` is true the list is empty and we must emit
        ``uncertain``.
        """
        # Step 1: we could not determine the vulnerable functions -> uncertain.
        if functions_unknown:
            return self._uncertain(
                alert,
                reasons=["could not determine vulnerable functions from the fix commit"],
                explanation=(
                    f"Uncertain: the fix commit for {alert.package}@{alert.version} "
                    f"({alert.advisory_id}) did not yield any identifiable vulnerable "
                    f"function, so reachability cannot be ruled out."
                ),
            )

        # Step 2: weak per-function extraction cannot support a negative claim.
        weak = [
            vf
            for vf in vulnerable_functions
            if getattr(vf, "confidence", 0.0) < MIN_TARGET_CONFIDENCE
        ]
        if weak:
            names = ", ".join(vf.qualified_name for vf in weak)
            return self._uncertain(
                alert,
                reasons=[
                    "vulnerable-function extraction confidence is too low for a "
                    f"negative verdict (minimum {MIN_TARGET_CONFIDENCE})",
                    f"low-confidence targets: {names}",
                ],
                explanation=(
                    f"Uncertain: the vulnerable function(s) for {alert.package}@"
                    f"{alert.version} ({alert.advisory_id}) were identified with "
                    f"confidence below {MIN_TARGET_CONFIDENCE}, so the target list "
                    f"may be incomplete or wrong and reachability cannot be ruled out."
                ),
            )

        # Step 3: unresolved call sites could hide a path to the vulnerable
        # function.  This check runs *before* the path search so that a resolved
        # path cannot mask an unresolved call that might reach the same target
        # through a different route.  Soundness over precision.
        unresolved = list(getattr(self.call_graph, "unresolved_calls", []))
        if unresolved:
            joined = ", ".join(unresolved[:5])
            suffix = "" if len(unresolved) <= 5 else f" (+{len(unresolved) - 5} more)"
            return self._uncertain(
                alert,
                reasons=[
                    f"unresolved call site(s) could reach the vulnerable function: {joined}{suffix}"
                ],
                blockers=unresolved,
                explanation=(
                    f"Uncertain: {alert.package}@{alert.version} "
                    f"({alert.advisory_id}) -- the analysis found call site(s) that "
                    f"could not be resolved to a graph node and might reach the "
                    f"vulnerable function through a hidden path."
                ),
            )

        # Step 4: locate target nodes in the graph and search for a path.
        target_nodes, target_problems = self._target_nodes(vulnerable_functions)
        best_path: list[CallNode] | None = None

        if target_nodes:
            for entry in self.entry_points:
                for target in target_nodes:
                    try:
                        path = nx.shortest_path(self.graph, entry, target)
                    except (nx.NetworkXNoPath, nx.NodeNotFound):
                        continue
                    if best_path is None or len(path) < len(best_path):
                        best_path = path

        if best_path:
            over_approx = any(
                self.graph[best_path[i]][best_path[i + 1]].get("over_approx", False)
                for i in range(len(best_path) - 1)
            )
            confidence = "medium" if over_approx else "high"
            call_path = [
                PathHop(file=self._rel(node.file), line=node.line, function=node.qualname)
                for node in best_path
            ]
            reasons = [
                f"call path from entry point {best_path[0].qualname} "
                f"to vulnerable function {best_path[-1].qualname}"
            ]
            if over_approx:
                reasons.append("path traverses an over-approximated (indirect) edge")
            explanation = (
                f"Reachable: {alert.package}@{alert.version} "
                f"({alert.advisory_id}) -- the vulnerable function "
                f"{best_path[-1].qualname} is reachable from project code via a "
                f"static call path starting at {best_path[0].qualname}."
            )
            return self._verdict(
                alert,
                status="reachable",
                confidence=confidence,
                call_path=call_path,
                reasons=reasons,
                dynamic_blockers=[],
                explanation=explanation,
            )

        # Step 5: positive-evidence gate.  ``not_reachable`` is a negative claim
        # about the whole program, so it is allowed only when every precondition
        # documented in :meth:`_positive_evidence_gate` holds.  Any violation
        # degrades the verdict to ``uncertain``.
        gate_reasons, blockers = self._positive_evidence_gate(
            vulnerable_functions=vulnerable_functions,
            functions_unknown=functions_unknown,
            target_nodes=target_nodes,
            target_problems=target_problems,
        )
        if gate_reasons:
            kinds = ", ".join(sorted({site.kind for site in self.dynamic_sites}))
            if blockers:
                gate_reasons.append("dynamic Python features could hide a reachable path")
            explanation = (
                f"Uncertain: {alert.package}@{alert.version} ({alert.advisory_id}) "
                f"is not reachable via any static call path, but the analysis is "
                f"incomplete: {'; '.join(gate_reasons)}."
            )
            if blockers:
                explanation += (
                    f" Dynamic features ({kinds}) in project or dependency code "
                    f"could conceal a path to the vulnerable function."
                )
            return self._uncertain(
                alert,
                reasons=gate_reasons,
                blockers=blockers,
                explanation=explanation,
            )

        # Step 6: every precondition holds and there is no path -> not_reachable.
        confidence = "high" if fix_commit.resolution_method == "direct_link" else "medium"
        target_names = ", ".join(vf.qualified_name for vf in vulnerable_functions) or "<none identified>"
        reasons = [
            "no static call path from any entry point to the vulnerable function",
            "no dynamic features that could conceal a path",
            "positive-evidence gate passed: targets found, all files parsed, "
            "function list complete, no unresolved dependency calls",
        ]
        explanation = (
            f"Not reachable: {alert.package}@{alert.version} ({alert.advisory_id}) "
            f"-- no static call path from project code to the vulnerable function(s) "
            f"({target_names}), and no dynamic features that could hide one."
        )
        return self._verdict(
            alert,
            status="not_reachable",
            confidence=confidence,
            call_path=[],
            reasons=reasons,
            dynamic_blockers=[],
            explanation=explanation,
        )

    # ------------------------------------------------------------------ helpers

    def _positive_evidence_gate(
        self,
        *,
        vulnerable_functions: list,
        functions_unknown: bool,
        target_nodes: list[CallNode],
        target_problems: list[str],
    ) -> tuple[list[str], list[str]]:
        """Return the reasons that forbid ``not_reachable``; empty means allowed.

        A ``not_reachable`` verdict asserts that *no* path exists.  That is only
        defensible when all of the following preconditions hold:

        1. ``functions_unknown`` is False and ``vulnerable_functions`` is
           non-empty: there is an actual target to look for.
        2. Every supplied vulnerable function maps to exactly one node in the
           call graph (exact qualname *and* file).  A qualname-only fallback
           could match a same-named function in a different module, and a
           missing node means the target was never analysed.
        3. Every project and dependency file parsed successfully.  An
           unparseable file could contain the only caller (or a dynamic call),
           so the graph is incomplete.
        4. No dynamic site exists: ``getattr``/plugins/registries can hide a
           call that static analysis cannot see.
        5. No unresolved call site targets the vulnerable dependency.  If a
           call into the dependency could not be mapped to a graph node, it
           might reach a vulnerable function that is absent from the graph.
        """
        reasons: list[str] = []
        blockers: list[str] = []

        # Precondition 1: a non-empty, known target list.
        if functions_unknown:
            reasons.append("vulnerable functions are unknown")
        if not vulnerable_functions:
            reasons.append("vulnerable-function list is empty")

        # Precondition 2: every target was found exactly once (file + qualname).
        reasons.extend(target_problems)
        if not target_nodes:
            reasons.append("no vulnerable-function node was found in the call graph")

        # Precondition 3: the graph covers every file.
        unparsed = list(getattr(self.call_graph, "unparsed_files", []))
        if unparsed:
            joined = ", ".join(unparsed[:5])
            suffix = "" if len(unparsed) <= 5 else f" (+{len(unparsed) - 5} more)"
            reasons.append(f"unparseable source file(s): {joined}{suffix}")

        # Precondition 4: no dynamic constructs that could hide an edge.
        if self.dynamic_sites:
            blockers = [str(site) for site in self.dynamic_sites]
            reasons.append("dynamic call sites are present")

        # Precondition 5: no unresolved call into the dependency.
        unresolved = list(getattr(self.call_graph, "unresolved_calls", []))
        if unresolved:
            joined = ", ".join(unresolved[:5])
            suffix = "" if len(unresolved) <= 5 else f" (+{len(unresolved) - 5} more)"
            reasons.append(f"unresolved dependency call site(s): {joined}{suffix}")

        return reasons, blockers

    def _target_nodes(self, vulnerable_functions: list) -> tuple[list[CallNode], list[str]]:
        """Map each :class:`VulnerableFunction` to its graph node.

        Returns ``(nodes, problems)``.  A target that does not map to exactly
        one node is a problem, never a silent miss.
        """
        nodes: list[CallNode] = []
        problems: list[str] = []
        seen: set[CallNode] = set()
        for vf in vulnerable_functions:
            matches = [
                node
                for node in self.graph.nodes
                if node.qualname == vf.qualified_name
                and self._same_file(node.file, vf.file_path)
            ]
            if len(matches) == 1:
                node = matches[0]
                if node not in seen:
                    seen.add(node)
                    nodes.append(node)
            elif not matches:
                problems.append(
                    f"target {vf.qualified_name!r} ({vf.file_path}) was not found "
                    f"in the call graph"
                )
            else:
                problems.append(
                    f"target {vf.qualified_name!r} ({vf.file_path}) is ambiguous: "
                    f"{len(matches)} graph nodes match"
                )
        return nodes, problems

    @staticmethod
    def _same_file(node_file: str | None, target_file: str | None) -> bool:
        """Compare paths exactly, then by suffix (absolute vs project-relative)."""
        if not node_file or not target_file:
            return False
        node_parts = PurePosixPath(str(node_file).replace("\\", "/")).parts
        target_parts = PurePosixPath(str(target_file).replace("\\", "/")).parts
        if node_parts == target_parts:
            return True
        if len(node_parts) >= len(target_parts) and node_parts[-len(target_parts):] == target_parts:
            return True
        if len(target_parts) >= len(node_parts) and target_parts[-len(node_parts):] == node_parts:
            return True
        return False

    @staticmethod
    def _rel(path: str | None) -> str:
        if path is None:
            return ""
        p = Path(path)
        try:
            return str(p)
        except Exception:
            return str(path)

    def _uncertain(
        self,
        alert: Alert,
        *,
        reasons: list[str],
        explanation: str,
        blockers: list[str] | None = None,
    ) -> Verdict:
        return self._verdict(
            alert,
            status="uncertain",
            confidence="medium",
            call_path=[],
            reasons=reasons,
            dynamic_blockers=blockers or [],
            explanation=explanation,
        )

    def _verdict(
        self,
        alert: Alert,
        *,
        status: Literal["reachable", "not_reachable", "uncertain"],
        confidence: Literal["high", "medium", "low"],
        call_path: list[PathHop],
        reasons: list[str],
        dynamic_blockers: list[str],
        explanation: str,
    ) -> Verdict:
        return Verdict(
            alert=alert,
            status=status,
            confidence=confidence,
            call_path=call_path,
            reasons=reasons,
            dynamic_blockers=dynamic_blockers,
            explanation=explanation,
        )
