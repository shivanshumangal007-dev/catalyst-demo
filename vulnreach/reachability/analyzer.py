"""Reachability analysis for VulnReach.

For each alert (plus the vulnerable functions resolved from its fix commit) the
analyzer decides whether the vulnerable code can be reached from project code:

1. ``functions_unknown``            -> ``uncertain`` (we cannot rule anything out)
2. static call path to a vulnerable function -> ``reachable`` (shortest path)
3. no static path, but dynamic sites could hide one -> ``uncertain``
4. no static path and no dynamic sites -> ``not_reachable``

Every verdict carries evidence (the call path, file:line per hop), a confidence
level with a short reason, and a human-readable explanation.  Per the project's
hard rule, we never emit ``not_reachable`` when reachability cannot be ruled out.
"""

from __future__ import annotations

from pathlib import Path

import networkx as nx

from vulnreach.advisories.fix_commit import FixCommit
from vulnreach.callgraph.builder import CallGraphResult, CallNode
from vulnreach.callgraph.dynamic_detector import DynamicSite
from vulnreach.models import Alert, PathHop, Verdict


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
            return self._verdict(
                alert,
                status="uncertain",
                confidence="medium",
                call_path=[],
                reasons=["could not determine vulnerable functions from the fix commit"],
                dynamic_blockers=[],
                explanation=(
                    f"Uncertain: the fix commit for {alert.package}@{alert.version} "
                    f"({alert.advisory_id}) did not yield any identifiable vulnerable "
                    f"function, so reachability cannot be ruled out."
                ),
            )

        # Step 2: locate target nodes in the graph and search for a path.
        target_nodes = self._target_nodes(vulnerable_functions)
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

        # Step 3: no static path, but dynamic features could hide one -> uncertain.
        blockers = [str(site) for site in self.dynamic_sites]
        if blockers:
            kinds = ", ".join(sorted({site.kind for site in self.dynamic_sites}))
            reasons = [
                "no static call path from any entry point to the vulnerable function",
                "dynamic Python features could hide a reachable path",
            ]
            explanation = (
                f"Uncertain: {alert.package}@{alert.version} ({alert.advisory_id}) "
                f"is not reachable via any static call path, but dynamic features "
                f"({kinds}) in project or dependency code could conceal a path to "
                f"the vulnerable function."
            )
            return self._verdict(
                alert,
                status="uncertain",
                confidence="medium",
                call_path=[],
                reasons=reasons,
                dynamic_blockers=blockers,
                explanation=explanation,
            )

        # Step 4: no path and no dynamic features -> not_reachable.
        confidence = "high" if fix_commit.resolution_method == "direct_link" else "medium"
        target_names = ", ".join(vf.qualified_name for vf in vulnerable_functions) or "<none identified>"
        reasons = [
            "no static call path from any entry point to the vulnerable function",
            "no dynamic features that could conceal a path",
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

    def _target_nodes(self, vulnerable_functions: list) -> list[CallNode]:
        """Map each :class:`VulnerableFunction` to its graph node, if present."""
        nodes: list[CallNode] = []
        for vf in vulnerable_functions:
            node = self._find_node(vf.qualified_name, vf.file_path)
            if node is not None:
                nodes.append(node)
        return nodes

    def _find_node(self, qualname: str, file_path: str | None) -> CallNode | None:
        for node in self.graph.nodes:
            if node.qualname == qualname:
                if file_path is None or self._rel(node.file) == self._rel(file_path):
                    return node
        # Fall back to qualname-only match
        for node in self.graph.nodes:
            if node.qualname == qualname:
                return node
        return None

    @staticmethod
    def _rel(path: str | None) -> str:
        if path is None:
            return ""
        p = Path(path)
        try:
            return str(p)
        except Exception:
            return str(path)

    def _verdict(
        self,
        alert: Alert,
        *,
        status: str,
        confidence: str,
        call_path: list[PathHop],
        reasons: list[str],
        dynamic_blockers: list[str],
        explanation: str,
    ) -> Verdict:
        return Verdict(
            alert=alert,
            status=status,  # type: ignore[arg-type]
            confidence=confidence,  # type: ignore[arg-type]
            call_path=call_path,
            reasons=reasons,
            dynamic_blockers=dynamic_blockers,
            explanation=explanation,
        )
