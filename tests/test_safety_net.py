"""Round 1 safety-net regressions (F-02, F-03, F-10, F-14, F-16, F-39, F-51).

Every test here failed before the Round 1 fixes and asserts the soundness
contract: ``not_reachable`` is only allowed when the positive-evidence gate
holds, and a user assertion never downgrades an ``uncertain`` verdict.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnreach.advisories.fix_commit import FixCommit
from vulnreach.agent.pr_chat import PRChatAgent
from vulnreach.callgraph.builder import CallGraphBuilder
from vulnreach.diffing.diff_to_functions import DiffToFunctions
from vulnreach.models import Alert, VulnerableFunction
from vulnreach.reachability.analyzer import ReachabilityAnalyzer

FIX = FixCommit(
    repo_url="https://github.com/owner/lib",
    sha="a" * 40,
    resolution_method="direct_link",
    confidence=0.95,
)
LIB = "def vulnerable():\n    return 1\n\ndef safe():\n    return 2\n"
ALERT = Alert(package="lib", version="1.0.0", advisory_id="A-1")


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, source in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    return root


def _vf(
    qualname: str = "lib.vulnerable",
    file_path: str = "lib.py",
    confidence: float = 0.95,
) -> VulnerableFunction:
    return VulnerableFunction(
        module="lib",
        qualified_name=qualname,
        file_path=file_path,
        confidence=confidence,
    )


def _analyze(
    project: Path,
    vulnerable_functions: list[VulnerableFunction],
    *,
    functions_unknown: bool = False,
    dependency: str | None = None,
):
    graph = CallGraphBuilder(project).build(dependency_name=dependency)
    analyzer = ReachabilityAnalyzer(graph, project)
    verdict = analyzer.analyze_alert(
        ALERT, vulnerable_functions, functions_unknown, FIX
    )
    return verdict, graph, analyzer


# ------------------------------------------------------------------ F-02 / F-39


def test_missing_target_is_uncertain(tmp_path):
    project = _write(tmp_path, {"main.py": "import lib\nlib.safe()\n"})
    verdict, _, _ = _analyze(project, [_vf("lib.not_in_graph")])
    assert verdict.status == "uncertain"
    assert any("not found" in reason for reason in verdict.reasons)


def test_empty_vulnerable_list_is_uncertain(tmp_path):
    project = _write(tmp_path, {"main.py": "import lib\nlib.safe()\n"})
    verdict, _, _ = _analyze(project, [])
    assert verdict.status == "uncertain"
    assert any("empty" in reason for reason in verdict.reasons)


def test_qualname_only_fallback_is_removed(tmp_path):
    """A same-qualname node in another file must not count as the target."""
    project = _write(
        tmp_path,
        {"lib.py": LIB, "main.py": "from lib import safe\nsafe()\n"},
    )
    verdict, _, _ = _analyze(project, [_vf(file_path="other.py")])
    assert verdict.status == "uncertain"
    assert any("not found" in reason for reason in verdict.reasons)


# ------------------------------------------------------------------ F-10


def test_syntax_error_forces_uncertain(tmp_path):
    project = _write(
        tmp_path,
        {
            "lib.py": LIB,
            "main.py": "from lib import safe\nsafe()\n",
            "broken.py": "import lib\nlib.vulnerable(\n",
        },
    )
    verdict, graph, _ = _analyze(project, [_vf()])
    assert graph.unparsed_files
    assert verdict.status == "uncertain"
    assert any("unparseable" in reason for reason in verdict.reasons)


def test_non_utf8_file_forces_uncertain(tmp_path):
    project = _write(
        tmp_path,
        {"lib.py": LIB, "main.py": "from lib import safe\nsafe()\n"},
    )
    (project / "weird.py").write_bytes(b"import lib\n# \xff\xfe\nlib.vulnerable()\n")
    verdict, graph, _ = _analyze(project, [_vf()])
    assert graph.unparsed_files
    assert verdict.status == "uncertain"


# ------------------------------------------------------------------ F-16


def test_low_confidence_target_is_uncertain(tmp_path):
    project = _write(
        tmp_path,
        {"lib.py": LIB, "main.py": "from lib import safe\nsafe()\n"},
    )
    verdict, _, _ = _analyze(project, [_vf(confidence=0.4)])
    assert verdict.status == "uncertain"
    assert any("confidence" in reason for reason in verdict.reasons)


# ------------------------------------------------------------------ positive-evidence gate


def test_unresolved_dependency_call_blocks_not_reachable(tmp_path, monkeypatch):
    """An unmapped call into the dependency could reach a missing vulnerable node."""
    dep = tmp_path / "deps" / "mydep"
    (dep / "__init__.py").parent.mkdir(parents=True)
    (dep / "__init__.py").write_text("")
    (dep / "core.py").write_text("def vulnerable():\n    return 1\n")
    project = _write(
        tmp_path / "proj", {"main.py": "import mydep\nmydep.unknown_call()\n"}
    )

    class FakeDist:
        def locate_file(self, rel):
            return dep / rel

    monkeypatch.setattr("importlib.metadata.distribution", lambda name: FakeDist())
    verdict, graph, _ = _analyze(
        project,
        [_vf("mydep.core.vulnerable", "mydep/core.py")],
        dependency="mydep",
    )
    assert graph.unresolved_calls
    assert verdict.status == "uncertain"
    assert any("unresolved" in reason for reason in verdict.reasons)


# ------------------------------------------------------------------ F-03


ADDED_ONLY_DIFF = """diff --git a/pkg/mod.py b/pkg/mod.py
--- a/pkg/mod.py
+++ b/pkg/mod.py
@@ -1,3 +1,5 @@
 def public_api(payload):
+    if payload is None:
+        raise ValueError('missing payload')
     token = payload.get('t')
     return _parse(token)
"""

OLD_MODULE = """def public_api(payload):
    token = payload.get('t')
    return _parse(token)

def _parse(token):
    return int(token)
"""


def test_added_only_hunk_maps_to_enclosing_function(tmp_path):
    diff = DiffToFunctions()
    functions = diff._parse(
        ADDED_ONLY_DIFF,
        {"pkg/mod.py": OLD_MODULE},
        repo_url="https://github.com/o/r",
        advisory_text="",
        commit_confidence=0.95,
    )
    assert functions, "an added-only fix hunk must map to its enclosing function"
    assert not diff.functions_unknown
    assert functions[0].qualified_name == "pkg.mod.public_api"

    project = _write(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/mod.py": (
                "def public_api(payload):\n"
                "    return _parse(payload)\n\n"
                "def _parse(token):\n"
                "    return int(token)\n"
            ),
            "main.py": "from pkg.mod import public_api\npublic_api({})\n",
        },
    )
    graph = CallGraphBuilder(project).build()
    verdict = ReachabilityAnalyzer(graph, project).analyze_alert(
        ALERT, functions, diff.functions_unknown, FIX
    )
    assert verdict.status != "not_reachable"


# ------------------------------------------------------------------ F-14


def test_assumption_only_adds_caveat_and_keeps_verdict(tmp_path):
    project = _write(
        tmp_path,
        {
            "lib.py": LIB,
            "main.py": (
                "import lib\n"
                "name = 'safe'\n"
                "getattr(lib, name)()\n"
                "lib.safe()\n"
            ),
        },
    )
    graph = CallGraphBuilder(project).build()
    analyzer = ReachabilityAnalyzer(graph, project)
    vf = [_vf()]
    verdict = analyzer.analyze_alert(ALERT, vf, False, FIX)
    assert verdict.status == "uncertain"

    agent = PRChatAgent(verdict, analyzer, str(project), ALERT, vf, FIX, graph)
    reply = agent.respond("Assume that getattr only ever receives 'safe'.")

    assert agent.verdict.status == "uncertain"
    assert agent.verdict.status == verdict.status
    assert any("user assertion" in reason.lower() for reason in agent.verdict.reasons)
    assert "caveat" in agent.verdict.explanation.lower()
    assert "remains" in reply.lower()
    assert agent.verdict.dynamic_blockers == verdict.dynamic_blockers


# ------------------------------------------------------------------ F-51


class _Completed:
    def __init__(self, returncode=0):
        self.returncode = returncode
        self.stdout = ""
        self.stderr = ""


def test_docker_run_does_not_duplicate_entrypoint(tmp_path, monkeypatch):
    from vulnreach.sandbox.docker_runner import DockerRunner

    project = tmp_path / "proj"
    project.mkdir()
    alerts = tmp_path / "alerts.json"
    alerts.write_text("[]")
    out = tmp_path / "out"

    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0:3] == ["docker", "image", "inspect"]:
            return _Completed(returncode=0)
        if cmd[1] == "run":
            out.mkdir(parents=True, exist_ok=True)
            (out / "report.json").write_text(json.dumps({"verdicts": []}))
        return _Completed(returncode=0)

    monkeypatch.setattr("subprocess.run", fake_run)
    runner = DockerRunner(image="vulnreach:test")
    runner.run_isolated(project, alerts, out)

    run_cmd = next(cmd for cmd in calls if len(cmd) > 1 and cmd[1] == "run")
    image_at = run_cmd.index("vulnreach:test")
    assert run_cmd[image_at + 1] == "scan", run_cmd


def test_cli_reports_isolated_runtime_error_without_traceback(
    tmp_path, monkeypatch, capsys
):
    from vulnreach.cli import main

    project = tmp_path / "proj"
    project.mkdir()
    alerts = tmp_path / "alerts.json"
    alerts.write_text("[]")

    class BoomRunner:
        def __init__(self, *args, **kwargs):
            pass

        def run_isolated(self, *args, **kwargs):
            raise RuntimeError("simulated isolation failure")

    monkeypatch.setattr(
        "vulnreach.sandbox.docker_runner.DockerRunner", BoomRunner
    )
    code = main(
        ["scan", str(project), "--alerts", str(alerts), "--isolated"]
    )
    captured = capsys.readouterr()
    assert code == 1
    assert "isolated analysis failed" in captured.err
    assert "Traceback" not in captured.err


# ------------------------------------------------------------------ call accounting


def test_call_accounting_complete(tmp_path):
    """Every ast.Call node must be accounted for: edge, dynamic site, or external.

    If the number of Call nodes seen differs from the number accounted for,
    some call could be silently dropped -- potentially hiding a path to the
    vulnerable function.
    """
    import ast

    project = _write(
        tmp_path,
        {
            "lib.py": LIB,
            "main.py": (
                "import lib\n"
                "x = lib.vulnerable()\n"
                "print(lib.vulnerable())\n"
                "if lib.vulnerable():\n"
                "    pass\n"
                "f = lambda: lib.vulnerable()\n"
                "f()\n"
            ),
        },
    )
    builder = CallGraphBuilder(project)
    builder.build()

    # Count all Call nodes via ast.walk across every parsed file.
    seen: set[tuple[str, int]] = set()
    for _module, path, tree in builder._files:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                seen.add((str(path), node.lineno))

    accounted = builder._accounted_calls
    missing = seen - accounted
    extra = accounted - seen
    assert not missing, f"unaccounted call sites: {missing}"
    assert not extra, f"spurious accounted calls: {extra}"
    assert len(seen) == len(accounted)

