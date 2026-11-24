"""Phase 7 adversarial regression suite.

Each test asserts the *safe* behaviour the README/contract promises. Failures
are audit findings, not test-suite breakage. Run:

    python3 -m pytest audit_work/tests -q
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import jsonschema  # noqa: E402

from vulnreach.advisories.fix_commit import FixCommit  # noqa: E402
from vulnreach.agent.pr_chat import PRChatAgent  # noqa: E402
from vulnreach.callgraph.builder import CallGraphBuilder, CallNode, _CallVisitor  # noqa: E402
from vulnreach.cache.store import CacheStore  # noqa: E402
from vulnreach.cli import _run_pipeline  # noqa: E402
from vulnreach.diffing.diff_to_functions import DiffToFunctions  # noqa: E402
from vulnreach.models import Alert, PathHop, Verdict, VulnerableFunction  # noqa: E402
from vulnreach.reachability.analyzer import ReachabilityAnalyzer  # noqa: E402
from vulnreach.vex.openvex import build_document  # noqa: E402

FIX = FixCommit(repo_url="https://github.com/o/r", sha="a" * 40,
                resolution_method="direct_link", confidence=0.95)
LIB = "def vulnerable():\n    return 1\n\ndef safe():\n    return 2\n"


def write(tmp: Path, files: dict[str, str]) -> Path:
    for rel, src in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src, encoding="utf-8")
    return tmp


def analyze(tmp: Path, files: dict[str, str], vf: str = "lib.vulnerable",
            vf_file: str = "lib.py", funcs_unknown: bool = False,
            vuln_funcs=None, dep: str | None = None, project: Path | None = None):
    project = project or write(tmp, files)
    result = CallGraphBuilder(project).build(dependency_name=dep)
    analyzer = ReachabilityAnalyzer(result, project)
    if vuln_funcs is None:
        vuln_funcs = [] if vf is None else [
            VulnerableFunction(module="lib", qualified_name=vf, file_path=vf_file, confidence=0.95)
        ]
    verdict = analyzer.analyze_alert(
        Alert(package="lib", version="1.0.0", advisory_id="A-1"),
        vuln_funcs, funcs_unknown, FIX,
    )
    return verdict, result, analyzer


CALL_CASES = {
    "assignment": "import lib\nx = lib.vulnerable()\n",
    "argument": "import lib\nprint(lib.vulnerable())\n",
    "lambda": "import lib\nf = lambda: lib.vulnerable()\nf()\n",
    "comprehension": "import lib\nxs = [lib.vulnerable() for _ in range(2)]\n",
    "if-test": "import lib\nif lib.vulnerable():\n    pass\n",
    "while-test": "import lib\nwhile lib.vulnerable():\n    break\n",
    "with-expr": "import lib\nwith lib.vulnerable():\n    pass\n",
    "try-body": "import lib\ntry:\n    lib.vulnerable()\nexcept Exception:\n    pass\n",
    "except-handler": "import lib\ntry:\n    pass\nexcept Exception:\n    lib.vulnerable()\n",
    "finally": "import lib\ntry:\n    pass\nfinally:\n    lib.vulnerable()\n",
    "await": "import asyncio, lib\nasync def h():\n    await lib.vulnerable()\nasyncio.run(h())\n",
    "yield": "import lib\ndef g():\n    yield lib.vulnerable()\nlist(g())\n",
    "class-body": "import lib\nclass A:\n    X = lib.vulnerable()\n",
    "decorator": "import lib\ndef deco(f):\n    lib.vulnerable()\n    return f\n@deco\ndef g():\n    pass\ng()\n",
    "raise": "import lib\nraise lib.vulnerable()\n",
    "assert": "import lib\nassert lib.vulnerable()\n",
    "fstring": "import lib\nx = f'{lib.vulnerable()}'\n",
    "subscript": "import lib\nx = [0][lib.vulnerable()]\n",
    "match-subject": "import lib\nmatch lib.vulnerable():\n    case _:\n        pass\n",
    "nested-function": "import lib\ndef outer():\n    def inner():\n        lib.vulnerable()\n    inner()\nouter()\n",
    "map-callback": "import lib\nlist(map(lambda _: lib.vulnerable(), [1]))\n",
    "function-value": "import lib\nf = lib.vulnerable\nf()\n",
    "dict-dispatch": "import lib\nd = {'x': lib.vulnerable}\nd['x']()\n",
    "partial": "import lib, functools\nf = functools.partial(lib.vulnerable)\nf()\n",
    "thread-target": "import lib, threading\nt = threading.Thread(target=lib.vulnerable)\nt.start()\nt.join()\n",
    "getattr-literal": "import lib\ngetattr(lib, 'vulnerable')()\n",
    "entry-points-import": "from importlib.metadata import entry_points\nfor ep in entry_points().select(group='x'):\n    ep.load()()\n",
    "entry-points-attr": "import importlib.metadata\nfor ep in importlib.metadata.entry_points().select(group='x'):\n    ep.load()()\n",
    "pkgutil": "import pkgutil, importlib\nfor m in pkgutil.iter_modules():\n    importlib.import_module(m.name)\n",
    "subclasses": "for c in object.__subclasses__():\n    c()\n",
    "context-manager-enter": "import lib\nclass H:\n    def __enter__(self):\n        return lib.vulnerable()\n    def __exit__(self,*a): return False\nwith H():\n    pass\n",
}


@pytest.mark.parametrize("name,src", CALL_CASES.items())
def test_call_construct_is_not_safe(tmp_path, name, src):
    files = {"lib.py": LIB, "main.py": src}
    verdict, _, _ = analyze(tmp_path, files)
    # Dynamic constructs may be uncertain; a genuine call must not be not_reachable.
    assert verdict.status != "not_reachable", f"{name}: {verdict.status} conf={verdict.confidence}"


def test_constructor(tmp_path):
    v, _, _ = analyze(
        tmp_path,
        {"lib.py": "class Thing:\n    def __init__(self):\n        self.x = 1\n",
         "main.py": "from lib import Thing\nThing()\n"},
        "lib.Thing.__init__",
    )
    assert v.status == "reachable"


def test_property(tmp_path):
    v, _, _ = analyze(
        tmp_path,
        {"lib.py": "class Thing:\n    @property\n    def value(self):\n        return 1\n",
         "main.py": "from lib import Thing\nprint(Thing().value)\n"},
        "lib.Thing.value",
    )
    assert v.status == "reachable"


def test_dunder(tmp_path):
    v, _, _ = analyze(
        tmp_path,
        {"lib.py": "class Thing:\n    def __eq__(self, o):\n        return True\n",
         "main.py": "from lib import Thing\nThing() == Thing()\n"},
        "lib.Thing.__eq__",
    )
    assert v.status == "reachable"


def test_missing_target_is_uncertain(tmp_path):
    v, _, _ = analyze(
        tmp_path, {"main.py": "import lib\nlib.safe()\n"},
        "_cffi.vulnerable", "lib.py",
    )
    assert v.status == "uncertain", "a target absent from the graph must not be declared safe"


def test_empty_vulnerable_list_is_uncertain(tmp_path):
    v, _, _ = analyze(tmp_path, {"main.py": "import lib\nlib.safe()\n"}, vf=None, vuln_funcs=[])
    assert v.status == "uncertain"


def test_library_public_function(tmp_path):
    v, _, _ = analyze(
        tmp_path,
        {"libpkg/__init__.py": "",
         "libpkg/public.py": "from .vuln import vulnerable\ndef public_api():\n    return vulnerable()\n",
         "libpkg/vuln.py": "def vulnerable():\n    return 1\n"},
        "libpkg.vuln.vulnerable", "libpkg/vuln.py",
    )
    assert v.status == "reachable"


def test_setup_py_console_script(tmp_path):
    v, _, _ = analyze(
        tmp_path,
        {"lib.py": LIB,
         "job.py": "def run():\n    import lib\n    return lib.vulnerable()\n",
         "setup.py": "from setuptools import setup\nsetup(entry_points={'console_scripts': ['x=job:run']})\n"},
    )
    assert v.status == "reachable"


def test_src_layout_qualname(tmp_path):
    v, _, _ = analyze(
        tmp_path,
        {"src/app/__init__.py": "",
         "src/app/main.py": "from app.lib import vulnerable\nvulnerable()\n",
         "src/app/lib.py": "def vulnerable():\n    return 1\n"},
        "app.lib.vulnerable", "app/lib.py",
    )
    assert v.status == "reachable"


def test_nested_qualname_map(tmp_path):
    v, _, _ = analyze(
        tmp_path,
        {
            "lib.py": "def outer():\n    def inner():\n        return 1\n    return inner()\n",
            "main.py": "from lib import outer\nouter()\n",
        },
        "lib.outer.inner", "lib.py",
    )
    assert v.status == "reachable"


def test_relative_alias(tmp_path):
    v, _, _ = analyze(
        tmp_path,
        {"pkg/__init__.py": "",
         "pkg/core.py": "def vulnerable():\n    return 1\n",
         "pkg/main.py": "from .core import vulnerable as v\nv()\n"},
        "pkg.core.vulnerable", "pkg/core.py",
    )
    assert v.status == "reachable"


def test_init_reexport_alias(tmp_path):
    v, _, _ = analyze(
        tmp_path,
        {"pkg/__init__.py": "from .core import vulnerable as v\n",
         "pkg/core.py": "def vulnerable():\n    return 1\n",
         "main.py": "from pkg import v\nv()\n"},
        "pkg.core.vulnerable", "pkg/core.py",
    )
    assert v.status == "reachable"


def test_syntax_error_caller_forces_uncertain(tmp_path):
    (tmp_path / "lib.py").write_text(LIB)
    (tmp_path / "main.py").write_text("from lib import safe\nsafe()\n")
    (tmp_path / "broken.py").write_text("import lib\nlib.vulnerable(\n")
    v, _, _ = analyze(tmp_path, {}, project=tmp_path)
    assert v.status != "not_reachable", "an unparseable file could hide the only caller"


def test_non_utf8_does_not_crash(tmp_path):
    (tmp_path / "lib.py").write_text(LIB)
    (tmp_path / "main.py").write_text("from lib import safe\nsafe()\n")
    (tmp_path / "weird.py").write_bytes(b"import lib\n# \xff\xfe\nlib.vulnerable()\n")
    v, _, _ = analyze(tmp_path, {}, project=tmp_path)
    assert v.status != "not_reachable"


ADDED_ONLY = """diff --git a/pkg/mod.py b/pkg/mod.py
--- a/pkg/mod.py
+++ b/pkg/mod.py
@@ -1,3 +1,5 @@
 def public_api(payload):
+    if payload is None:
+        raise ValueError('missing payload')
     token = payload.get('t')
     return _parse(token)
"""
CALLER_OLD = """def public_api(payload):
    token = payload.get('t')
    return _parse(token)

def _parse(token):
    return int(token)
"""


def test_added_only_fix_hunk_not_safe(tmp_path):
    d = DiffToFunctions()
    funcs = d._parse(ADDED_ONLY, {"pkg/mod.py": CALLER_OLD},
                     repo_url="https://github.com/o/r", advisory_text="", commit_confidence=0.95)
    project = write(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/mod.py": "def public_api(payload):\n    return _parse(payload)\n\ndef _parse(t):\n    return int(t)\n",
        "main.py": "from pkg.mod import public_api\npublic_api({})\n",
    })
    graph = CallGraphBuilder(project).build()
    v = ReachabilityAnalyzer(graph, project).analyze_alert(
        Alert(package="lib", version="1", advisory_id="A"), funcs, d.functions_unknown, FIX)
    assert d.functions_unknown or funcs, "empty function list must be marked unknown"
    # Post-F-03 the enclosing (pre-fix) function is identified, so the list is
    # no longer empty/unknown.  Here main() calls public_api(), so the
    # vulnerability is reachable -- which satisfies the safe contract
    # (status != "not_reachable") documented in AUDIT_REPORT.md round-1 notes.
    # The historical `== uncertain` assertion reflected the pre-F-03 empty-list
    # behaviour and is intentionally superseded.
    assert v.status != "not_reachable", f"added-only hunk must not be false-safe: {v.status}"


def test_repo_url_regex(self=None):
    assert DiffToFunctions._repo_parts("https://github.com/psf/requests") == ("psf", "requests")


def test_openvex_schema(tmp_path):
    schema = json.loads((ROOT / "audit_work" / "openvex_schema.json").read_text())
    v = Verdict(alert=Alert(package="PyYAML", version="5.4", advisory_id="GHSA-x"),
                status="not_reachable", confidence="high", reasons=["no path"])
    doc = build_document([v], author="vulnreach", project_purl="pkg:pypi/demo@1.0.0")
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(doc))
    assert not errors, [e.message for e in errors]


def test_assumption_does_not_flip_to_safe(tmp_path):
    project = write(tmp_path, {
        "lib.py": LIB,
        "main.py": "import lib\nname = 'safe'\ngetattr(lib, name)()\nlib.safe()\n",
    })
    graph = CallGraphBuilder(project).build()
    analyzer = ReachabilityAnalyzer(graph, project)
    alert = Alert(package="lib", version="1", advisory_id="A")
    vf = [VulnerableFunction(module="lib", qualified_name="lib.vulnerable",
                             file_path="lib.py", confidence=0.95)]
    verdict = analyzer.analyze_alert(alert, vf, False, FIX)
    assert verdict.status == "uncertain"
    agent = PRChatAgent(verdict, analyzer, str(project), alert, vf, FIX, graph)
    agent.respond("Assume that getattr only ever receives 'safe'.")
    assert agent.verdict.status != "not_reachable", "a user assertion is not evidence"


def test_multi_alert_pipeline(tmp_path):
    deps = tmp_path / "deps"
    for pkg, vuln in (("depa", "vuln_a"), ("depb", "vuln_b")):
        p = deps / pkg
        p.mkdir(parents=True)
        (p / "__init__.py").write_text("")
        (p / "core.py").write_text(f"def {vuln}():\n    return 1\n")
        (p / "api.py").write_text(f"from .core import {vuln}\ndef public():\n    return {vuln}()\n")
    project = write(tmp_path / "proj", {
        "main.py": "from depa.api import public as a\nfrom depb.api import public as b\na()\nb()\n",
    })
    cache = CacheStore(db_path=tmp_path / "store.sqlite")

    class FakeDist:
        def __init__(self, base):
            self.base = base
        def locate_file(self, rel):
            return self.base / rel

    dists = {"depa": FakeDist(deps / "depa"), "depb": FakeDist(deps / "depb")}

    def fake_dist(name):
        if name in dists:
            return dists[name]
        import importlib.metadata
        raise importlib.metadata.PackageNotFoundError(name)

    for pkg, vuln in (("depa", "vuln_a"), ("depb", "vuln_b")):
        cache.put(pkg, "1.0.0", "advisory_functions", {
            "fix_commit": FIX.model_dump(),
            "vulnerable_functions": [{
                "module": f"{pkg}.core", "qualified_name": f"{pkg}.core.{vuln}",
                "file_path": "core.py", "confidence": 0.95,
            }],
            "functions_unknown": False,
        }, advisory_id=f"ADV-{pkg}")

    alerts = [
        {"package": "depa", "version": "1.0.0", "advisory_id": "ADV-depa"},
        {"package": "depb", "version": "1.0.0", "advisory_id": "ADV-depb"},
    ]
    with patch("importlib.metadata.distribution", side_effect=fake_dist):
        verdicts, _, _ = _run_pipeline(project, alerts, cache)
    assert [v.status for v in verdicts] == ["reachable", "reachable"]


def test_cold_and_warm_cache_agree(tmp_path):
    dep = tmp_path / "mydep"
    (dep / "__init__.py").parent.mkdir(parents=True)
    (dep / "__init__.py").write_text("")
    (dep / "core.py").write_text("def vulnerable():\n    return 1\n")
    (dep / "api.py").write_text("from .core import vulnerable\ndef public():\n    return vulnerable()\n")
    project = write(tmp_path / "proj", {"main.py": "from mydep.api import public\npublic()\n"})

    class FakeDist:
        def locate_file(self, rel):
            return dep / rel

    vf = [VulnerableFunction(module="mydep.core", qualified_name="mydep.core.vulnerable",
                             file_path="mydep/core.py", confidence=0.95)]
    with patch("importlib.metadata.distribution", return_value=FakeDist()):
        cold_graph = CallGraphBuilder(project).build(dependency_name="mydep")
        cold = ReachabilityAnalyzer(cold_graph, project).analyze_alert(
            Alert(package="mydep", version="1", advisory_id="A"), vf, False, FIX)
        nodes = [{"qualname": n.qualname, "file": n.file, "line": n.line}
                 for n in cold_graph.graph.nodes if n.qualname.startswith("mydep.")]
        edges = [{"source": u.qualname, "target": w.qualname}
                 for u, w in cold_graph.graph.edges
                 if u.qualname.startswith("mydep.") and w.qualname.startswith("mydep.")]
        builder = CallGraphBuilder(project)
        builder.build(dependency_name="mydep", include_dependency=False)
        builder.add_cached_subgraph(nodes, edges)
        builder.entry_points.append(CallNode("mydep.<module>", "", 1))
        # Re-resolve project calls now that the cached dependency nodes are
        # registered in _file_functions, mirroring what the CLI does on a warm
        # cache run so project -> dependency edges are preserved (F-06).
        builder.unresolved_calls = []
        builder._accounted_calls = set()
        builder._all_call_sites = []
        for module, path, tree in builder._files:
            module_node = CallNode(
                qualname=f"{module}.<module>",
                file=builder._display_file(path),
                line=1,
            )
            if not builder.graph.has_node(module_node):
                builder.graph.add_node(module_node)
            visitor = _CallVisitor(builder, module, path, module_node)
            visitor.visit(tree)
            builder._accounted_calls.update(visitor.accounted_calls)
            builder._all_call_sites.extend(visitor.all_call_sites)
        warm_graph = type("R", (), {"graph": builder.graph, "entry_points": builder.entry_points,
                                    "dynamic_sites": [], "name_index": builder._name_index})()
        warm = ReachabilityAnalyzer(warm_graph, project).analyze_alert(
            Alert(package="mydep", version="1", advisory_id="A"), vf, False, FIX)
    assert cold.status == "reachable"
    assert warm.status == cold.status, "warm cache changed the verdict"
