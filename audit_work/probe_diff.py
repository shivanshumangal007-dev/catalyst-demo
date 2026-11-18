"""Phase 2 probes: diff-to-functions edge cases (no network)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vulnreach.advisories.fix_commit import FixCommit  # noqa: E402
from vulnreach.diffing.diff_to_functions import DiffToFunctions  # noqa: E402
from vulnreach.models import Alert, VulnerableFunction  # noqa: E402
from vulnreach.reachability.analyzer import ReachabilityAnalyzer  # noqa: E402
from vulnreach.callgraph.builder import CallGraphBuilder  # noqa: E402

FIX = FixCommit(repo_url="https://github.com/o/r", sha="a" * 40,
                resolution_method="direct_link", confidence=0.95)


def parse(label, diff, old, advisory=""):
    d = DiffToFunctions()
    res = d._parse(diff, old, repo_url="https://github.com/o/r",
                   advisory_text=advisory, commit_confidence=0.95)
    print(f"{label:42s} n={len(res)} unknown={d.functions_unknown} "
          f"funcs={[r.qualified_name for r in res]}")
    return d, res


CALLER_OLD = """def public_api(payload):
    token = payload.get('t')
    return _parse(token)

def _parse(token):
    return int(token)
"""

# Fix adds validation to the *caller* only; every hunk line is context or added.
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

RENAMED_FN_DIFF = """diff --git a/pkg/mod.py b/pkg/mod.py
--- a/pkg/mod.py
+++ b/pkg/mod.py
@@ -1,4 +1,4 @@
-def _parse(token):
+def _parse_token(token):
     return int(token)
"""

CONST_DIFF = """diff --git a/pkg/cfg.py b/pkg/cfg.py
--- a/pkg/cfg.py
+++ b/pkg/cfg.py
@@ -1,2 +1,2 @@
-TIMEOUT = 5
+TIMEOUT = 10
 def helper():
     pass
"""

MULTI_DIFF = """diff --git a/pkg/a.py b/pkg/a.py
--- a/pkg/a.py
+++ b/pkg/a.py
@@ -1,3 +1,3 @@
 def alpha():
-    return 1
+    return 2
diff --git a/pkg/b.py b/pkg/b.py
--- a/pkg/b.py
+++ b/pkg/b.py
@@ -1,3 +1,3 @@
 class B:
     def beta(self):
-        return 3
+        return 4
"""

DECORATOR_DIFF = """diff --git a/pkg/mod.py b/pkg/mod.py
--- a/pkg/mod.py
+++ b/pkg/mod.py
@@ -1,3 +1,3 @@
-@old_deco
+@new_deco
 def handler():
     return 1
"""

NESTED_OLD = """def outer():
    def inner():
        return 1
    return inner()
"""

NESTED_DIFF = """diff --git a/pkg/mod.py b/pkg/mod.py
--- a/pkg/mod.py
+++ b/pkg/mod.py
@@ -1,4 +1,4 @@
 def outer():
     def inner():
-        return 1
+        return 2
     return inner()
"""

if __name__ == "__main__":
    d, res = parse("added-only caller validation", ADDED_ONLY_DIFF, {"pkg/mod.py": CALLER_OLD})
    # chain into analyzer
    proj = Path("/tmp/vr_diff_addedonly"); import shutil
    shutil.rmtree(proj, ignore_errors=True)
    (proj / "pkg").mkdir(parents=True)
    (proj / "pkg/__init__.py").write_text("")
    (proj / "pkg/mod.py").write_text("def public_api(payload):\n    return _parse(payload)\n\ndef _parse(t):\n    return int(t)\n")
    (proj / "main.py").write_text("from pkg.mod import public_api\npublic_api({})\n")
    g = CallGraphBuilder(proj).build()
    a = ReachabilityAnalyzer(g, proj)
    v = a.analyze_alert(Alert(package="lib", version="1", advisory_id="A"), res, d.functions_unknown, FIX)
    print(f"{'  -> analyzer verdict':42s} {v.status} {v.confidence}")
    print(f"{'  -> funcs_unknown=False, list empty':42s} {d.functions_unknown=} {res=}")

    parse("function rename (pre-fix name)", RENAMED_FN_DIFF, {"pkg/mod.py": "def _parse(token):\n    return int(token)\n"})
    parse("module-level constant", CONST_DIFF, {"pkg/cfg.py": "TIMEOUT = 5\ndef helper():\n    pass\n"})
    parse("multi-file multi-hunk", MULTI_DIFF, {
        "pkg/a.py": "def alpha():\n    return 1\n",
        "pkg/b.py": "class B:\n    def beta(self):\n        return 3\n",
    })
    parse("decorator line changed", DECORATOR_DIFF, {"pkg/mod.py": "@old_deco\ndef handler():\n    return 1\n"})
    parse("nested function change", NESTED_DIFF, {"pkg/mod.py": NESTED_OLD})
    parse("C-only diff", """diff --git a/src/x.c b/src/x.c
--- a/src/x.c
+++ b/src/x.c
@@ -1,2 +1,2 @@
-int f() { return 1; }
+int f() { return 2; }
""", {})
    parse("two files, one pre-fix missing", MULTI_DIFF, {"pkg/a.py": "def alpha():\n    return 1\n"})

    # URL construction / rename handling (mock network)
    dtf = DiffToFunctions()
    seen = []
    def fake_get(url):
        seen.append(url)
        return None
    dtf._get_text = fake_get
    dtf._fetch_old_files(FIX, MULTI_DIFF)
    print("\npre-fix URLs for normal diff:")
    for u in seen: print("  ", u)
    seen.clear()
    rename_diff = """diff --git a/pkg/old.py b/pkg/new.py
similarity index 90%
rename from pkg/old.py
rename to pkg/new.py
--- a/pkg/old.py
+++ b/pkg/new.py
@@ -1,2 +1,2 @@
-def f():
+def g():
     return 1
"""
    dtf2 = DiffToFunctions(); dtf2._get_text = fake_get
    files = dtf2._changed_python_files(rename_diff)
    dtf2._fetch_old_files(FIX, rename_diff)
    print("rename changed files:", files)
    print("rename pre-fix URLs:")
    for u in seen: print("  ", u)
