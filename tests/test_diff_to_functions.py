"""Tests for diff_to_functions using small unified-diff fixtures (no network)."""

from __future__ import annotations

from vulnreach.advisories.fix_commit import FixCommit
from vulnreach.diffing.diff_to_functions import DiffToFunctions


def _dtf() -> DiffToFunctions:
    return DiffToFunctions()


# ------------------------------------------------------------------ fixtures


MATH_OLD = """def add(a, b):
    return a + b

class Calculator:
    def compute(self, x):
        return x * 2

    def _secret(self, x):
        return x + 1
"""

MATH_DIFF = """--- a/mypkg/math.py
+++ b/mypkg/math.py
@@ -8,2 +8,2 @@
     def _secret(self, x):
-        return x + 1
+        return x + 2
"""

CONFIG_OLD = """DEBUG = True
VERSION = "1"

def setup():
    pass
"""

CONFIG_DIFF = """--- a/mypkg/config.py
+++ b/mypkg/config.py
@@ -1,2 +1,2 @@
-DEBUG = True
+DEBUG = False
 VERSION = "1"
"""

UTILS_OLD = """def _helper(x):
    # comment
    return x

def public_api(y):
    return _helper(y)
"""

UTILS_DIFF = """--- a/mypkg/utils.py
+++ b/mypkg/utils.py
@@ -1,3 +1,3 @@
 def _helper(x):
-    # comment
+    # comment revised
     return x
"""


def _run(diff: str, old_contents: dict[str, str], *, advisory_text: str = "", confidence: float = 0.5):
    dtf = _dtf()
    result = dtf._parse(
        diff,
        old_contents,
        repo_url="https://github.com/owner/mypkg",
        advisory_text=advisory_text,
        commit_confidence=confidence,
    )
    return dtf, result


# ------------------------------------------------------------------ method change


def test_method_change_qualified_name():
    """A changed line inside a method maps to module.Class.method."""
    dtf, result = _run(MATH_DIFF, {"mypkg/math.py": MATH_OLD})

    assert len(result) == 1
    vf = result[0]
    assert vf.qualified_name == "mypkg.math.Calculator._secret"
    assert vf.module == "mypkg.math"
    assert vf.file_path == "mypkg/math.py"
    assert vf.confidence == 0.5
    assert not dtf.functions_unknown


def test_module_level_change_marker():
    """A changed line outside any function maps to module.<module>."""
    dtf, result = _run(CONFIG_DIFF, {"mypkg/config.py": CONFIG_OLD})

    assert len(result) == 1
    vf = result[0]
    assert vf.qualified_name == "mypkg.config.<module>"
    assert vf.module == "mypkg.config"
    assert vf.confidence == 0.5
    assert not dtf.functions_unknown


# ------------------------------------------------------------------ formatting-only private change


def test_formatting_only_private_lowers_confidence():
    """Private function changed only by a comment gets confidence -0.1."""
    dtf, result = _run(UTILS_DIFF, {"mypkg/utils.py": UTILS_OLD})

    assert len(result) == 1
    vf = result[0]
    assert vf.qualified_name == "mypkg.utils._helper"
    assert vf.confidence == 0.4  # 0.5 - 0.1

    # The public caller is an entry point one level up.
    assert len(dtf.public_entry_points) == 1
    entry = dtf.public_entry_points[0]
    assert entry.qualified_name == "mypkg.utils.public_api"
    assert entry.file_path == "mypkg/utils.py"


def test_advisory_text_bonus():
    """A function name appearing in the advisory text gets +0.05 confidence."""
    _, result = _run(
        MATH_DIFF,
        {"mypkg/math.py": MATH_OLD},
        advisory_text="The _secret method is vulnerable",
    )
    assert result[0].confidence == 0.55  # 0.5 + 0.05


# ------------------------------------------------------------------ unknown flag


def test_no_fix_commit_means_unknown():
    """No fix commit -> empty list and functions_unknown=True (never not_reachable)."""
    dtf = _dtf()
    result = dtf.functions_for_commit(
        FixCommit(resolution_method="not_found", confidence=0.0),
        advisory_text="",
    )
    assert result == []
    assert dtf.functions_unknown is True


def test_fetch_failure_means_unknown(monkeypatch):
    """A fix commit whose diff cannot be fetched is unknown, not safe."""

    def boom(self, fix_commit):  # noqa: ARG001
        return None

    monkeypatch.setattr(DiffToFunctions, "_fetch_diff", boom)
    dtf = _dtf()
    result = dtf.functions_for_commit(
        FixCommit(
            repo_url="https://github.com/owner/mypkg",
            sha="abc123",
            resolution_method="direct_link",
            confidence=0.95,
        ),
        advisory_text="",
    )
    assert result == []
    assert dtf.functions_unknown is True
