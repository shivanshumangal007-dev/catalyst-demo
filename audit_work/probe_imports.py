"""Phase 1 probes: relative imports, aliases, re-exports, star imports."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_work.harness import FIX, analyze, make  # noqa: E402

CASES = {
    "relative unaliased": (
        {"pkg/__init__.py": "",
         "pkg/core.py": "def vulnerable():\n    return 1\n",
         "pkg/main.py": "from .core import vulnerable\nvulnerable()\n"},
        "pkg.core.vulnerable", "pkg/core.py",
    ),
    "relative alias": (
        {"pkg/__init__.py": "",
         "pkg/core.py": "def vulnerable():\n    return 1\n",
         "pkg/main.py": "from .core import vulnerable as v\nv()\n"},
        "pkg.core.vulnerable", "pkg/core.py",
    ),
    "relative module alias": (
        {"pkg/__init__.py": "",
         "pkg/core.py": "def vulnerable():\n    return 1\n",
         "pkg/main.py": "from . import core as c\nc.vulnerable()\n"},
        "pkg.core.vulnerable", "pkg/core.py",
    ),
    "relative level-2 alias": (
        {"pkg/__init__.py": "", "pkg/sub/__init__.py": "",
         "pkg/core.py": "def vulnerable():\n    return 1\n",
         "pkg/sub/main.py": "from ..core import vulnerable as v\nv()\n"},
        "pkg.core.vulnerable", "pkg/core.py",
    ),
    "init re-export alias": (
        {"pkg/__init__.py": "from .core import vulnerable as v\n",
         "pkg/core.py": "def vulnerable():\n    return 1\n",
         "main.py": "from pkg import v\nv()\n"},
        "pkg.core.vulnerable", "pkg/core.py",
    ),
    "init re-export plain": (
        {"pkg/__init__.py": "from .core import vulnerable\n",
         "pkg/core.py": "def vulnerable():\n    return 1\n",
         "main.py": "from pkg import vulnerable\nvulnerable()\n"},
        "pkg.core.vulnerable", "pkg/core.py",
    ),
    "star import": (
        {"pkg/__init__.py": "",
         "pkg/core.py": "def vulnerable():\n    return 1\n",
         "pkg/main.py": "from .core import *\nvulnerable()\n"},
        "pkg.core.vulnerable", "pkg/core.py",
    ),
    "absolute alias": (
        {"pkg/__init__.py": "",
         "pkg/core.py": "def vulnerable():\n    return 1\n",
         "main.py": "from pkg.core import vulnerable as v\nv()\n"},
        "pkg.core.vulnerable", "pkg/core.py",
    ),
    "function-scope import": (
        {"pkg/__init__.py": "",
         "pkg/core.py": "def vulnerable():\n    return 1\n",
         "main.py": "def run():\n    from pkg.core import vulnerable as v\n    return v()\nrun()\n"},
        "pkg.core.vulnerable", "pkg/core.py",
    ),
    "conditional import": (
        {"pkg/__init__.py": "",
         "pkg/core.py": "def vulnerable():\n    return 1\n",
         "main.py": "try:\n    from pkg.core import vulnerable as v\nexcept ImportError:\n    v = None\nv()\n"},
        "pkg.core.vulnerable", "pkg/core.py",
    ),
    "dynamic relative import": (
        {"pkg/__init__.py": "",
         "pkg/core.py": "def vulnerable():\n    return 1\n",
         "pkg/main.py": "import importlib\nm = importlib.import_module('.core', __package__)\nm.vulnerable()\n"},
        "pkg.core.vulnerable", "pkg/core.py",
    ),
    "same-module nested qualname": (
        {"lib.py": "def outer():\n    def inner():\n        return 1\n    return inner()\n"},
        "lib.outer.inner", "lib.py",
    ),
}


def expected_safe(actual: str) -> str:
    return "reachable" if actual == "reachable" else actual


if __name__ == "__main__":
    mismatches = []
    for name, (files, vf, vf_file) in CASES.items():
        project = make("imp_" + name.replace(" ", "_").replace("-", "_"), files)
        try:
            verdict, graph = analyze(project, vf, vf_file)
            actual, conf = verdict.status, verdict.confidence
        except Exception as exc:
            actual, conf = f"CRASH:{type(exc).__name__}", "-"
        # Every case except the dynamic relative import should be reachable.
        want = "uncertain" if name == "dynamic relative import" else "reachable"
        ok = actual == want or (want == "reachable" and actual == "reachable")
        if not ok:
            mismatches.append((name, want, actual))
        print(f"{'OK ' if ok else 'FAIL'} {name:30s} want={want:12s} actual={actual:22s} conf={conf}")
    print("\nMISMATCHES:", len(mismatches))
    for m in mismatches:
        print("  ", m)
