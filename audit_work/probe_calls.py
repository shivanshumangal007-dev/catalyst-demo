"""Phase 1 probes: call constructs. Expected all 'reachable' (except labelled)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_work.harness import LIB, analyze, make  # noqa: E402

CASES = {
    # (fixture files, expected)
    "module-level direct": ({"main.py": "import lib\nlib.vulnerable()\n"}, "reachable"),
    "alias function import": ({"main.py": "from lib import vulnerable as v\nv()\n"}, "reachable"),
    "alias module import": ({"main.py": "import lib as l\nl.vulnerable()\n"}, "reachable"),
    "assignment call": ({"main.py": "import lib\nx = lib.vulnerable()\n"}, "reachable"),
    "call as argument": ({"main.py": "import lib\nprint(lib.vulnerable())\n"}, "reachable"),
    "annassign call": ({"main.py": "import lib\nx: int = lib.vulnerable()\n"}, "reachable"),
    "augassign call": ({"main.py": "import lib\nx = 0\nx += lib.vulnerable()\n"}, "reachable"),
    "return call (fn)": ({"main.py": "import lib\ndef f():\n    return lib.vulnerable()\nf()\n"}, "reachable"),
    "lambda body call": ({"main.py": "import lib\nf = lambda: lib.vulnerable()\nf()\n"}, "reachable"),
    "comprehension call": ({"main.py": "import lib\nxs = [lib.vulnerable() for _ in range(2)]\n"}, "reachable"),
    "if test call": ({"main.py": "import lib\nif lib.vulnerable():\n    pass\n"}, "reachable"),
    "while test call": ({"main.py": "import lib\nwhile lib.vulnerable():\n    break\n"}, "reachable"),
    "with item call": ({"main.py": "import lib\nclass C:\n    def __enter__(self): return self\n    def __exit__(self,*a): return False\nwith C():\n    pass\n"}, "not_reachable"),  # control: C() not vulnerable
    "with expr vulnerable": ({"main.py": "import lib\nwith lib.vulnerable():\n    pass\n"}, "reachable"),
    "try body call": ({"main.py": "import lib\ntry:\n    lib.vulnerable()\nexcept Exception:\n    pass\n"}, "reachable"),
    "except handler call": ({"main.py": "import lib\ntry:\n    pass\nexcept Exception:\n    lib.vulnerable()\n"}, "reachable"),
    "finally call": ({"main.py": "import lib\ntry:\n    pass\nfinally:\n    lib.vulnerable()\n"}, "reachable"),
    "async await call": ({"main.py": "import asyncio, lib\nasync def h():\n    await lib.vulnerable()\nasyncio.run(h())\n"}, "reachable"),
    "generator yield call": ({"main.py": "import lib\ndef g():\n    yield lib.vulnerable()\nlist(g())\n"}, "reachable"),
    "class body call": ({"main.py": "import lib\nclass A:\n    X = lib.vulnerable()\n"}, "reachable"),
    "decorator call": ({"main.py": "import lib\ndef deco(f):\n    lib.vulnerable()\n    return f\n@deco\ndef g():\n    pass\ng()\n"}, "reachable"),
    "raise call": ({"main.py": "import lib\nraise lib.vulnerable()\n"}, "reachable"),
    "assert call": ({"main.py": "import lib\nassert lib.vulnerable()\n"}, "reachable"),
    "fstring call": ({"main.py": "import lib\nx = f'{lib.vulnerable()}'\n"}, "reachable"),
    "subscript call": ({"main.py": "import lib\nx = [0][lib.vulnerable()]\n"}, "reachable"),
    "match subject call": ({"main.py": "import lib\nmatch lib.vulnerable():\n    case _:\n        pass\n"}, "reachable"),
    "nested function call": ({"main.py": "import lib\ndef outer():\n    def inner():\n        lib.vulnerable()\n    inner()\nouter()\n"}, "reachable"),
    "callback map": ({"main.py": "import lib\nlist(map(lambda _: lib.vulnerable(), [1]))\n"}, "reachable"),
    "function as value then call": ({"main.py": "import lib\nf = lib.vulnerable\nf()\n"}, "reachable"),
    "dict-of-callables": ({"main.py": "import lib\nd = {'x': lib.vulnerable}\nd['x']()\n"}, "reachable"),
    "functools.partial": ({"main.py": "import lib, functools\nf = functools.partial(lib.vulnerable)\nf()\n"}, "reachable"),
    "Thread target": ({"main.py": "import lib, threading\nt = threading.Thread(target=lib.vulnerable)\nt.start()\nt.join()\n"}, "reachable"),
    "getattr literal": ({"main.py": "import lib\ngetattr(lib, 'vulnerable')()\n"}, "reachable"),
    "getattr variable": ({"main.py": "import lib\nname = 'vulnerable'\ngetattr(lib, name)()\n"}, "uncertain"),
    "import_module literal": ({"main.py": "import importlib\nlib = importlib.import_module('lib')\nlib.vulnerable()\n"}, "reachable"),
    "import_module variable": ({"main.py": "import importlib\nname = 'lib'\nlib = importlib.import_module(name)\nlib.vulnerable()\n"}, "uncertain"),
    "dunder import literal": ({"main.py": "lib = __import__('lib')\nlib.vulnerable()\n"}, "reachable"),
    "dunder import variable": ({"main.py": "name = 'lib'\nlib = __import__(name)\nlib.vulnerable()\n"}, "uncertain"),
    "entry_points from-import": ({"main.py": "from importlib.metadata import entry_points\nfor ep in entry_points().select(group='x'):\n    ep.load()()\n"}, "uncertain"),
    "entry_points attr": ({"main.py": "import importlib.metadata\nfor ep in importlib.metadata.entry_points().select(group='x'):\n    ep.load()()\n"}, "uncertain"),
    "pkgutil": ({"main.py": "import pkgutil, importlib\nfor m in pkgutil.iter_modules():\n    importlib.import_module(m.name)\n"}, "uncertain"),
    "subclasses": ({"main.py": "for c in object.__subclasses__():\n    c()\n"}, "uncertain"),
    "contextmanager enter": ({"main.py": "import lib\nclass H:\n    def __enter__(self):\n        return lib.vulnerable()\n    def __exit__(self,*a): return False\nwith H():\n    pass\n"}, "reachable"),
}

if __name__ == "__main__":
    only = sys.argv[1:] or list(CASES)
    mismatches = []
    for name, (files, expected) in CASES.items():
        if only and not any(o in name for o in only):
            continue
        files = {"lib.py": LIB, **files}
        project = make(name.replace(" ", "_").replace("/", "_").replace(".", "_"), files)
        # Determine target qualname: lib.vulnerable for lib.py
        try:
            v, _ = analyze(project, "lib.vulnerable", "lib.py")
            actual, conf = v.status, v.confidence
        except Exception as exc:  # crash is a finding
            actual, conf = f"CRASH:{type(exc).__name__}", "-"
        mark = "OK " if actual == expected else "FAIL"
        if actual != expected:
            mismatches.append((name, expected, actual))
        print(f"{mark} {name:34s} expected={expected:13s} actual={actual:22s} conf={conf}")
    print("\nMISMATCHES:", mismatches)
