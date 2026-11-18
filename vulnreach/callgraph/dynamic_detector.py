"""Dynamic feature detection for VulnReach.

Walks Python source trees and records every dynamic construct that could hide a
call path to vulnerable code.  Each finding is a :class:`DynamicSite` with a
file, line, kind and short detail.

The goal is *soundness*: if any of these constructs exists in reachable code, we
cannot rule out a hidden path, so the analyzer must emit ``uncertain`` rather
than ``not_reachable``.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DynamicSite:
    """One dynamic construct that could obscure reachability."""

    file: str
    line: int
    kind: str
    detail: str = ""

    def __str__(self) -> str:
        return f"{self.file}:{self.line} [{self.kind}] {self.detail}"


class DynamicDetector:
    """Detect dynamic Python features in a tree of source files."""

    # Kinds
    GETATTR = "getattr"
    SETATTR = "setattr"
    IMPORTLIB = "importlib.import_module"
    IMPORT_BUILTIN = "__import__"
    EVAL = "eval"
    EXEC = "exec"
    ENTRY_POINTS = "entry_points"
    PKG_RESOURCES = "pkg_resources_plugin_loading"
    PKGUTIL = "pkgutil.iter_modules"
    GLOBALS_CALL = "globals_call"
    KWARGS_FORWARD = "kwargs_forward"
    DICT_DISPATCH = "dict_dispatch"
    PICKLE_UNSAFE = "pickle_unsafe_load"
    YAML_UNSAFE = "yaml_unsafe_load"

    def __init__(self) -> None:
        self.sites: list[DynamicSite] = []

    # ------------------------------------------------------------------ public

    def detect(self, project_path: str | Path, files: list[tuple[str, Path, Any]]) -> list[DynamicSite]:
        """Detect dynamic sites in every parsed file of ``files``.

        ``files`` is a list of ``(module, path, tree)`` tuples as produced by
        :class:`CallGraphBuilder`.
        """
        self.sites = []
        for _module, path, tree in files:
            self._detect_in_tree(str(path), tree)
        return list(self.sites)

    def detect_in_source(self, file: str, source: str) -> list[DynamicSite]:
        """Detect dynamic sites in a single source string."""
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        before = len(self.sites)
        self._detect_in_tree(file, tree)
        return self.sites[before:]

    # ------------------------------------------------------------------ walking

    def _detect_in_tree(self, file: str, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            self._check_node(file, node)

    # ------------------------------------------------------------------ checks

    def _check_node(self, file: str, node: ast.AST) -> None:
        # getattr / setattr with non-literal name
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            name = node.func.id
            if name in {"getattr", "setattr"} and len(node.args) >= 2:
                attr_arg = node.args[1]
                if not self._is_literal_str(attr_arg):
                    self._add(
                        file, node.lineno,
                        self.GETATTR if name == "getattr" else self.SETATTR,
                        f"{name}(obj, <non-literal>)",
                    )
                return

            # importlib.import_module / __import__ with non-literal name
            if name == "import_module" and node.args and not self._is_literal_str(node.args[0]):
                self._add(file, node.lineno, self.IMPORTLIB, "import_module(<non-literal>)")
                return
            if name == "__import__" and node.args and not self._is_literal_str(node.args[0]):
                self._add(file, node.lineno, self.IMPORT_BUILTIN, "__import__(<non-literal>)")
                return

            # eval / exec
            if name in {"eval", "exec"}:
                self._add(file, node.lineno, name.upper(), f"{name}(...)")
                return

            # entry_points() called by bare name (from importlib.metadata import entry_points)
            if name == "entry_points":
                self._add(file, node.lineno, self.ENTRY_POINTS, "entry_points()")
                return

        # attribute calls: importlib.import_module(...), pkgutil.iter_modules(),
        # entry_points(), pkg_resources..., pickle.loads, yaml.load
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            value = node.func.value

            # importlib.import_module / importlib.util ...
            if self._is_name(value, "importlib"):
                if attr == "import_module" and node.args and not self._is_literal_str(node.args[0]):
                    self._add(file, node.lineno, self.IMPORTLIB, "importlib.import_module(<non-literal>)")
                return

            # pkgutil.iter_modules
            if self._is_name(value, "pkgutil") and attr == "iter_modules":
                self._add(file, node.lineno, self.PKGUTIL, "pkgutil.iter_modules()")
                return

            # pkg_resources / importlib.metadata entry_points
            if attr == "entry_points" and self._is_importlib_metadata(value):
                self._add(file, node.lineno, self.ENTRY_POINTS, "entry_points()")
                return
            if isinstance(value, ast.Attribute) and self._is_name(value.value, "pkg_resources") and value.attr == "iter_entry_points":
                self._add(file, node.lineno, self.PKG_RESOURCES, "pkg_resources.iter_entry_points()")
                return

            # object.__subclasses__() -- can iterate over every loaded class
            if (
                attr == "__subclasses__"
                and isinstance(value, ast.Name)
                and value.id == "object"
            ):
                self._add(file, node.lineno, "subclasses", "object.__subclasses__()")
                return

            # pickle.loads / pickle.load (unsafe)
            if self._is_name(value, "pickle") and attr in {"loads", "load"}:
                self._add(file, node.lineno, self.PICKLE_UNSAFE, f"pickle.{attr}()")
                return

            # yaml.load (unsafe unless Loader=SafeLoader)
            if self._is_name(value, "yaml") and attr == "load":
                safe = any(
                    kw.arg == "Loader" and isinstance(kw.value, ast.Name) and kw.value.id == "SafeLoader"
                    for kw in node.keywords
                )
                if not safe:
                    self._add(file, node.lineno, self.YAML_UNSAFE, "yaml.load() without SafeLoader")
                return

        # globals()[name]() / locals()[name]()
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Subscript):
            if isinstance(node.func.value, ast.Name) and node.func.value.id in {"globals", "locals"}:
                self._add(file, node.lineno, self.GLOBALS_CALL, f"{node.func.value.id}[...]()")
                return

        # dict-of-callables dispatch: {...}[key]()
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Subscript):
            if isinstance(node.func.value, ast.Dict):
                self._add(file, node.lineno, self.DICT_DISPATCH, "{...}[key]() dispatch")
                return

        # **kwargs forwarded to a callable: func(**kwargs)
        if isinstance(node, ast.Call):
            has_kwargs = any(
                isinstance(kw, ast.keyword) and kw.arg is None
                for kw in node.keywords
            )
            if has_kwargs:
                self._add(file, node.lineno, self.KWARGS_FORWARD, "call with **kwargs")
                return

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _is_literal_str(node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return True
        return False

    @staticmethod
    def _is_name(node: ast.AST, names: str | tuple[str, ...]) -> bool:
        if not isinstance(node, ast.Name):
            return False
        if isinstance(names, str):
            return node.id == names
        return node.id in names

    @staticmethod
    def _is_importlib_metadata(node: ast.AST) -> bool:
        """Return True if ``node`` is ``importlib.metadata`` (Name or Attribute chain)."""
        if isinstance(node, ast.Name):
            return node.id == "importlib.metadata"
        if isinstance(node, ast.Attribute):
            if node.attr == "metadata":
                return isinstance(node.value, ast.Name) and node.value.id == "importlib"
        return False

    def _add(self, file: str, line: int, kind: str, detail: str = "") -> None:
        self.sites.append(DynamicSite(file=file, line=line, kind=kind, detail=detail))
