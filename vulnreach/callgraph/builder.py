"""Call graph builder for VulnReach.

Walks a Python project tree (and an installed target dependency) and builds an
*over-approximating* call graph with :mod:`networkx`.

Nodes are qualified function names (with ``file`` and ``line``); edges are
possible calls.  When a call target cannot be resolved precisely, edges are
added to *all* functions with the matching name -- soundness over precision --
and those edges are flagged ``over_approx=True`` so the reachability analyzer
can downgrade confidence accordingly.

Entry points are module-level code, ``if __name__ == "__main__"`` blocks,
framework-decorated functions (@app.route, @click.command, @pytest.fixture, …)
and console_scripts entry points.
"""

from __future__ import annotations

import ast
import configparser
import importlib.metadata
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import networkx as nx

from vulnreach.callgraph.dynamic_detector import DynamicDetector, DynamicSite


@dataclass(frozen=True)
class CallNode:
    """A graph node: a qualified function name with source location."""

    qualname: str
    file: str
    line: int


@dataclass
class CallGraphResult:
    graph: nx.DiGraph
    entry_points: list[CallNode]
    dynamic_sites: list[DynamicSite]
    name_index: dict[str, list[CallNode]]
    # Files that could not be read or parsed.  Any non-empty entry means the
    # graph is incomplete, so the analyzer must not return ``not_reachable``.
    unparsed_files: list[str] = field(default_factory=list)
    # Call sites (inside the analysed project) whose callee could not be
    # resolved and whose receiver is the target dependency.  Such a call could
    # reach a vulnerable dependency function that is absent from the graph.
    unresolved_calls: list[str] = field(default_factory=list)


# A local name binding recorded during the import/definition pass.
@dataclass
class _Binding:
    kind: str  # "module", "attr", "function", "class", "instance"
    module: str | None = None
    attr: str | None = None
    qualname: str | None = None  # resolved qualified name, when known


class CallGraphBuilder:
    """Build a call graph for a Python project."""

    FRAMEWORK_DECORATORS = {
        "app.route", "route", "click.command", "command", "pytest.fixture", "fixture",
        "app.get", "app.post", "app.put", "app.delete", "app.patch", "bottle.route",
        "flask.route", "fastapi.get", "fastapi.post",
    }

    # Compound statements whose bodies may contain calls at the same caller level.
    COMPOUND_ATTRS = ("body", "orelse", "finalbody")

    def __init__(self, project_path: str | Path) -> None:
        self.project_path = Path(project_path).resolve()
        # Per-file collected info
        self._files: list[tuple[str, Path, ast.Module]] = []
        self._file_imports: dict[str, dict[str, _Binding]] = {}
        self._file_functions: dict[str, dict[str, CallNode]] = {}
        self._class_bases: dict[str, list[str]] = {}
        self._class_methods: dict[str, dict[str, CallNode]] = {}
        self._instance_types: dict[str, dict[str, str]] = {}
        # Global index: short name -> all CallNodes (for over-approximation)
        self._name_index: dict[str, list[CallNode]] = {}
        # Functions decorated with framework entry-point decorators
        self._framework_functions: set[str] = set()
        # Graph
        self.graph = nx.DiGraph()
        self.entry_points: list[CallNode] = []
        # Stack state while walking one file
        self._current_module: str = ""
        self._current_class: str | None = None
        self._current_caller: CallNode | None = None
        # Soundness bookkeeping (see CallGraphResult)
        self.unparsed_files: list[str] = []
        self.unresolved_calls: list[str] = []
        self._dependency_name: str | None = None

    # ------------------------------------------------------------------ cached subgraph

    def add_cached_subgraph(
        self,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        """Add a pre-built (cached) dependency subgraph to the graph.

        Nodes are dicts with ``qualname``, ``file``, ``line``; edges are dicts
        with ``source``, ``target`` and optional ``over_approx``.  This lets the
        CLI reuse a previously cached call graph for a dependency without
        re-parsing its source files.
        """
        for node in nodes:
            call_node = CallNode(
                qualname=node["qualname"],
                file=node.get("file", ""),
                line=int(node.get("line", 1)),
            )
            self.graph.add_node(call_node)
            self._name_index.setdefault(call_node.qualname.split(".")[-1], []).append(
                call_node
            )
        for edge in edges:
            source = self._find_node(edge["source"])
            target = self._find_node(edge["target"])
            if source is None or target is None:
                continue
            self.graph.add_edge(
                source, target, over_approx=bool(edge.get("over_approx", False))
            )

    # ------------------------------------------------------------------ public

    def build(
        self,
        dependency_name: str | None = None,
        include_dependency: bool = True,
    ) -> CallGraphResult:
        self._reset()
        self._dependency_name = dependency_name if include_dependency else None
        files = self._collect_project_files()
        if dependency_name and include_dependency:
            files.extend(self._collect_dependency_files(dependency_name))

        # Pass 1: parse + collect definitions, imports, classes, instance types
        for module, path in files:
            tree = self._parse_file(path)
            if tree is None:
                continue
            self._files.append((module, path, tree))
            self._collect_definitions(module, tree)

        # Pass 2: resolve calls and add edges
        for module, path, tree in self._files:
            self._resolve_module(module, tree)

        # Entry points
        self._find_entry_points()

        # Dynamic sites
        detector = DynamicDetector()
        dynamic_sites = detector.detect(self.project_path, self._files)

        return CallGraphResult(
            graph=self.graph,
            entry_points=self.entry_points,
            dynamic_sites=dynamic_sites,
            name_index=self._name_index,
            unparsed_files=list(self.unparsed_files),
            unresolved_calls=list(self.unresolved_calls),
        )

    # ------------------------------------------------------------------ reset / files

    def _reset(self) -> None:
        self.graph.clear()
        self.entry_points = []
        self._files = []
        self._file_imports = {}
        self._file_functions = {}
        self._class_bases = {}
        self._class_methods = {}
        self._instance_types = {}
        self._name_index = {}
        self._framework_functions = set()
        self.unparsed_files = []
        self.unresolved_calls = []
        self._dependency_name = None

    def _collect_project_files(self) -> list[tuple[str, Path]]:
        files: list[tuple[str, Path]] = []
        if not self.project_path.exists():
            return files
        for py in sorted(self.project_path.rglob("*.py")):
            # skip anything inside .git / __pycache__
            if any(part in {".git", "__pycache__"} for part in py.parts):
                continue
            rel = py.relative_to(self.project_path)
            module = self._rel_to_module(rel)
            files.append((module, py))
        return files

    def _collect_dependency_files(self, dependency_name: str) -> list[tuple[str, Path]]:
        """Best-effort: locate an installed distribution and list its .py files."""
        files: list[tuple[str, Path]] = []
        try:
            dist = importlib.metadata.distribution(dependency_name)
        except importlib.metadata.PackageNotFoundError:
            return files
        base: Path | None = None
        try:
            base = dist.locate_file("")
        except Exception:
            base = None
        if base is None or not base.is_dir():
            # Fall back: try importing to find __file__
            try:
                mod = __import__(dependency_name)
                base = Path(getattr(mod, "__file__", "") or "").parent
            except Exception:
                return files
        for py in sorted(base.rglob("*.py")):
            if any(part in {".git", "__pycache__", "tests", "test"} for part in py.parts):
                continue
            try:
                rel = py.relative_to(base)
            except ValueError:
                continue
            module = dependency_name + "." + self._rel_to_module(rel)
            files.append((module, py))
        return files

    @staticmethod
    def _rel_to_module(rel: Path) -> str:
        parts = [p for p in rel.parts]
        if parts and parts[-1].endswith(".py"):
            parts = parts[:-1] + [parts[-1][:-3]]
        return ".".join(parts)

    def _parse_file(self, path: Path) -> ast.Module | None:
        """Parse one file, recording any failure as an incomplete graph.

        A file we cannot read or parse could contain the only call path to the
        vulnerable function, so it must make the whole analysis ``uncertain``.
        """
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            self._record_unparsed(path, exc)
            return None
        try:
            return ast.parse(source, filename=str(path))
        except (SyntaxError, ValueError, RecursionError) as exc:
            self._record_unparsed(path, exc)
            return None

    def _record_unparsed(self, path: Path, exc: BaseException) -> None:
        self.unparsed_files.append(f"{self._display_file(path)} ({type(exc).__name__})")

    # ------------------------------------------------------------------ pass 1: definitions

    def _collect_definitions(self, module: str, tree: ast.Module) -> None:
        self._current_module = module
        self._current_class = None
        self._file_imports[module] = {}
        self._file_functions.setdefault(module, {})
        self._instance_types.setdefault(module, {})

        for node in tree.body:
            self._collect_stmt(module, node)

    def _collect_stmt(self, module: str, node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._collect_function(module, node, None)
        elif isinstance(node, ast.ClassDef):
            self._collect_class(module, node)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                self._record_import(module, alias.name, alias.asname)
        elif isinstance(node, ast.ImportFrom):
            level = node.level or 0
            if level > 0:
                base_module = self._relative_base(module, level)
            else:
                base_module = node.module
            for alias in node.names:
                if alias.name == "*":
                    continue
                target = f"{base_module}.{alias.name}" if base_module else alias.name
                local = alias.asname or alias.name
                self._file_imports[module][local] = _Binding(
                    kind="attr", module=target, attr=alias.name, qualname=target,
                )
        elif isinstance(node, ast.Assign):
            self._collect_assign(module, node)

    def _collect_function(
        self, module: str, node: ast.FunctionDef | ast.AsyncFunctionDef, class_qualname: str | None
    ) -> str:
        parts = [module]
        if class_qualname:
            parts.append(class_qualname.split(".")[-1])
        parts.append(node.name)
        qualname = ".".join(parts)

        call_node = CallNode(qualname=qualname, file=self._display_file(self._path_for_module(module)), line=node.lineno)
        self.graph.add_node(call_node)
        self._file_functions[module][qualname] = call_node
        self._name_index.setdefault(node.name, []).append(call_node)

        if self._has_framework_decorator(node):
            self._framework_functions.add(qualname)

        if class_qualname:
            self._class_methods.setdefault(class_qualname, {})[node.name] = call_node

        # Recurse into body for nested functions / classes / calls
        prev_class = self._current_class
        prev_caller = self._current_caller
        self._current_class = class_qualname
        self._current_caller = call_node
        for stmt in node.body:
            self._collect_stmt_in_func(module, stmt, class_qualname)
        self._current_class = prev_class
        self._current_caller = prev_caller
        return qualname

    def _collect_stmt_in_func(self, module: str, node: ast.AST, class_qualname: str | None) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._collect_function(module, node, class_qualname)
        elif isinstance(node, ast.ClassDef):
            self._collect_class(module, node)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                self._record_import(module, alias.name, alias.asname)
        elif isinstance(node, ast.ImportFrom):
            level = node.level or 0
            if level > 0:
                base_module = self._relative_base(module, level)
            else:
                base_module = node.module
            for alias in node.names:
                if alias.name == "*":
                    continue
                target = f"{base_module}.{alias.name}" if base_module else alias.name
                local = alias.asname or alias.name
                self._file_imports[module][local] = _Binding(
                    kind="attr", module=target, attr=alias.name, qualname=target,
                )
        elif isinstance(node, ast.Assign):
            self._collect_assign(module, node)

    def _collect_class(self, module: str, node: ast.ClassDef) -> None:
        bases = []
        for base in node.bases:
            bases.append(self._resolve_base_name(base))
        class_qualname = ".".join([module, node.name])
        self._class_bases[class_qualname] = [b for b in bases if b]
        self._class_methods.setdefault(class_qualname, {})

        prev_class = self._current_class
        prev_caller = self._current_caller
        self._current_class = class_qualname
        self._current_caller = None  # class body itself is not a caller
        for stmt in node.body:
            self._collect_stmt_in_func(module, stmt, class_qualname)
        self._current_class = prev_class
        self._current_caller = prev_caller

    def _collect_assign(self, module: str, node: ast.Assign) -> None:
        """Track `x = ClassName()` so we know instance types for method calls."""
        value = node.value
        class_name: str | None = None
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
            class_name = value.func.id
        elif isinstance(value, ast.Name):
            # x = y  -> copy binding type if known
            existing = self._instance_types[module].get(value.id)
            if existing:
                class_name = None  # we only store class names, not aliases
        if class_name is None:
            return
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._instance_types[module][target.id] = class_name
            elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
                self._instance_types[module][f"self.{target.attr}"] = class_name

    def _record_import(self, module: str, name: str, asname: str | None) -> None:
        local = asname or name.split(".")[0]
        self._file_imports[module][local] = _Binding(kind="module", module=name, attr=None, qualname=name)

    def _relative_base(self, module: str, level: int) -> str | None:
        parts = module.split(".")
        if level >= len(parts):
            return None
        return ".".join(parts[: len(parts) - level]) if level > 0 else None

    def _path_for_module(self, module: str) -> Path:
        for mod, path, _tree in self._files:
            if mod == module:
                return path
        return self.project_path / (module.replace(".", "/") + ".py")

    def _display_file(self, path: Path) -> str:
        """Return ``path`` relative to the project root when possible."""
        try:
            return str(path.relative_to(self.project_path))
        except ValueError:
            return str(path)

    # ------------------------------------------------------------------ pass 2: calls

    def _resolve_module(self, module: str, tree: ast.Module) -> None:
        module_node = CallNode(qualname=f"{module}.<module>", file=self._display_file(self._path_for_module(module)), line=1)
        if not self.graph.has_node(module_node):
            self.graph.add_node(module_node)
        self._name_index.setdefault("<module>", []).append(module_node)
        self._current_module = module
        self._current_class = None
        self._current_caller = module_node
        for stmt in tree.body:
            self._resolve_stmt(module, stmt)

    def _resolve_stmt(self, module: str, node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualname = self._function_qualname(module, node, self._current_class)
            caller = self._file_functions[module].get(qualname) or self._current_caller
            prev_class, prev_caller = self._current_class, self._current_caller
            self._current_class = self._current_class
            self._current_caller = caller
            for stmt in node.body:
                self._resolve_stmt_in_func(module, stmt)
            self._current_class, self._current_caller = prev_class, prev_caller
        elif isinstance(node, ast.ClassDef):
            class_qualname = ".".join([module, node.name])
            prev_class, prev_caller = self._current_class, self._current_caller
            self._current_class = class_qualname
            self._current_caller = None
            for stmt in node.body:
                self._resolve_stmt_in_func(module, stmt)
            self._current_class, self._current_caller = prev_class, prev_caller
        elif isinstance(node, ast.Assign):
            # instance tracking already done in pass 1; re-run for safety
            self._collect_assign(module, node)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            self._add_call_edge(module, node.value, self._current_caller)
        elif isinstance(node, ast.Return) and isinstance(node.value, ast.Call):
            self._add_call_edge(module, node.value, self._current_caller)
        elif isinstance(node, ast.If):
            self._resolve_compound(module, node, [node.body, node.orelse])
        elif isinstance(node, ast.For):
            self._resolve_compound(module, node, [node.body, node.orelse])
        elif isinstance(node, ast.While):
            self._resolve_compound(module, node, [node.body, node.orelse])
        elif isinstance(node, ast.Try):
            self._resolve_compound(module, node, [node.body, *node.handlers, node.orelse, node.finalbody])
        elif isinstance(node, ast.TryStar):
            self._resolve_compound(module, node, [node.body, *node.handlers, node.orelse, node.finalbody])
        elif isinstance(node, ast.With):
            self._resolve_compound(module, node, [node.body])
        elif isinstance(node, ast.Match):
            for case in node.cases:
                self._resolve_compound(module, case, [case.body])

    def _resolve_stmt_in_func(self, module: str, node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualname = self._function_qualname(module, node, self._current_class)
            caller = self._file_functions[module].get(qualname)
            prev_caller = self._current_caller
            if caller:
                self._current_caller = caller
            for stmt in node.body:
                self._resolve_stmt_in_func(module, stmt)
            self._current_caller = prev_caller
        elif isinstance(node, ast.ClassDef):
            class_qualname = ".".join([module, node.name])
            prev_class, prev_caller = self._current_class, self._current_caller
            self._current_class = class_qualname
            self._current_caller = None
            for stmt in node.body:
                self._resolve_stmt_in_func(module, stmt)
            self._current_class, self._current_caller = prev_class, prev_caller
        elif isinstance(node, ast.Assign):
            self._collect_assign(module, node)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            self._add_call_edge(module, node.value, self._current_caller)
        elif isinstance(node, ast.Return) and isinstance(node.value, ast.Call):
            self._add_call_edge(module, node.value, self._current_caller)
        elif isinstance(node, ast.If):
            self._resolve_compound(module, node, [node.body, node.orelse])
        elif isinstance(node, ast.For):
            self._resolve_compound(module, node, [node.body, node.orelse])
        elif isinstance(node, ast.While):
            self._resolve_compound(module, node, [node.body, node.orelse])
        elif isinstance(node, ast.Try):
            self._resolve_compound(module, node, [node.body, *node.handlers, node.orelse, node.finalbody])
        elif isinstance(node, ast.TryStar):
            self._resolve_compound(module, node, [node.body, *node.handlers, node.orelse, node.finalbody])
        elif isinstance(node, ast.With):
            self._resolve_compound(module, node, [node.body])
        elif isinstance(node, ast.Match):
            for case in node.cases:
                self._resolve_compound(module, case, [case.body])

    def _resolve_compound(self, module: str, node: ast.AST, groups: list[list[ast.AST]]) -> None:
        for group in groups:
            for stmt in group:
                if stmt is None:
                    continue
                self._resolve_stmt_in_func(module, stmt)

    def _function_qualname(self, module: str, node: ast.FunctionDef | ast.AsyncFunctionDef, class_qualname: str | None) -> str:
        parts = [module]
        if class_qualname:
            parts.append(class_qualname.split(".")[-1])
        parts.append(node.name)
        return ".".join(parts)

    def _add_call_edge(self, module: str, call: ast.Call, caller: CallNode | None) -> None:
        if caller is None:
            return
        callees, over_approx = self._resolve_call_targets(module, call.func)
        if not callees and self._call_targets_dependency(module, call.func):
            # This call is aimed at the vulnerable dependency but we could not
            # map it to any graph node.  It could therefore reach a vulnerable
            # function we never indexed; record it so the analyzer stays
            # ``uncertain`` instead of declaring the package safe.
            try:
                rendered = ast.unparse(call.func)
            except Exception:
                rendered = "<unprintable>"
            self.unresolved_calls.append(
                f"{self._display_file(self._path_for_module(module))}:{call.lineno} "
                f"unresolved call to {rendered}"
            )
        for callee in callees:
            if callee is caller:
                continue
            self.graph.add_edge(caller, callee, over_approx=over_approx)

    def _call_targets_dependency(self, module: str, func_expr: ast.AST) -> bool:
        """Return True when a call's receiver is imported from the dependency."""
        dependency = self._dependency_name
        if not dependency:
            return False
        root = self._root_name(func_expr)
        if root is None:
            return False
        binding = self._file_imports.get(module, {}).get(root)
        if binding is None:
            return False
        target = binding.qualname or binding.module or ""
        return target == dependency or target.startswith(dependency + ".")

    @staticmethod
    def _root_name(func_expr: ast.AST) -> str | None:
        if isinstance(func_expr, ast.Name):
            return func_expr.id
        if isinstance(func_expr, ast.Attribute):
            return CallGraphBuilder._root_name(func_expr.value)
        return None

    def _resolve_call_targets(self, module: str, func_expr: ast.AST) -> tuple[list[CallNode], bool]:
        """Return (possible callees, whether resolution was over-approximated)."""
        if isinstance(func_expr, ast.Name):
            return self._resolve_name_call(module, func_expr.id)
        if isinstance(func_expr, ast.Attribute):
            return self._resolve_attribute_call(module, func_expr)
        # lambda / conditional / other -> cannot resolve precisely
        return [], True

    def _resolve_name_call(self, module: str, name: str) -> tuple[list[CallNode], bool]:
        # Function defined in this module with matching short name
        for qualname, node in self._file_functions[module].items():
            if qualname.split(".")[-1] == name:
                return [node], False
        # Imported binding pointing at a specific function
        binding = self._file_imports[module].get(name)
        if binding is not None and binding.qualname:
            node = self._find_node(binding.qualname)
            if node:
                return [node], False
        # Over-approximate: all functions with this short name
        return list(self._name_index.get(name, [])), True

    def _resolve_attribute_call(self, module: str, expr: ast.Attribute) -> tuple[list[CallNode], bool]:
        attr = expr.attr
        value = expr.value

        if isinstance(value, ast.Name) and value.id == "self":
            return self._resolve_method_on_class(self._current_class or "", attr)

        if isinstance(value, ast.Name):
            var_type = self._instance_types[module].get(value.id)
            if var_type:
                return self._resolve_method_on_class(var_type, attr)
            var_type = self._instance_types[module].get(f"self.{value.id}")
            if var_type:
                return self._resolve_method_on_class(var_type, attr)
            # Unknown object: over-approximate all functions with attr name
            return list(self._name_index.get(attr, [])), True

        if isinstance(value, ast.Attribute):
            # Chained a.b.c() -> over-approximate by final attr
            return list(self._name_index.get(attr, [])), True

        if isinstance(value, ast.Call):
            # foo().bar() -> over-approximate
            return list(self._name_index.get(attr, [])), True

        return list(self._name_index.get(attr, [])), True

    def _resolve_method_on_class(self, class_qualname: str, method_name: str) -> tuple[list[CallNode], bool]:
        if not class_qualname:
            return list(self._name_index.get(method_name, [])), True
        # Walk MRO: class then its bases recursively
        visited: set[str] = set()
        stack: list[str] = [class_qualname]
        while stack:
            cls = stack.pop()
            if cls in visited:
                continue
            visited.add(cls)
            methods = self._class_methods.get(cls, {})
            if method_name in methods:
                return [methods[method_name]], False
            stack.extend(self._class_bases.get(cls, []))
        # Not found in hierarchy: over-approximate
        return list(self._name_index.get(method_name, [])), True

    def _resolve_base_name(self, base: ast.AST) -> str:
        if isinstance(base, ast.Name):
            return base.id
        if isinstance(base, ast.Attribute):
            return base.attr
        return ""

    def _find_node(self, qualname: str) -> CallNode | None:
        for module_nodes in self._file_functions.values():
            if qualname in module_nodes:
                return module_nodes[qualname]
        return None

    @staticmethod
    def _short_name(func_expr: ast.AST) -> str:
        if isinstance(func_expr, ast.Name):
            return func_expr.id
        if isinstance(func_expr, ast.Attribute):
            return func_expr.attr
        return ""

    @staticmethod
    def _has_framework_decorator(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for dec in func_node.decorator_list:
            name = CallGraphBuilder._decorator_name(dec)
            if name in CallGraphBuilder.FRAMEWORK_DECORATORS:
                return True
        return False

    @staticmethod
    def _decorator_name(dec: ast.AST) -> str:
        if isinstance(dec, ast.Name):
            return dec.id
        if isinstance(dec, ast.Attribute):
            return dec.attr
        if isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Name):
                return dec.func.id
            if isinstance(dec.func, ast.Attribute):
                return dec.func.attr
        return ""

    # ------------------------------------------------------------------ entry points

    def _find_entry_points(self) -> None:
        seen: set[str] = set()

        # Every module-level node is an entry point (module-level code runs on import).
        for mod, path, _tree in self._files:
            node = CallNode(
                qualname=f"{mod}.<module>",
                file=self._display_file(path),
                line=1,
            )
            if node.qualname not in seen:
                seen.add(node.qualname)
                self.entry_points.append(node)

        # Framework-decorated functions (recorded during pass 1).
        for qualname in self._framework_functions:
            node = self._find_node(qualname)
            if node and node.qualname not in seen:
                seen.add(node.qualname)
                self.entry_points.append(node)

        # console_scripts from pyproject.toml / setup.cfg / setup.py
        for entry in self._console_script_entries():
            qualname = entry.get("qualname")
            path = entry.get("file")
            line = entry.get("line", 1)
            if qualname and path:
                node = CallNode(qualname=qualname, file=str(path), line=line)
                if node.qualname not in seen:
                    seen.add(node.qualname)
                    self.entry_points.append(node)

    def _console_script_entries(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        pyproject = self.project_path / "pyproject.toml"
        if pyproject.exists():
            try:
                data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            scripts = data.get("project", {}).get("scripts", {})
            for _name, spec in scripts.items():
                entries.extend(self._parse_script_spec(spec, pyproject))
        setup_cfg = self.project_path / "setup.cfg"
        if setup_cfg.exists():
            cp = configparser.ConfigParser()
            cp.read(setup_cfg, encoding="utf-8")
            if cp.has_section("options.entry_points"):
                for _name, spec in cp.items("options.entry_points"):
                    entries.extend(self._parse_script_spec(spec, setup_cfg))
        return entries

    @staticmethod
    def _parse_script_spec(spec: str, source_file: Path) -> list[dict[str, Any]]:
        # spec like "name = module:function"
        entries: list[dict[str, Any]] = []
        if "=" not in spec:
            return entries
        _, rhs = spec.split("=", 1)
        rhs = rhs.strip()
        if ":" not in rhs:
            return entries
        mod, func = rhs.split(":", 1)
        # locate the file
        candidate = source_file.parent / (mod.replace(".", "/") + ".py")
        if not candidate.exists():
            # search project
            for py in source_file.parent.rglob("*.py"):
                rel = py.relative_to(source_file.parent)
                if ".".join(rel.parts[:-1] + (rel.stem,)) == mod:
                    candidate = py
                    break
        entries.append({"qualname": f"{mod}.{func}", "file": str(candidate), "line": 1})
        return entries
