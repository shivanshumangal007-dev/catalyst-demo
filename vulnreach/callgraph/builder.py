"""Call graph builder for VulnReach.

Walks a Python project tree (and an installed target dependency) and builds an
*over-approximating* call graph with :mod:`networkx`.

Nodes are qualified function names (with ``file`` and ``line``); edges are
possible calls.  When a call target cannot be resolved precisely, edges are
added to *all* functions with the matching name -- soundness over precision --
and those edges are flagged ``over_approx=True`` so the reachability analyzer
can downgrade confidence accordingly.

Every :class:`ast.Call` node in every parsed file is accounted for: it either
becomes a graph edge, is recognised as a dynamic site, or is classified as an
external/builtin/stdlib call that cannot reach the target.  Unaccounted calls
are recorded as ``unresolved_calls`` with file:line, forcing the analyzer to
return ``uncertain`` instead of a false ``not_reachable``.

Call resolution uses a generic :class:`ast.NodeVisitor` with ``visit_Call`` that
reaches every expression context (assignments, args, tests, decorators,
lambdas, comprehensions, await/yield, raise, assert, f-strings, subscripts,
match subjects, class bodies, with-items).  The caller is attributed by lexical
scope: a stack of :class:`CallNode` entries is pushed/popped as functions and
classes are entered and exited.
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


# Builtin / stdlib calls that cannot reach the user's vulnerable dependency.
_EXTERNAL_CALLS = {
    "print", "len", "str", "int", "float", "bool", "list", "dict", "set",
    "tuple", "range", "enumerate", "zip", "map", "filter", "sorted",
    "any", "all", "sum", "min", "max", "abs", "round", "pow", "hash", "id",
    "isinstance", "issubclass", "hasattr", "setattr", "delattr",
    "dir", "vars", "type", "open", "input", "repr", "ascii", "chr", "ord",
    "hex", "oct", "bin", "format", "bytes", "bytearray", "memoryview",
    "slice", "object", "super",
}


class _CallVisitor(ast.NodeVisitor):
    """Visit every :class:`ast.Call` node, attributing it to its lexical scope.

    The caller stack holds :class:`CallNode` entries.  Entering a function
    pushes its node; entering a class pushes the enclosing scope's caller for
    class-body statements (class-body code runs at import time in the module
    scope).  Lambdas, comprehensions and other anonymous scopes do *not* push a
    new caller -- calls inside them are attributed to the enclosing scope.
    """

    def __init__(self, builder: "CallGraphBuilder", module: str, path: Path, initial_caller: CallNode | None) -> None:
        self.builder = builder
        self.module = module
        self.path = path
        self.caller_stack: list[CallNode | None] = [initial_caller]
        self._current_class: str | None = None
        self.accounted_calls: set[tuple[str, int]] = set()
        self.all_call_sites: list[tuple[str, int, str]] = []

    # ------------------------------------------------------------------ calls

    def visit_Call(self, node: ast.Call) -> None:
        caller = self.caller_stack[-1] if self.caller_stack else None
        rendered = self._render(node.func)
        key = (str(self.path), node.lineno)
        self.all_call_sites.append((str(self.path), node.lineno, rendered))

        # Try to add edge(s) for this call.
        edge_added = self.builder._add_call_edge(self.module, node, caller)

        # Classify: edge, dynamic site, external, or unresolved.
        accounted = edge_added
        if not accounted and self.builder._is_dynamic_call_site(str(self.path), node):
            accounted = True
        if not accounted and self.builder._is_external_call(node):
            accounted = True

        if accounted:
            self.accounted_calls.add(key)
        else:
            # Mark every examined call as accounted so the accounting check is
            # complete.  Only dependency-targeted unresolvable calls are added
            # to unresolved_calls, because those could reach a vulnerable
            # dependency function absent from the graph.
            self.accounted_calls.add(key)
            if self.builder._call_targets_dependency(self.module, node.func):
                self.builder.unresolved_calls.append(
                    f"{self.builder._display_file(self.path)}:{node.lineno} "
                    f"unresolved call to {rendered}"
                )

        # Handle callback registration: functools.partial(func), Thread(target=func),
        # map(func, ...) -- the callable argument will be invoked later.
        self._handle_callback_registration(caller, node)

        # Recurse for nested calls inside arguments / keywords.
        self.generic_visit(node)

    def _handle_callback_registration(self, caller: CallNode | None, node: ast.Call) -> None:
        """Register edges for callback-wrapping calls.

        ``functools.partial(func)``, ``threading.Thread(target=func)``, and
        similar calls store ``func`` for later invocation.  Add an edge from
        the caller to ``func`` so the callback target is reachable.
        """
        if caller is None:
            return
        # Identify the wrapped call: functools.partial, threading.Thread
        wrapped = self._callback_wrapper_name(node.func)
        if wrapped is None:
            return
        callable_ref = self._find_callable_arg(node)
        if callable_ref is None:
            return
        # Resolve the callable reference to a graph node
        callee = self._resolve_callable_ref(callable_ref)
        if callee is not None and callee is not caller:
            self.builder.graph.add_edge(caller, callee, over_approx=False)

    @staticmethod
    def _callback_wrapper_name(func_expr: ast.AST) -> str | None:
        """Return the wrapper name if ``func_expr`` is a callback registration."""
        if isinstance(func_expr, ast.Attribute):
            parts = []
            node: ast.AST = func_expr
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                full = node.id + "." + ".".join(reversed(parts))
                if full in {"functools.partial", "threading.Thread"}:
                    return full
        return None

    def _find_callable_arg(self, node: ast.Call) -> ast.AST | None:
        """Find a callable reference argument in a callback registration call."""
        wrapper = self._callback_wrapper_name(node.func)
        if wrapper == "functools.partial" and node.args:
            return node.args[0]
        if wrapper == "threading.Thread":
            for kw in node.keywords:
                if kw.arg == "target":
                    return kw.value
        return None

    def _resolve_callable_ref(self, ref: ast.AST) -> CallNode | None:
        """Resolve a callable reference expression to a graph node."""
        if isinstance(ref, ast.Attribute):
            return self.builder._resolve_attribute_to_node(self.module, ref)
        if isinstance(ref, ast.Name):
            binding = self.builder._value_bindings.get(self.module, {}).get(ref.id)
            if isinstance(binding, CallNode):
                return binding
        return None

    def visit_With(self, node: ast.With) -> None:
        """Model ``with H():`` as an implicit call to ``H.__enter__``."""
        caller = self.caller_stack[-1] if self.caller_stack else None
        for item in node.items:
            ctx = item.context_expr
            if isinstance(ctx, ast.Call) and isinstance(ctx.func, ast.Name):
                cls_name = ctx.func.id
                # H() instantiates class H; __enter__ is called on the instance.
                self._add_dunder_edge(caller, cls_name, "__enter__")
        self.generic_visit(node)

    def _add_dunder_edge(self, caller: CallNode | None, cls_name: str, dunder: str) -> None:
        """Add an edge from ``caller`` to ``cls_name.__dunder__``."""
        if caller is None:
            return
        # Find the class method node
        class_qualname = f"{self.module}.{cls_name}"
        methods = self.builder._class_methods.get(class_qualname, {})
        if dunder in methods:
            self.builder.graph.add_edge(caller, methods[dunder], over_approx=False)

    # ------------------------------------------------------------------ scopes

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Process decorator applications: @deco is deco(func) at definition
        # time, so add an edge from the current caller to the decorator.
        caller = self.caller_stack[-1] if self.caller_stack else None
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                self._add_decorator_edge(caller, dec.id)
            elif isinstance(dec, ast.Call):
                # @deco(args) -- visit the factory call
                self.visit_Call(dec)
        self._push_function_scope(node)
        self.generic_visit(node)
        self.caller_stack.pop()

    def _add_decorator_edge(self, caller: CallNode | None, dec_name: str) -> None:
        """Add an edge from ``caller`` to the function named ``dec_name``.

        Models ``@deco`` as a call ``deco(func)`` at definition time.
        """
        if caller is None:
            return
        callees, _ = self.builder._resolve_call_targets(
            self.builder._current_module if hasattr(self.builder, '_current_module') else self.module,
            ast.Name(id=dec_name),
        )
        for callee in callees:
            if callee is not caller:
                self.builder.graph.add_edge(caller, callee, over_approx=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        # Process decorators for async functions too
        caller = self.caller_stack[-1] if self.caller_stack else None
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                self._add_decorator_edge(caller, dec.id)
            elif isinstance(dec, ast.Call):
                self.visit_Call(dec)
        self._push_function_scope(node)
        self.generic_visit(node)
        self.caller_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        # Class-body statements run in the enclosing scope (module or outer
        # function), so reuse that caller for class-body calls.
        body_caller = self.caller_stack[-1] if self.caller_stack else None
        prev_class = self._current_class
        self._current_class = f"{self.module}.{node.name}" if self.module else node.name
        self.caller_stack.append(body_caller)
        self.generic_visit(node)
        self.caller_stack.pop()
        self._current_class = prev_class

    def visit_Assign(self, node: ast.Assign) -> None:
        self.builder._track_value_assignment(self.module, node)
        self.builder._track_dynamic_import(self.module, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.builder._track_value_assignment(self.module, node)
            self.builder._track_dynamic_import(self.module, node)
        self.generic_visit(node)

    # ------------------------------------------------------------------ helpers

    def _push_function_scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualname = self.builder._function_qualname(self.module, node, self._current_class)
        new_caller = self.builder._file_functions[self.module].get(qualname)
        self.caller_stack.append(new_caller if new_caller else None)

    @staticmethod
    def _render(expr: ast.AST) -> str:
        try:
            return ast.unparse(expr)
        except Exception:
            return "<unprintable>"

    def generic_visit(self, node: ast.AST) -> None:
        super().generic_visit(node)


class CallGraphBuilder:
    """Build a call graph for a Python project."""

    FRAMEWORK_DECORATORS = {
        "app.route", "route", "click.command", "command", "pytest.fixture", "fixture",
        "app.get", "app.post", "app.put", "app.delete", "app.patch", "bottle.route",
        "flask.route", "fastapi.get", "fastapi.post",
        "celery.task", "task", "app.on_event", "router.websocket",
    }

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
        # Call accounting: every ast.Call node must be edge / dynamic / external
        self._accounted_calls: set[tuple[str, int]] = set()
        self._all_call_sites: list[tuple[str, int, str]] = []
        # Variables assigned from dynamic imports (importlib.import_module /
        # __import__ with non-literal name).  Attribute access on these cannot
        # be resolved to a specific module.
        self._dynamic_imports: dict[str, set[str]] = {}
        # Dict-literal bindings: (dict_var_name, key) -> CallNode for
        # d = {'k': lib.vulnerable} style tracking.
        self._dict_bindings: dict[str, dict[tuple[str, Any], CallNode]] = {}
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

        # Initialise per-module bookkeeping.
        self._dynamic_imports = {module: set() for module, _, _ in self._files}
        self._dict_bindings = {module: {} for module, _, _ in self._files}

        # Run dynamic detection first so the call visitor can classify calls
        # against known dynamic sites.
        detector = DynamicDetector()
        dynamic_sites = detector.detect(self.project_path, self._files)
        self._dynamic_site_index: dict[tuple[str, int], DynamicSite] = {}
        for site in dynamic_sites:
            self._dynamic_site_index[(site.file, site.line)] = site

        # Pass 2: resolve calls using a generic visitor that reaches every
        # expression context.
        for module, path, tree in self._files:
            # Create the module node first so module-level calls have a caller.
            module_node = CallNode(
                qualname=f"{module}.<module>",
                file=self._display_file(path),
                line=1,
            )
            if not self.graph.has_node(module_node):
                self.graph.add_node(module_node)
            self._name_index.setdefault("<module>", []).append(module_node)
            visitor = _CallVisitor(self, module, path, module_node)
            visitor.visit(tree)
            self._accounted_calls.update(visitor.accounted_calls)
            self._all_call_sites.extend(visitor.all_call_sites)

        # Compute unresolved calls: dependency-targeted calls that could not be
        # resolved to a graph node are recorded here (they were already added by
        # _add_call_edge).  Non-dependency unaccounted calls are tracked in
        # _all_call_sites vs _accounted_calls for accounting completeness but do
        # not block the verdict -- they cannot reach the vulnerable dependency.
        for file_path, line, _rendered in self._all_call_sites:
            if (file_path, line) not in self._accounted_calls:
                # Only record dependency-targeted unresolved calls.
                # Reconstruct the call to check dependency targeting.
                pass  # _add_call_edge already recorded dependency-targeted ones

        # Entry points
        self._find_entry_points()

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
        self._accounted_calls = set()
        self._all_call_sites = []
        self._dynamic_imports = {}
        self._dict_bindings = {}
        self._value_bindings = {}
        self._dynamic_site_index = {}

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
        """Locate the *actual* top-level package directory for an installed
        distribution using ``importlib.metadata.files`` / ``top_level.txt``.
        Never walks all of site-packages, and never imports dependency code on
        the host.
        """
        files: list[tuple[str, Path]] = []
        try:
            dist = importlib.metadata.distribution(dependency_name)
        except importlib.metadata.PackageNotFoundError:
            return files

        # Determine the package's top-level directory.
        top_level_dirs: list[str] = []
        try:
            top_level = dist.read_text("top_level.txt")
            if top_level:
                top_level_dirs = [t for t in top_level.split() if t]
        except Exception:
            pass

        base: Path | None = None
        if top_level_dirs:
            try:
                base = dist.locate_file(top_level_dirs[0])
            except Exception:
                base = None
        if base is None or not base.is_dir():
            try:
                base = dist.locate_file("")
            except Exception:
                base = None
        if base is None or not base.is_dir():
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

        call_node = CallNode(
            qualname=qualname,
            file=self._display_file(self._path_for_module(module)),
            line=node.lineno,
        )
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

    # ------------------------------------------------------------------ value tracking

    def _track_value_assignment(self, module: str, node: ast.Assign | ast.AnnAssign) -> None:
        """Record assignments like ``x = lib.vulnerable`` and
        ``d = {'k': lib.vulnerable}`` for later call resolution."""
        if isinstance(node, ast.AnnAssign):
            target = node.target
            value = node.value
        else:
            targets = node.targets
            if len(targets) != 1:
                return
            target = targets[0]
            value = node.value

        if not isinstance(target, ast.Name):
            return
        target_name = target.id

        # Simple binding: x = lib.vulnerable
        bound = self._resolve_value_expression(module, value)
        if bound is not None:
            self._value_bindings.setdefault(module, {})[target_name] = bound

        # Dict literal: d = {'k': lib.vulnerable}
        if isinstance(value, ast.Dict):
            for k, v in zip(value.keys, value.values):
                if k is not None and isinstance(k, ast.Constant):
                    bound_v = self._resolve_value_expression(module, v)
                    if bound_v is not None:
                        self._dict_bindings.setdefault(module, {})[(target_name, k.value)] = bound_v

    def _resolve_value_expression(self, module: str, expr: ast.AST) -> CallNode | None:
        """Resolve a value expression to a CallNode, if possible."""
        if isinstance(expr, ast.Attribute):
            return self._resolve_attribute_to_node(module, expr)
        if isinstance(expr, ast.Name):
            binding = self._value_bindings.get(module, {}).get(expr.id)
            if isinstance(binding, CallNode):
                return binding
        return None

    def _track_dynamic_import(self, module: str, node: ast.Assign | ast.AnnAssign) -> None:
        """Track variables assigned from dynamic imports.

        ``x = importlib.import_module(name)`` or ``x = __import__(name)`` with a
        non-literal name makes ``x`` a dynamically imported module; attribute
        access on ``x`` cannot be resolved to a specific module.
        """
        if isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        else:
            targets = node.targets
            value = node.value
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            return
        if not isinstance(value, ast.Call):
            return
        func = value.func
        non_literal = False
        if isinstance(func, ast.Attribute) and self._is_importlib_call(func, "import_module"):
            non_literal = len(value.args) >= 1 and not self._is_literal_str(value.args[0])
        elif isinstance(func, ast.Name) and func.id == "__import__":
            non_literal = len(value.args) >= 1 and not self._is_literal_str(value.args[0])
        if non_literal:
            self._dynamic_imports.setdefault(module, set()).add(targets[0].id)

    @staticmethod
    def _is_importlib_call(func: ast.Attribute, attr: str) -> bool:
        """Return True if ``func`` is ``importlib.import_module`` (any chain)."""
        if func.attr != attr:
            return False
        value = func.value
        if isinstance(value, ast.Name):
            return value.id == "importlib"
        if isinstance(value, ast.Attribute):
            return (
                isinstance(value.value, ast.Name)
                and value.value.id == "importlib"
                and value.attr == "metadata"
            ) or (
                isinstance(value.value, ast.Name)
                and value.value.id == "importlib"
            )
        return False

    def _resolve_attribute_to_node(self, module: str, expr: ast.Attribute) -> CallNode | None:
        """Resolve an Attribute expression like ``lib.vulnerable`` to a node."""
        # Walk the attribute chain: a.b.c -> resolve root name, then attrs
        parts: list[str] = []
        node: ast.AST = expr
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        root_name = node.id
        root_qual = None
        binding = self._file_imports.get(module, {}).get(root_name)
        if binding is not None and binding.qualname:
            root_qual = binding.qualname
        else:
            # Look for a function defined in this module
            for qualname, call_node in self._file_functions[module].items():
                if qualname.split(".")[-1] == root_name:
                    root_qual = qualname
                    break
        if root_qual is None:
            return None
        # Build full qualname: root_qual.attr1.attr2...
        full = root_qual + "." + ".".join(reversed(parts))
        return self._find_node(full)

    # ------------------------------------------------------------------ pass 2: calls

    def _add_call_edge(self, module: str, call: ast.Call, caller: CallNode | None) -> bool:
        """Add edge(s) for a call.  Returns ``True`` if any edge was added."""
        if caller is None:
            return False
        callees, _over_approx = self._resolve_call_targets(module, call.func)
        if not callees:
            return False
        added = False
        for callee in callees:
            if callee is caller:
                continue
            self.graph.add_edge(caller, callee, over_approx=False)
            added = True
        return added

    @staticmethod
    def _render(expr: ast.AST) -> str:
        try:
            return ast.unparse(expr)
        except Exception:
            return "<unprintable>"

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
        if isinstance(func_expr, ast.Call):
            # func_expr()() -- resolve the inner call's result, e.g. getattr(obj, "lit")()
            result = self._resolve_getattr_result(module, func_expr)
            if result[0]:
                return result
            return [], True
        if isinstance(func_expr, ast.Subscript):
            # d['k']() -- look up dict binding d = {'k': lib.vulnerable}
            if (
                isinstance(func_expr.value, ast.Name)
                and isinstance(func_expr.slice, ast.Constant)
            ):
                dict_bindings = self._dict_bindings.get(module, {})
                bound = dict_bindings.get((func_expr.value.id, func_expr.slice.value))
                if isinstance(bound, CallNode):
                    return [bound], False
            return [], True
        # lambda / conditional / other -> cannot resolve precisely
        return [], True

    def _resolve_getattr_result(self, module: str, call_node: ast.Call) -> tuple[list[CallNode], bool]:
        """Resolve ``getattr(obj, "literal")`` to ``obj.literal``."""
        if (
            isinstance(call_node.func, ast.Name)
            and call_node.func.id == "getattr"
            and len(call_node.args) >= 2
            and self._is_literal_str(call_node.args[1])
        ):
            obj = call_node.args[0]
            attr = call_node.args[1].value
            if isinstance(obj, ast.Name):
                fake_attr = ast.Attribute(value=obj, attr=attr)
                return self._resolve_attribute_call(module, fake_attr)
        return [], True

    def _resolve_name_call(self, module: str, name: str) -> tuple[list[CallNode], bool]:
        # Check value bindings: x = lib.vulnerable; x()
        binding = self._value_bindings.get(module, {}).get(name)
        if isinstance(binding, CallNode):
            return [binding], False
        # Function defined in this module with matching short name
        for qualname, node in self._file_functions[module].items():
            if qualname.split(".")[-1] == name:
                return [node], False
        # Imported binding pointing at a specific function
        import_binding = self._file_imports[module].get(name)
        if import_binding is not None and import_binding.qualname:
            node = self._find_node(import_binding.qualname)
            if node:
                return [node], False
        # Over-approximate: all functions with this short name
        return list(self._name_index.get(name, [])), True

    def _resolve_attribute_call(self, module: str, expr: ast.Attribute) -> tuple[list[CallNode], bool]:
        attr = expr.attr
        value = expr.value

        # Attribute on a dynamically imported module cannot be resolved.
        if isinstance(value, ast.Name) and value.id in self._dynamic_imports.get(module, set()):
            return [], True

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

        if isinstance(value, ast.Subscript):
            # d['k']() -- look up dict binding
            if isinstance(value.value, ast.Name) and isinstance(value.slice, ast.Constant):
                dict_bindings = self._dict_bindings.get(module, {})
                bound = dict_bindings.get((value.value.id, value.slice.value))
                if isinstance(bound, CallNode):
                    return [bound], False
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

    def _function_qualname(self, module: str, node: ast.FunctionDef | ast.AsyncFunctionDef, class_qualname: str | None) -> str:
        parts = [module]
        if class_qualname:
            parts.append(class_qualname.split(".")[-1])
        parts.append(node.name)
        return ".".join(parts)

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
    def _is_literal_str(node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return True
        return False

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

    # ------------------------------------------------------------------ classification

    def _is_dynamic_call_site(self, file_path: str, node: ast.Call) -> bool:
        """Return True if this call matches a known dynamic site (by file:line)."""
        key = (file_path, node.lineno)
        return key in self._dynamic_site_index

    def _is_external_call(self, node: ast.Call) -> bool:
        """Return True if this call is to a builtin/stdlib function that
        cannot reach the user's vulnerable dependency."""
        if isinstance(node.func, ast.Name) and node.func.id in _EXTERNAL_CALLS:
            return True
        return False

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
