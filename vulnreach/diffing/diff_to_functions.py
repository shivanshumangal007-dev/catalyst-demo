"""Map a commit diff to the vulnerable functions it touches.

The public entry point is :class:`DiffToFunctions`.  Given a :class:`FixCommit`
it fetches the commit diff, reconstructs the old (pre-fix) version of each
changed ``.py`` file, parses it with :mod:`ast`, and maps every removed or
modified line to the enclosing function/method qualified name.

The result is a list of :class:`VulnerableFunction`.  When there is no fix
commit (or the diff cannot be obtained) an empty list is returned and
:attr:`functions_unknown` is set to ``True`` so the reachability analyzer can
treat the alert as ``uncertain`` rather than ``not_reachable``.
"""

from __future__ import annotations

import ast
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

import unidiff

from vulnreach.advisories.fix_commit import FixCommit
from vulnreach.models import VulnerableFunction

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
COMMIT_DIFF_RE = re.compile(r"github.com/([^/]+)/([^/]+?)(?:\.git)?/commit/([0-9a-fA-F]{5,40})")
MODULE_RE = re.compile(r"^https?://github.com/([^/]+)/([^/]+?)(?:\.git)?/?$")

# File name / path signals that a change should be ignored entirely.
IGNORED_DIRS = {
    "tests", "test", "testing", "__pycache__", ".git", "docs", "doc",
    "documentation", "examples", "example",
}
IGNORED_NAMES = {"conftest.py", "setup.py", "conf.py"}
CHANGELOG_NAMES = {"changelog", "changes", "release_notes"}


@dataclass
class _FuncInfo:
    """A function/method discovered in the pre-fix AST of one file."""

    qualname: str
    lineno: int
    end_lineno: int
    is_private: bool


class DiffToFunctions:
    """Resolve vulnerable functions from a fix commit diff.

    Attributes set on every call to :meth:`functions_for_commit`:

    * ``functions_unknown`` — ``True`` when no fix commit/diff is available, so
      the analyzer must emit ``uncertain`` instead of ``not_reachable``.
    * ``public_entry_points`` — public functions that directly call a changed
      private function (one level up); likely real user entry points.
    """

    def __init__(self, cache_db: str | Path | None = None) -> None:
        self.cache_db = Path(cache_db) if cache_db else None
        self.functions_unknown = False
        self.public_entry_points: list[VulnerableFunction] = []

    # ------------------------------------------------------------------ entry

    def functions_for_commit(
        self,
        fix_commit: FixCommit,
        advisory_text: str = "",
    ) -> list[VulnerableFunction]:
        """Return vulnerable functions touched by ``fix_commit``.

        Returns an empty list and sets ``functions_unknown=True`` when there is
        no fix commit or the diff/old files cannot be fetched.
        """
        self.functions_unknown = False
        self.public_entry_points = []

        if not fix_commit.sha or not fix_commit.repo_url:
            self.functions_unknown = True
            return []

        diff_text = self._fetch_diff(fix_commit)
        if diff_text is None:
            self.functions_unknown = True
            return []

        old_contents = self._fetch_old_files(fix_commit, diff_text)
        if not old_contents:
            # We have a commit but cannot inspect any pre-fix file: cannot rule
            # anything out, so stay unknown rather than declare safe.
            self.functions_unknown = True
            return []

        return self._parse(
            diff_text,
            old_contents,
            repo_url=fix_commit.repo_url,
            advisory_text=advisory_text,
            commit_confidence=fix_commit.confidence,
        )

    # ------------------------------------------------------------------ fetching

    def _fetch_diff(self, fix_commit: FixCommit) -> str | None:
        """Fetch the unified diff for a commit via GitHub's .diff media type."""
        parts = self._repo_parts(fix_commit.repo_url)
        if parts is None:
            return None
        owner, repo = parts
        url = f"https://github.com/{owner}/{repo}/commit/{fix_commit.sha}.diff"
        return self._get_text(url)

    def _fetch_old_files(
        self,
        fix_commit: FixCommit,
        diff_text: str,
    ) -> dict[str, str]:
        """Return {file_path: old_file_text} for every analysable .py file."""
        parts = self._repo_parts(fix_commit.repo_url)
        if parts is None:
            return {}
        owner, repo = parts
        contents: dict[str, str] = {}
        for path in self._changed_python_files(diff_text):
            url = f"https://raw.githubusercontent.com/{owner}/{repo}/{fix_commit.sha}~1/{path}"
            text = self._get_text(url)
            if text is not None:
                contents[path] = text
        return contents

    def _get_text(self, url: str) -> str | None:
        headers = {"User-Agent": "vulnreach"}
        if GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read()
            return body.decode("utf-8", errors="replace")
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, UnicodeDecodeError):
            return None

    # ------------------------------------------------------------------ parsing

    def _parse(
        self,
        diff_text: str,
        old_contents: dict[str, str],
        repo_url: str,
        advisory_text: str,
        commit_confidence: float,
    ) -> list[VulnerableFunction]:
        try:
            patch_set = unidiff.PatchSet(StringIO(diff_text))
        except unidiff.errors.UnidiffParseError:
            self.functions_unknown = True
            return []

        results: dict[str, VulnerableFunction] = {}
        analysable_file_seen = False

        for patched_file in patch_set:
            path = self._clean_path(patched_file.target_file or patched_file.source_file or "")
            if not path:
                continue
            if not path.endswith(".py"):
                continue
            if self._is_ignored(path):
                continue
            old_text = old_contents.get(path)
            if old_text is None:
                # A changed Python file we cannot inspect could contain the
                # vulnerable function; never silently drop it.
                self.functions_unknown = True
                continue

            try:
                tree = ast_parse(old_text)
            except SyntaxError:
                self.functions_unknown = True
                continue

            analysable_file_seen = True
            module = self._module_from_path(path)
            funcs = self._collect_functions(tree, module)

            # Per-function change tracking.
            changes: dict[str, dict[str, Any]] = {}

            for hunk in patched_file:
                # Added lines do not exist in the pre-fix file.  Anchor them to
                # the nearest old-file line (previous context/removed line, or
                # the hunk's old start) so the enclosing pre-fix function can
                # still be found.
                last_old_lineno: int | None = None
                for line in hunk:
                    if line.is_removed:
                        old_lineno = line.source_line_no
                        if old_lineno is not None:
                            self._record_change(
                                changes, module, path, funcs, old_lineno, line.value
                            )
                        last_old_lineno = old_lineno
                    elif line.is_added:
                        anchor = (
                            last_old_lineno
                            if last_old_lineno is not None
                            else hunk.source_start
                        )
                        if anchor:
                            self._record_change(
                                changes, module, path, funcs, anchor, line.value
                            )
                    else:
                        if line.source_line_no is not None:
                            last_old_lineno = line.source_line_no

            for qualname, data in changes.items():
                conf = self._compute_confidence(
                    commit_confidence,
                    data["is_private"],
                    data["lines"],
                    len(data["formatting_lines"]),
                    advisory_text,
                    data["qualname"],
                )
                vf = VulnerableFunction(
                    module=data["module"],
                    qualified_name=qualname,
                    file_path=data["file_path"],
                    confidence=max(0.0, min(1.0, conf)),
                )
                results[qualname] = vf

        if analysable_file_seen and not results:
            # We had pre-fix files to inspect but mapped no changed line to a
            # function.  Treat the function list as unknown rather than safe.
            self.functions_unknown = True

        # Public entry points: public functions that directly call a changed
        # private function (one level up), in the same pre-fix file.
        self.public_entry_points = self._find_entry_points(
            patch_set, old_contents, results
        )

        return list(results.values())

    def _record_change(
        self,
        changes: dict[str, dict[str, Any]],
        module: str,
        path: str,
        funcs: list[_FuncInfo],
        old_lineno: int,
        line_value: str,
    ) -> None:
        """Attribute one changed line to its innermost pre-fix function."""
        info = self._enclosing_function(funcs, old_lineno)
        if info is None:
            qualname = f"{module}.<module>"
            is_private = False
        else:
            qualname = info.qualname
            is_private = info.is_private

        entry = changes.setdefault(
            qualname,
            {
                "qualname": qualname,
                "file_path": path,
                "is_private": is_private,
                "module": module,
                "lines": set(),
                "formatting_lines": set(),
            },
        )
        entry["lines"].add(old_lineno)
        if self._is_formatting_line(line_value):
            entry["formatting_lines"].add(old_lineno)

    # ------------------------------------------------------------------ AST walking

    @staticmethod
    def _collect_functions(tree: Any, module: str) -> list[_FuncInfo]:
        """Collect every FunctionDef/AsyncFunctionDef with qualified name + range."""
        results: list[_FuncInfo] = []

        def walk(node: Any, classname: str | None, outer: list[str]) -> None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parts = [module]
                if classname:
                    parts.append(classname)
                parts.extend(outer)
                parts.append(node.name)
                qualname = ".".join(parts)
                end = node.end_lineno or node.lineno
                results.append(
                    _FuncInfo(
                        qualname=qualname,
                        lineno=node.lineno,
                        end_lineno=end,
                        is_private=node.name.startswith("_"),
                    )
                )
                new_outer = outer + [node.name]
                for child in ast.iter_child_nodes(node):
                    walk(child, classname, new_outer)
            elif isinstance(node, ast.ClassDef):
                for child in ast.iter_child_nodes(node):
                    walk(child, node.name, outer)
            else:
                for child in ast.iter_child_nodes(node):
                    walk(child, classname, outer)

        for child in ast.iter_child_nodes(tree):
            walk(child, None, [])
        return results

    @staticmethod
    def _line_to_func_map(funcs: list[_FuncInfo]) -> dict[int, _FuncInfo]:
        """Map every line of a file to its innermost enclosing function."""
        mapping: dict[int, _FuncInfo] = {}
        for info in funcs:
            for lineno in range(info.lineno, info.end_lineno + 1):
                existing = mapping.get(lineno)
                if existing is None or (
                    info.end_lineno - info.lineno
                    < existing.end_lineno - existing.lineno
                ):
                    mapping[lineno] = info
        return mapping

    @staticmethod
    def _enclosing_function(funcs: list[_FuncInfo], lineno: int) -> _FuncInfo | None:
        """Return the innermost function containing ``lineno``, else None."""
        candidates = [f for f in funcs if f.lineno <= lineno <= f.end_lineno]
        if not candidates:
            return None
        return min(candidates, key=lambda f: f.end_lineno - f.lineno)

    # ------------------------------------------------------------------ confidence

    @staticmethod
    def _is_formatting_line(diff_line_value: str) -> bool:
        """Heuristic: a removed line that is only whitespace or a comment."""
        body = diff_line_value[1:] if diff_line_value.startswith(("-", "+")) else diff_line_value
        stripped = body.strip()
        if not stripped:
            return True
        if stripped.startswith("#"):
            return True
        return False

    def _compute_confidence(
        self,
        base: float,
        is_private: bool,
        lines: set[int],
        formatting_lines: int,
        advisory_text: str,
        qualname: str,
    ) -> float:
        conf = base
        if is_private and lines and formatting_lines == len(lines):
            conf -= 0.1
        short = qualname.split(".")[-1]
        if short and short.lower() in advisory_text.lower():
            conf += 0.05
        return max(0.0, min(1.0, conf))

    # ------------------------------------------------------------------ entry points

    def _find_entry_points(
        self,
        patch_set: Any,
        old_contents: dict[str, str],
        results: dict[str, VulnerableFunction],
    ) -> list[VulnerableFunction]:
        """Public functions that directly call a changed private function."""
        changed_private = {
            vf.qualified_name.split(".")[-1]: vf
            for vf in results.values()
            if vf.qualified_name.split(".")[-1].startswith("_")
        }
        if not changed_private:
            return []

        entry_points: list[VulnerableFunction] = []
        seen: set[str] = set()

        for patched_file in patch_set:
            path = self._clean_path(patched_file.target_file or patched_file.source_file or "")
            if not path or path not in old_contents:
                continue
            old_text = old_contents[path]
            try:
                tree = ast_parse(old_text)
            except SyntaxError:
                continue
            module = self._module_from_path(path)
            funcs = self._collect_functions(tree, module)
            line_to_func = self._line_to_func_map(funcs)

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                short = self._called_name(node.func)
                if short not in changed_private:
                    continue
                caller = line_to_func.get(node.lineno)
                if caller is None or caller.is_private:
                    continue
                entry_qual = caller.qualname
                if entry_qual in seen:
                    continue
                seen.add(entry_qual)
                private_vf = changed_private[short]
                entry_points.append(
                    VulnerableFunction(
                        module=module,
                        qualified_name=entry_qual,
                        file_path=path,
                        confidence=private_vf.confidence,
                    )
                )
        return entry_points

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _called_name(func_node: Any) -> str | None:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            return func_node.attr
        return None

    @staticmethod
    def _repo_parts(repo_url: str) -> tuple[str, str] | None:
        m = MODULE_RE.match(repo_url.strip())
        if not m:
            return None
        return m.group(1), m.group(2)

    @staticmethod
    def _clean_path(path: str) -> str:
        """Strip the a/ or b/ prefix that unidiff keeps."""
        for prefix in ("a/", "b/"):
            if path.startswith(prefix):
                return path[len(prefix):]
        return path

    @staticmethod
    def _module_from_path(path: str) -> str:
        p = path
        if p.startswith("./"):
            p = p[2:]
        for prefix in ("src/", "lib/"):
            if p.startswith(prefix):
                p = p[len(prefix):]
        if p.endswith(".py"):
            p = p[:-3]
        return p.replace("/", ".")

    @classmethod
    def _changed_python_files(cls, diff_text: str) -> list[str]:
        paths: list[str] = []
        try:
            patch_set = unidiff.PatchSet(StringIO(diff_text))
        except unidiff.errors.UnidiffParseError:
            return []
        for patched_file in patch_set:
            path = cls._clean_path(
                patched_file.target_file or patched_file.source_file or ""
            )
            if path and path.endswith(".py") and not cls._is_ignored(path):
                paths.append(path)
        return paths

    @staticmethod
    def _is_ignored(path: str) -> bool:
        lower = path.lower()
        parts = [seg for seg in lower.split("/")]
        if any(seg in IGNORED_DIRS for seg in parts):
            return True
        name = parts[-1] if parts else ""
        if name in IGNORED_NAMES:
            return True
        if name.startswith("test_") or name.endswith("_test.py"):
            return True
        if any(token in lower for token in CHANGELOG_NAMES):
            return True
        return False


def ast_parse(source: str) -> Any:
    """Parse Python source with :mod:`ast` (kept as a seam for testing)."""
    return ast.parse(source)
