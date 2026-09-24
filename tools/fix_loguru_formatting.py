#!/usr/bin/env python3
"""
Script de correction automatique pour l'issue #390.
- Supprime les traces d'entrée logger.debug("func_name(arg={arg})") sans args
- Remplace logger.exception("erreur: e") par un message contextuel
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

SRC = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("src")
_EXCLUDED = {".eggs", "netcross.egg-info", "__pycache__", ".venv"}

# Orchestration files: keep traces but convert to summaries
_ORCHESTRATION_FILES = {
    "cross_capture_analyzer_cli.py",
    "cross_capture_batch_cli.py",
    "cross_capture_diff_cli.py",
    "cross_history_cli.py",
    "netcross_ai_models_cli.py",
    "netcross_api/app.py",
    "netcross_core/analysis.py",
    "netcross_core/batch.py",
    "netcross_core/baseline_diff.py",
    "netcross_core/live_diff.py",
    "netcross_core/live_report.py",
}

_GENERIC_RE = re.compile(
    r"^(erreur\s*[:\s]*(e|exc|exception|valueerror|notifyerror|filenotfounderror)?\s*"
    r"|erreur inattendue\s*)$",
    re.IGNORECASE,
)

# Variables that are complex objects — use summaries instead of f-string
_COMPLEX_VARS = {
    "packets", "flows", "findings", "layers", "headers", "text", "objects",
    "results", "items", "entries", "rows", "records", "segments",
    "connections", "sessions", "events", "reports", "captures",
    "annotations", "diff", "baseline", "current", "r", "d",
}


def _is_string_with_braces(node):
    if isinstance(node, ast.JoinedStr):
        return False
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return False
    return "{" in node.value


def _has_format_braces_without_args(call):
    args = call.args
    if not args:
        return False
    if not _is_string_with_braces(args[0]):
        return False
    return len(args) <= 1


def _is_generic_exception(call):
    args = call.args
    if not args:
        return False
    first = args[0]
    if isinstance(first, ast.JoinedStr):
        return False
    if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
        return False
    return bool(_GENERIC_RE.match(first.value.strip()))


def _find_enclosing_function(tree, target_lineno):
    """Find the function that contains the given line number."""
    best_func = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= target_lineno:
                if best_func is None or node.lineno > best_func.lineno:
                    best_func = node
    return best_func


def _find_except_clause(tree, target_lineno):
    """Find the except clause that contains the given line number."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if node.lineno <= target_lineno:
                end = getattr(node, 'end_lineno', target_lineno)
                if target_lineno <= end:
                    return node
    return None


def _find_try_block(tree, target_lineno):
    """Find the try block that contains the given line number."""
    best_try = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            if node.lineno <= target_lineno:
                end = getattr(node, 'end_lineno', target_lineno)
                if target_lineno <= end:
                    if best_try is None or node.lineno > best_try.lineno:
                        best_try = node
    return best_try


def _make_summary_msg(original_msg, func_name):
    """Convert an entry trace to a summary message."""
    # Extract arg names from braces
    var_names = re.findall(r'\{(\w+)\}', original_msg)
    parts = []
    for v in var_names:
        if v == "self":
            continue
        if v in _COMPLEX_VARS:
            parts.append(f"{v}={{len({v})}}")
        else:
            parts.append(f"{v}={{{v}}}")
    if not parts:
        return None  # Nothing useful to log
    return f"{func_name}(" + ", ".join(parts) + ")"


def process_file(py_file: Path, is_orchestration: bool) -> int:
    """Process a single file, return number of fixes applied."""
    source = py_file.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(py_file))
    except SyntaxError:
        return 0

    lines = source.split("\n")
    fixes = []  # (lineno, old_line, new_line)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "logger"):
            continue
        method = func.attr
        if method not in ("debug", "info", "warning", "error", "exception"):
            continue

        lineno = node.lineno  # 1-based
        if lineno > len(lines):
            continue
        old_line = lines[lineno - 1]
        indentation = len(old_line) - len(old_line.lstrip())
        indent_str = " " * indentation

        # Case 1: braces without args
        if _has_format_braces_without_args(node):
            first_arg = node.args[0]
            if not isinstance(first_arg, ast.Constant):
                continue
            msg = first_arg.value

            if is_orchestration:
                # Keep trace but convert to f-string with summaries
                func_node = _find_enclosing_function(tree, lineno)
                func_name = func_node.name if func_node else "opération"
                summary = _make_summary_msg(msg, func_name)
                if summary:
                    # Use loguru positional format
                    var_names = re.findall(r'\{(\w+)\}', msg)
                    fmt_parts = []
                    arg_parts = []
                    for v in var_names:
                        if v == "self":
                            continue
                        if v in _COMPLEX_VARS:
                            fmt_parts.append(f"{v}={{}}")
                            arg_parts.append(f"len({v})")
                        else:
                            fmt_parts.append(f"{v}={{}}")
                            arg_parts.append(v)
                    if fmt_parts:
                        new_msg = f"{func_name}(" + ", ".join(fmt_parts) + ")"
                        args_str = ", ".join(arg_parts)
                        new_line = f'{indent_str}logger.{method}("{new_msg}", {args_str})'
                    else:
                        continue  # Skip, nothing to log
                else:
                    continue  # Skip, nothing useful
            else:
                # Remove the line entirely (utility function entry trace)
                new_line = None  # Signal to remove

            fixes.append((lineno, old_line, new_line))

        # Case 2: generic exception message
        elif method == "exception" and _is_generic_exception(node):
            func_node = _find_enclosing_function(tree, lineno)
            func_name = func_node.name if func_node else "opération"

            except_node = _find_except_clause(tree, lineno)
            exc_var = None
            if except_node and except_node.name:
                exc_var = except_node.name
            elif except_node and except_node.type:
                # Get exception type name
                if isinstance(except_node.type, ast.Name):
                    exc_type = except_node.type.id
                else:
                    exc_type = "Exception"
                exc_var = exc_type.lower()

            if exc_var:
                new_msg = f"échec dans {func_name}: {{{exc_var}}}"
                # Use f-string for simplicity
                new_line = f'{indent_str}logger.exception(f"{new_msg}")'
            else:
                new_line = f'{indent_str}logger.exception(f"échec dans {func_name}")'

            fixes.append((lineno, old_line, new_line))

    if not fixes:
        return 0

    # Apply fixes (process from last to first to preserve line numbers)
    fixes.sort(key=lambda x: x[0], reverse=True)
    for lineno, old_line, new_line in fixes:
        if new_line is None:
            # Remove the line
            del lines[lineno - 1]
        else:
            lines[lineno - 1] = new_line

    new_source = "\n".join(lines)
    if new_source != source:
        py_file.write_text(new_source, encoding="utf-8")
        return len(fixes)
    return 0


def main():
    total_fixes = 0
    total_files = 0
    for py_file in sorted(SRC.rglob("*.py")):
        if any(part in _EXCLUDED for part in py_file.parts):
            continue
        rel = py_file.relative_to(SRC)
        is_orch = str(rel) in _ORCHESTRATION_FILES
        n = process_file(py_file, is_orch)
        if n > 0:
            total_fixes += n
            total_files += 1
            print(f"  Fixed {n} in {rel}{' (orchestration)' if is_orch else ''}")
    print(f"\nTotal: {total_fixes} fixes across {total_files} files")


if __name__ == "__main__":
    main()
