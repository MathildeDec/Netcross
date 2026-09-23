#!/usr/bin/env python3
"""Add get_logger to all modules that don't have it, using AST for proper placement.

This script uses Python's AST module to find the correct insertion point:
after the last top-level import statement (not inside any function/class/try block).
"""
import ast
import os
import re
import sys


LOGGER_IMPORT = "from netcross_core.logging_config import get_logger"
LOGGER_LINE = "logger = get_logger(__name__)"


def has_logger(content: str) -> bool:
    return (
        "get_logger" in content
        or "from loguru" in content
        or "logging_config" in content
    )


def find_insertion_point(content: str) -> int | None:
    """Find the line number (0-based) after which to insert the logger."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return None

    last_import_end = 0
    docstring_end = 0

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            last_import_end = max(last_import_end, node.end_lineno)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            # Module docstring
            if docstring_end == 0:
                docstring_end = node.end_lineno

    if last_import_end > 0:
        return last_import_end  # 1-based, so this is the 0-based line after
    elif docstring_end > 0:
        return docstring_end
    else:
        return 0  # Insert at the very top


def add_logger_to_file(fpath: str) -> bool:
    """Add logger import and initialization to a file. Returns True if changed."""
    with open(fpath, "r") as f:
        content = f.read()

    if has_logger(content):
        return False

    stripped = content.strip()
    if len(stripped) < 10:
        return False

    lines = content.split("\n")
    insert_after = find_insertion_point(content)

    if insert_after is None:
        return False

    # Convert 1-based to 0-based index
    insert_idx = insert_after  # already points to the line after the last import

    # Skip blank lines after the insertion point
    while insert_idx < len(lines) and lines[insert_idx].strip() == "":
        insert_idx += 1

    # Insert: blank line, import, blank line, logger
    new_lines = lines[:insert_idx] + [
        "",
        LOGGER_IMPORT,
        "",
        LOGGER_LINE,
    ] + lines[insert_idx:]

    with open(fpath, "w") as f:
        f.write("\n".join(new_lines))

    return True


def main():
    src_dir = "src"
    added = 0
    skipped = 0
    errors = []

    for root, dirs, files in os.walk(src_dir):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for fname in sorted(files):
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            try:
                if add_logger_to_file(fpath):
                    # Verify it compiles
                    import py_compile
                    py_compile.compile(fpath, doraise=True)
                    added += 1
                else:
                    skipped += 1
            except Exception as e:
                errors.append((fpath, str(e)))
                # Revert this file
                import subprocess
                subprocess.run(["git", "checkout", "--", fpath], capture_output=True)

    print(f"Added logger to {added} modules, skipped {skipped}")
    if errors:
        print(f"\n{len(errors)} errors (reverted):")
        for fpath, err in errors:
            print(f"  {fpath}: {err}")


if __name__ == "__main__":
    main()
