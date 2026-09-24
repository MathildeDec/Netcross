#!/usr/bin/env python3
"""
Corrige les problèmes résiduels du fix automatique #390 :
1. Variables invalides ({valueerror}, {filenotfounderror}, etc.) dans les f-strings
2. Lignes orphelines d'appels multi-lignes partiellement supprimés
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

SRC = Path("src")
_EXCLUDED = {".eggs", "netcross.egg-info", "__pycache__", ".venv"}

# Patterns de variables invalides (noms d'exceptions lowercased sans `as`)
_INVALID_VAR_RE = re.compile(
    r': \{(valueerror|filenotfounderror|notifyerror|exception)\}$'
)


def fix_invalid_vars(source: str) -> str:
    """Corrige les variables invalides dans les f-strings d'exception."""
    lines = source.split("\n")
    changed = False
    for i, line in enumerate(lines):
        if 'logger.exception(f"échec dans ' in line:
            new = _INVALID_VAR_RE.sub('', line)
            if new != line:
                # Also remove trailing colon if present: "échec dans func:"
                new = new.replace('")', '")')
                lines[i] = new
                changed = True
    if changed:
        return "\n".join(lines)
    return source


def fix_multiline_orphans(source: str) -> str:
    """Corrige les lignes orphelines d'appels multi-lignes partiellement supprimés."""
    lines = source.split("\n")
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Pattern: a string literal line that looks like an orphaned continuation
        # of a removed logger.debug( call
        # Check if this line is a bare string literal (continuation of a removed call)
        if (
            stripped.startswith('"')
            and stripped.endswith('"')
            and not stripped.startswith('"""')
            and not stripped.startswith("'''")
            and i > 0
        ):
            # Check if previous line was also an orphan or empty
            prev_stripped = result[-1].strip() if result else ""
            # Check if this is a logger continuation orphan
            if (
                ("{" in stripped or "(" in stripped)
                and not prev_stripped.startswith("logger")
                and not prev_stripped.startswith("def ")
                and not prev_stripped.startswith("class ")
            ):
                # Skip this orphaned string line
                i += 1
                # Also skip the closing ) if it follows
                if i < len(lines) and lines[i].strip() == ")":
                    i += 1
                continue

        # Also handle the case where we have an empty if block
        # (line with just indentation followed by a non-indented line)
        result.append(line)
        i += 1

    return "\n".join(result)


def fix_empty_if_blocks(source: str) -> str:
    """Corrige les blocs if vides en ajoutant `pass`."""
    lines = source.split("\n")
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        result.append(line)
        stripped = line.strip()

        # Check for if/for/while/with/try that might have empty body
        if stripped.endswith(":") and any(
            stripped.startswith(kw) for kw in ("if ", "for ", "while ", "with ", "try:")
        ):
            # Check next non-empty line
            indent = len(line) - len(line.lstrip())
            j = i + 1
            while j < len(lines) and lines[j].strip() == "":
                j += 1
            if j < len(lines):
                next_indent = len(lines[j]) - len(lines[j].lstrip())
                if next_indent <= indent:
                    # Empty block - add pass
                    result.append(" " * (indent + 4) + "pass")
        i += 1
    return "\n".join(result)


def main():
    total = 0
    for py_file in sorted(SRC.rglob("*.py")):
        if any(part in _EXCLUDED for part in py_file.parts):
            continue
        source = py_file.read_text(encoding="utf-8")
        new = fix_invalid_vars(source)
        new = fix_multiline_orphans(new)
        new = fix_empty_if_blocks(new)
        if new != source:
            py_file.write_text(new, encoding="utf-8")
            total += 1
            print(f"  Fixed: {py_file.relative_to(SRC)}")
    print(f"\nTotal: {total} files fixed")


if __name__ == "__main__":
    main()
