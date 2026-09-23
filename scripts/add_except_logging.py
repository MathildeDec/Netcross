#!/usr/bin/env python3
"""Add logger.debug() to every except block that doesn't have a logger call.

Uses AST to find except handlers, checks if they already contain a logger call,
and if not, inserts a logger.debug() as the first statement.

For modules using lazy logger (pcap_parser, CLIs): uses _get_logger().debug()
"""
import ast
import os
import re
import sys


def has_logger_call(handler: ast.ExceptHandler) -> bool:
    """Check if the handler body already contains a logger call."""
    for node in ast.walk(handler):
        if isinstance(node, ast.Attribute):
            if node.attr in ('debug', 'info', 'warning', 'error', 'exception', 'critical'):
                if isinstance(node.value, ast.Name) and node.value.id in ('logger', '_logger'):
                    return True
                if isinstance(node.value, ast.Call):
                    # _get_logger().debug(...)
                    return True
    return False


def is_lazy_logger_module(content: str) -> bool:
    """Check if this module uses the lazy logger pattern."""
    return '_get_logger' in content


def get_except_indent(handler: ast.ExceptHandler, source_lines: list[str]) -> int:
    """Get the indentation of the except handler body."""
    # The first statement in the body
    if handler.body:
        first_stmt = handler.body[0]
        line = source_lines[first_stmt.lineno - 1]
        return len(line) - len(line.lstrip())
    return 4


def add_logging_to_file(fpath: str) -> int:
    """Add logger.debug to all except blocks without logging. Returns count added."""
    with open(fpath, 'r') as f:
        content = f.read()
    
    lazy = is_lazy_logger_module(content)
    if lazy:
        logger_expr = "_get_logger()"
    else:
        logger_expr = "logger"
    
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return 0
    
    # Collect all except handlers without logger calls
    handlers_to_fix = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if not has_logger_call(node):
                handlers_to_fix.append(node)
    
    if not handlers_to_fix:
        return 0
    
    # Sort by line number descending (so insertions don't affect earlier line numbers)
    handlers_to_fix.sort(key=lambda h: h.lineno, reverse=True)
    
    lines = content.split('\n')
    inserted = 0
    
    for handler in handlers_to_fix:
        # Get the exception name
        exc_name = ""
        if handler.type and isinstance(handler.type, ast.Name):
            exc_name = handler.type.id
        elif handler.type and isinstance(handler.type, ast.Tuple):
            names = [n.id for n in handler.type.elts if isinstance(n, ast.Name)]
            exc_name = "/".join(names)
        
        # Get the indentation of the first statement in the body
        if handler.body:
            first_stmt = handler.body[0]
            line_idx = first_stmt.lineno - 1
            if line_idx < len(lines):
                line = lines[line_idx]
                indent = len(line) - len(line.lstrip())
            else:
                indent = 4
        else:
            indent = 4
        
        # Check if the body is just a pass, raise, or return
        first_stmt = handler.body[0] if handler.body else None
        is_pass = isinstance(first_stmt, ast.Pass)
        is_raise = isinstance(first_stmt, ast.Raise)
        is_return = isinstance(first_stmt, ast.Return)
        
        # Choose log level
        if is_raise:
            level = "debug"
            msg = f"exception {exc_name} propagée" if exc_name else "exception propagée"
        elif is_return or is_pass:
            level = "debug"
            msg = f"exception {exc_name} gérée silencieusement" if exc_name else "exception gérée silencieusement"
        else:
            level = "exception"
            msg = f"exception {exc_name}" if exc_name else "exception"
        
        log_line = f"{' ' * indent}{logger_expr}.{level}(\"{msg}\")"
        
        # Insert at the beginning of the handler body
        insert_line = handler.body[0].lineno - 1 if handler.body else handler.lineno
        
        # Adjust for previous insertions (since we go in reverse, this should be fine)
        lines.insert(insert_line, log_line)
        inserted += 1
    
    with open(fpath, 'w') as f:
        f.write('\n'.join(lines))
    
    return inserted


def main():
    src_dir = "src"
    total = 0
    
    for root, dirs, files in os.walk(src_dir):
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for fname in sorted(files):
            if not fname.endswith('.py'):
                continue
            fpath = os.path.join(root, fname)
            
            # Check if file has logger
            with open(fpath, 'r') as f:
                content = f.read()
            
            if 'get_logger' not in content and '_get_logger' not in content:
                continue
            
            count = add_logging_to_file(fpath)
            if count > 0:
                # Verify it compiles
                import py_compile
                try:
                    py_compile.compile(fpath, doraise=True)
                    print(f"  {fpath}: +{count} logger calls")
                    total += count
                except py_compile.PyCompileError as e:
                    print(f"  FAIL {fpath}: {e}")
                    # Revert
                    import subprocess
                    subprocess.run(["git", "checkout", "--", fpath], capture_output=True)
    
    print(f"\nTotal: {total} logger calls added to except blocks")


if __name__ == "__main__":
    main()
