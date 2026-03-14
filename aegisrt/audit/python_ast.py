
from __future__ import annotations

import ast
from pathlib import Path

def parse_file(path: str | Path) -> ast.Module | None:
    try:
        source = Path(path).read_text(encoding="utf-8", errors="replace")
        return ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError, OSError):
        return None

def find_function_calls(tree: ast.Module, names: set[str] | list[str]) -> list[ast.Call]:
    target_names = set(names)
    matches: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name: str | None = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        if name and name in target_names:
            matches.append(node)
    return matches

def find_string_concatenation(tree: ast.Module) -> list[ast.BinOp]:
    results: list[ast.BinOp] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.BinOp):
            continue
        if not isinstance(node.op, ast.Add):
            continue
        if _involves_string(node.left) or _involves_string(node.right):
            results.append(node)
    return results

def find_fstring_with_names(
    tree: ast.Module, names: set[str] | list[str]
) -> list[ast.JoinedStr]:
    target_names = set(names)
    results: list[ast.JoinedStr] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                referenced = _extract_names(value.value)
                if referenced & target_names:
                    results.append(node)
                    break
    return results

def extract_code_snippet(file_path: str | Path, line: int, context: int = 2) -> str:
    try:
        lines = Path(file_path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    snippet_lines: list[str] = []
    for idx in range(start, end):
        if idx == line - 1:
            marker = ">>>"
        else:
            marker = "   "
        snippet_lines.append(f"{marker} {idx + 1:4d} | {lines[idx]}")
    return "\n".join(snippet_lines)

def _involves_string(node: ast.expr) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    return False

def _extract_names(node: ast.expr) -> set[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
    return names
