from __future__ import annotations

import ast
import importlib.util
import re
from pathlib import Path

import pytest

PUBLIC_SCHEMA_AND_RUNTIME_TOKENS = {
    "agent",
    "allowed",
    "assistant",
    "attestation",
    "benign",
    "broker",
    "build",
    "check",
    "command",
    "content",
    "context",
    "credential",
    "deploy",
    "diagnostic",
    "execute",
    "help",
    "http.get",
    "ignore",
    "invalid",
    "inspect",
    "list",
    "malicious",
    "note",
    "object",
    "policy",
    "post",
    "print",
    "private",
    "read",
    "reference",
    "request",
    "response",
    "scope",
    "secret:",
    "secret",
    "secrets",
    "send",
    "shell.exec",
    "status",
    "text",
    "this",
    "test",
    "token",
    "tool",
    "tools",
    "trust",
    "user",
    "validation",
    "value",
    "values",
    "write",
}


def _string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _string_value(node.left)
        right = _string_value(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _docstring_node_ids(tree: ast.AST) -> set[int]:
    docstring_nodes: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(
                node,
                ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef,
            )
            and node.body
            and isinstance(node.body[0], ast.Expr)
        ):
            first = node.body[0].value
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                docstring_nodes.add(id(first))
    return docstring_nodes


def _string_literals(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    docstring_nodes = _docstring_node_ids(tree)
    values: list[str] = []
    for node in ast.walk(tree):
        if id(node) in docstring_nodes:
            continue
        value = _string_value(node)
        if value is not None:
            values.append(value)
    return values


def _regex_name(node: ast.Call, parents: dict[ast.AST, ast.AST]) -> str:
    parent = parents.get(node)
    if isinstance(parent, ast.Assign) and len(parent.targets) == 1:
        target = parent.targets[0]
        if isinstance(target, ast.Name):
            return target.id
    return ""


def _regex_alternation_count(pattern: str) -> int:
    in_class = False
    escaped = False
    count = 0
    for ch in pattern:
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "|" and not in_class:
            count += 1
    return count + 1 if count else 0


def _compiled_regexes(path: Path) -> list[tuple[str, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    patterns: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "compile"
            and isinstance(func.value, ast.Name)
            and func.value.id == "re"
            and node.args
        ):
            pattern = _string_value(node.args[0])
            if pattern is not None:
                patterns.append((_regex_name(node, parents), pattern))
    return patterns


@pytest.mark.skipif(
    importlib.util.find_spec("zero_trust_agent_benchmark") is None,
    reason="zero-trust-agent-benchmark not installed",
)
def test_src_string_literals_do_not_copy_benchmark_generator_tokens() -> None:
    from zero_trust_agent_benchmark.generator import literal_tokens

    src = Path(__file__).resolve().parents[1] / "src"
    source_tokens: set[str] = set()
    for path in src.rglob("*.py"):
        for literal in _string_literals(path):
            source_tokens.update(re.findall(r"[a-z][a-z0-9_.:-]{3,}", literal.lower()))

    forbidden = literal_tokens() - PUBLIC_SCHEMA_AND_RUNTIME_TOKENS
    assert sorted(source_tokens & forbidden) == []


def test_src_has_no_large_content_keyword_regexes() -> None:
    allowed_generic_patterns = {"_CHAT_CONTROL_RE"}
    src = Path(__file__).resolve().parents[1] / "src"
    offenders: list[str] = []
    for path in src.rglob("*.py"):
        for name, pattern in _compiled_regexes(path):
            if name in allowed_generic_patterns:
                continue
            if _regex_alternation_count(pattern) > 10:
                offenders.append(f"{path.relative_to(src)}:{name}")
    assert offenders == []
