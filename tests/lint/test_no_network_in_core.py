"""Lint guard: Layers 1-3 must not import any network library.

This is a hard constraint from the design spec. If a future commit
introduces a network import in core code, this test fails the build.
"""
from __future__ import annotations

import ast
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[2] / "src" / "keystonecrypto"
FORBIDDEN_MODULES = {
    "httpx", "requests", "urllib", "urllib3",
    "urllib.request", "urllib.parse",
    "socket", "aiohttp", "http.client",
}

# Files in these subpackages are allowed network imports (they are
# the chain-adapter layer).
ALLOWED_SUBDIRS = {"btc", "eth", "sol"}


def _imports_in(path: Path) -> set[str]:
    """Return top-level module names imported in a Python source file."""
    tree = ast.parse(path.read_text())
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".")[0])
    return found


def test_no_network_imports_in_core() -> None:
    offenders: list[str] = []
    for py_file in CORE_DIR.rglob("*.py"):
        # Skip chain adapter subdirs.
        rel = py_file.relative_to(CORE_DIR)
        if rel.parts and rel.parts[0] in ALLOWED_SUBDIRS:
            continue
        imports = _imports_in(py_file)
        bad = imports & FORBIDDEN_MODULES
        if bad:
            offenders.append(f"{py_file.relative_to(CORE_DIR.parent.parent)}: {sorted(bad)}")
    assert not offenders, "Forbidden network imports in core:\n" + "\n".join(offenders)
