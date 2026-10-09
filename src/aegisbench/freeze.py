"""Reproducibility freeze: hash every artifact without touching semantics.

Run: `python -m aegisbench.freeze` from the repo root.
Prints JSON {python, dependencies, commands, files: {relpath: sha256}}.

The manifest document itself (`docs/reproducibility_manifest.md`) is the
only frozen-listed file excluded from hashing, because it embeds the
hashes (hashing it would be circular). Everything else is covered.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import sys
from pathlib import Path

COMMANDS = [
    "python -m pytest",
    "ruff check src tests benchmark examples",
    "ruff format --check src tests benchmark examples",
    "python -m aegisbench.benchmark",
    "python -m aegisbench.heldout",
    "python -m aegisbench.freeze",
]

SOURCE_FILES = [
    "src/aegisbench/__init__.py",
    "src/aegisbench/models.py",
    "src/aegisbench/parser.py",
    "src/aegisbench/reporter.py",
    "src/aegisbench/cli.py",
    "src/aegisbench/metrics.py",
    "src/aegisbench/evidence.py",
    "src/aegisbench/pipeline.py",
    "src/aegisbench/benchmark.py",
    "src/aegisbench/heldout.py",
    "src/aegisbench/blind.py",
    "src/aegisbench/freeze.py",
    "src/aegisbench/rules/__init__.py",
    "src/aegisbench/rules/broad_permissions.py",
    "src/aegisbench/analyzers/__init__.py",
    "src/aegisbench/analyzers/graph.py",
    "src/aegisbench/adapters/__init__.py",
    "src/aegisbench/adapters/mcp.py",
]

GENERATOR_FILES = [
    "benchmark/generate.py",
    "benchmark/heldout_v1/generate.py",
]

TEST_FILES = [
    "tests/test_benchmark.py",
    "tests/test_blind.py",
    "tests/test_cli.py",
    "tests/test_cli_mvp.py",
    "tests/test_corpus.py",
    "tests/test_evidence.py",
    "tests/test_graph.py",
    "tests/test_heldout.py",
    "tests/test_mcp_adapter.py",
    "tests/test_metrics.py",
    "tests/test_parser.py",
    "tests/test_pipeline.py",
    "tests/test_rules.py",
    "tests/test_security_regressions.py",
]

DOC_FILES = [
    "README.md",
    "CONTRIBUTING.md",
    "LICENSE",
    ".gitignore",
    "pyproject.toml",
    ".github/workflows/ci.yml",
    "docs/scope.md",
    "docs/installation.md",
    "docs/usage.md",
    "docs/security_model.md",
    "docs/limitations.md",
    "docs/mcp_support_matrix.md",
    "docs/phase2_protocol.md",
    "docs/phase2_results.md",
    "docs/independent_evaluation_kit.md",
    "docs/acceptance_policy.md",
    "docs/real_schema_scope.md",
    "docs/audit_note_5_1.md",
    "examples/mcp/README.md",
    "benchmark/README.md",
    "benchmark/labels.json",
    "benchmark/heldout_v1/README.md",
    "benchmark/heldout_v1/labels.json",
    "benchmark/real_mcp/README.md",
]


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def frozen_files() -> list[Path]:
    root = repo_root()
    paths = [root / f for f in (SOURCE_FILES + GENERATOR_FILES + TEST_FILES + DOC_FILES)]
    for dataset in (
        "benchmark/dataset",
        "benchmark/heldout_v1/fixtures",
        "benchmark/real_mcp",
        "examples/mcp",
        "tests/fixtures/safe",
        "tests/fixtures/risky",
    ):
        d = root / dataset
        if d.is_dir():
            paths.extend(sorted(p for p in d.glob("*.json") if p.is_file()))
    return sorted(set(paths))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dependency_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for dist in ("typer", "pydantic", "pytest", "ruff"):
        try:
            versions[dist] = importlib.metadata.version(dist)
        except importlib.metadata.PackageNotFoundError:
            versions[dist] = "not-installed"
    return versions


def build_freeze() -> dict:
    root = repo_root()
    files: dict[str, str] = {}
    missing: list[str] = []
    for path in frozen_files():
        rel = str(path.relative_to(root)).replace("\\", "/")
        if path.is_file():
            files[rel] = sha256_file(path)
        else:
            missing.append(rel)
    return {
        "python": sys.version.split()[0],
        "dependencies": dependency_versions(),
        "commands": COMMANDS,
        "files": files,
        "missing": missing,
    }


def main() -> None:
    print(json.dumps(build_freeze(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
