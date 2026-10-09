"""Parser safety tests. Fixture content is never executed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegisbench.parser import (
    FixtureParseError,
    collect_json_files,
    parse_fixture_file,
    resolve_scan_root,
)

SAFE = {"schema_version": "1.0", "agent_name": "t", "tools": []}


def _write(path: Path, data) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_valid_safe_fixture(tmp_path: Path):
    src = _write(tmp_path / "agent.json", SAFE)
    parsed = parse_fixture_file(src, tmp_path)
    assert parsed.relative_path == "agent.json"
    assert parsed.fixture.schema_version == "1.0"


def test_malformed_json(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not valid json", encoding="utf-8")
    with pytest.raises(FixtureParseError, match="Malformed JSON"):
        parse_fixture_file(bad, tmp_path)


def test_schema_validation_error(tmp_path: Path):
    bad = _write(tmp_path / "bad.json", {"wrong": "schema"})
    with pytest.raises(FixtureParseError, match="Schema validation"):
        parse_fixture_file(bad, tmp_path)


def test_oversized_file(tmp_path: Path):
    big = tmp_path / "big.json"
    big.write_text("x" * (1_000_000 + 1), encoding="utf-8")
    with pytest.raises(FixtureParseError, match="too large"):
        parse_fixture_file(big, tmp_path)


def test_unsupported_format_single_file(tmp_path: Path):
    txt = tmp_path / "notes.txt"
    txt.write_text("hello", encoding="utf-8")
    root = resolve_scan_root(txt)
    with pytest.raises(FixtureParseError, match="Unsupported file format"):
        collect_json_files(root)


def test_path_traversal_blocked(tmp_path: Path):
    inner = tmp_path / "root"
    inner.mkdir()
    outside = _write(tmp_path / "outside.json", SAFE)
    # Craft a path with ".." that resolves outside the scan root.
    traversal = inner / ".." / "outside.json"
    with pytest.raises(FixtureParseError, match="outside scan root"):
        parse_fixture_file(traversal, inner)
    assert outside.exists()  # we never deleted or executed anything


def test_symlink_escape_skipped(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    _write(root / "ok.json", SAFE)
    secret_dir = tmp_path / "secret"
    secret_dir.mkdir()
    secret = _write(secret_dir / "secret.json", SAFE)
    link = root / "evil.json"
    try:
        link.symlink_to(secret)
    except OSError:
        pytest.skip("Symlinks not supported on this platform")
    files, warnings = collect_json_files(root)
    resolved = [p.resolve() for p in files]
    assert secret.resolve() not in resolved
    assert any("symlink escape" in w.lower() for w in warnings)


def test_nonexistent_path():
    with pytest.raises(FixtureParseError, match="does not exist"):
        resolve_scan_root("/definitely/not/here/aegisbench-xyz")


def test_directory_scan_ignores_non_json(tmp_path: Path):
    _write(tmp_path / "a.json", SAFE)
    (tmp_path / "notes.txt").write_text("ignore me", encoding="utf-8")
    files, _ = collect_json_files(tmp_path)
    assert len(files) == 1
    assert files[0].name == "a.json"
