"""Safe, read-only JSON fixture parsing.

Safety properties:
- Never executes fixture content (only ``json.load`` + Pydantic validation).
- Never launches servers, never contacts URLs, never imports scanned modules.
- Never reads outside the explicitly supplied scan root.
- Resolves symlinks and rejects escapes.
- Enforces a maximum file size.
- Only ``.json`` files are parsed; anything else is rejected or skipped.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from aegisbench.models import AgentFixture

MAX_FILE_SIZE_BYTES = 1_000_000  # 1 MiB
SUPPORTED_SUFFIX = ".json"


class FixtureParseError(ValueError):
    """Raised when a fixture file cannot be safely parsed."""


def resolve_scan_root(scan_path: str | Path) -> Path:
    """Resolve the user-supplied scan path to an absolute real path."""
    p = Path(scan_path)
    try:
        resolved = p.resolve(strict=False)
    except OSError as exc:
        raise FixtureParseError(f"Cannot resolve scan path {str(p)!r}: {exc}") from exc
    if not resolved.exists():
        raise FixtureParseError(f"Scan path does not exist: {resolved}")
    return resolved


def is_within_root(candidate: Path, root: Path) -> bool:
    """Return True if resolved `candidate` is inside resolved `root`."""
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def collect_json_files(scan_root: Path) -> tuple[list[Path], list[str]]:
    """Collect ``.json`` files under `scan_root` without leaving it.

    Returns (files, warnings). Symlink escapes are skipped with a warning,
    never followed. Non-JSON files inside a directory scan are skipped
    silently (a single-file scan of a non-JSON file is an error).
    """
    warnings: list[str] = []
    if scan_root.is_file():
        if scan_root.suffix.lower() != SUPPORTED_SUFFIX:
            raise FixtureParseError(
                f"Unsupported file format {scan_root.suffix!r}: "
                f"only {SUPPORTED_SUFFIX} files are supported."
            )
        _check_file_size(scan_root)
        return [scan_root], warnings

    if not scan_root.is_dir():
        raise FixtureParseError(f"Scan path is not a file or directory: {scan_root}")

    files: list[Path] = []
    # Sort for deterministic collection order.
    for candidate in sorted(scan_root.rglob("*")):
        if not candidate.is_file() and not candidate.is_symlink():
            continue
        # Resolve symlinks to detect escapes; broken symlinks are skipped.
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            warnings.append(f"Skipped unreadable or broken link: {candidate}")
            continue
        if not is_within_root(resolved, scan_root):
            warnings.append(f"Skipped symlink escape: {candidate} -> {resolved}")
            continue
        if resolved.suffix.lower() != SUPPORTED_SUFFIX:
            continue
        try:
            _check_file_size(resolved)
        except FixtureParseError as exc:
            # Oversized files are hard errors, not silent skips, so the
            # user notices. Surface immediately.
            raise FixtureParseError(str(exc)) from exc
        # Only report each real file once (rglob can surface a symlink
        # path plus its target under pathological layouts).
        if resolved not in files:
            files.append(resolved)
    return sorted(files), warnings


def _check_file_size(path: Path) -> None:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise FixtureParseError(f"Cannot stat file {path}: {exc}") from exc
    if size > MAX_FILE_SIZE_BYTES:
        raise FixtureParseError(
            f"File too large ({size} bytes > {MAX_FILE_SIZE_BYTES} bytes): {path}"
        )


@dataclass(frozen=True)
class ParsedFixture:
    absolute_path: Path
    relative_path: str
    fixture: AgentFixture


def parse_fixture_file(path: Path, scan_root: Path) -> ParsedFixture:
    """Parse one JSON fixture file. Never executes its content."""
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise FixtureParseError(f"Cannot resolve file {path}: {exc}") from exc
    if not is_within_root(resolved, scan_root):
        raise FixtureParseError(f"Path traversal blocked: {path} resolves outside scan root")
    _check_file_size(resolved)
    if resolved.suffix.lower() != SUPPORTED_SUFFIX:
        raise FixtureParseError(f"Unsupported file format: {resolved}")

    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise FixtureParseError(f"Cannot read file {resolved}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise FixtureParseError(f"File is not valid UTF-8: {resolved}: {exc}") from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FixtureParseError(f"Malformed JSON in {resolved}: {exc}") from exc

    try:
        fixture = AgentFixture.model_validate(data)
    except ValidationError as exc:
        raise FixtureParseError(f"Schema validation failed for {resolved}: {exc}") from exc

    try:
        rel = str(resolved.relative_to(scan_root))
    except ValueError as exc:
        raise FixtureParseError(f"Path traversal blocked: {resolved}") from exc
    # Normalize to POSIX separators for stable cross-platform findings.
    rel = rel.replace("\\", "/")
    return ParsedFixture(absolute_path=resolved, relative_path=rel, fixture=fixture)
