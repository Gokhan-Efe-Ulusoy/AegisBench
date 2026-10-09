"""Scan pipeline: fixtures and MCP configs to findings, without execution.

One JSON file is handled as follows (in order):
1. Size, encoding, and JSON-syntax checks (failures -> rejected).
2. Native fixture validation (schema 1.0/1.1) -> baseline + graph checks.
3. Otherwise, MCP config adaptation (``mcpServers``/``servers``) ->
   baseline check on the normalized tool list (the graph correctly finds
   no invented edges) with provenance attached to graph detail.
4. Anything else -> rejected with the validation reason.

Per-file outcomes distinguish scanned / partial / skipped / rejected.
Rejected files are collected (with reasons) rather than silently skipped;
the CLI still exits 2 when any rejection occurred. Nothing here executes
fixture content, launches servers, or touches the network.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from aegisbench import evidence as evidence_mod
from aegisbench.adapters import mcp as mcp_adapter
from aegisbench.analyzers import graph as graph_analyzer
from aegisbench.models import AgentFixture, Finding
from aegisbench.parser import (
    MAX_FILE_SIZE_BYTES,
    SUPPORTED_SUFFIX,
    FixtureParseError,
    collect_json_files,
    is_within_root,
    resolve_scan_root,
)
from aegisbench.rules import broad_permissions

STATUS_SCANNED = "scanned"
STATUS_PARTIAL = "partial"
STATUS_SKIPPED = "skipped"
STATUS_REJECTED = "rejected"


@dataclass(frozen=True)
class FileOutcome:
    display_path: str
    status: str
    kind: str  # "fixture" | "mcp" | "other"
    findings: tuple[Finding, ...] = ()
    details: tuple[dict, ...] = ()  # graph-only, aligned by finding order below
    detail_for: tuple[str, ...] = ()  # finding keys (rule_id|field_path|matched) per detail
    warnings: tuple[str, ...] = ()
    unsupported: tuple[str, ...] = ()
    reason: str = ""  # set for skipped/rejected


@dataclass
class ScanResult:
    outcomes: list[FileOutcome] = field(default_factory=list)
    collector_warnings: tuple[str, ...] = ()

    @property
    def findings(self) -> list[Finding]:
        ordered: list[Finding] = []
        for outcome in sorted(self.outcomes, key=lambda o: o.display_path):
            ordered.extend(outcome.findings)
        return ordered

    @property
    def rejected(self) -> list[FileOutcome]:
        return [o for o in self.outcomes if o.status == STATUS_REJECTED]

    @property
    def partial(self) -> list[FileOutcome]:
        return [o for o in self.outcomes if o.status == STATUS_PARTIAL]


def _finding_key(finding: Finding) -> str:
    return f"{finding.rule_id}|{finding.evidence.field_path}|{finding.evidence.matched_value}"


def _read_json_doc(path: Path) -> object:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise FixtureParseError(f"Cannot stat file {path}: {exc}") from exc
    if size > MAX_FILE_SIZE_BYTES:
        raise FixtureParseError(f"File too large ({size} bytes > {MAX_FILE_SIZE_BYTES} bytes)")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FixtureParseError(f"Cannot read file: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise FixtureParseError(f"File is not valid UTF-8: {exc}") from exc
    if not text.strip():
        raise FixtureParseError("File is empty; expected a JSON object.")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise FixtureParseError(f"Malformed JSON: {exc}") from exc


def scan_file(path: Path, scan_root: Path) -> FileOutcome:
    """Analyze one resolved file inside `scan_root`. Never raises."""
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        return FileOutcome(_display(path, scan_root), STATUS_REJECTED, "other", reason=str(exc))
    display = _display(resolved, scan_root)
    if not is_within_root(resolved, scan_root):
        return FileOutcome(
            display, STATUS_REJECTED, "other", reason="Path resolves outside scan root."
        )
    try:
        doc = _read_json_doc(resolved)
    except FixtureParseError as exc:
        return FileOutcome(display, STATUS_REJECTED, "other", reason=str(exc))
    try:
        fixture = AgentFixture.model_validate(doc)
    except ValidationError as fixture_error:
        return _scan_mcp_doc(doc, display, str(fixture_error))
    return _scan_fixture(fixture, display, kind="fixture", provenance=None)


def _scan_fixture(
    fixture: AgentFixture, display: str, kind: str, provenance: dict[str, str] | None
) -> FileOutcome:
    baseline = broad_permissions.check(fixture, display)
    paired = graph_analyzer.check_detailed(fixture, display)
    graph_findings = [finding for finding, _ in paired]
    details = tuple(evidence_mod.describe_path(path, fixture, provenance) for _, path in paired)
    warnings = graph_analyzer.build_graph(fixture).warnings
    findings = tuple(sorted(baseline + graph_findings, key=_sort_key))
    # Align details to graph findings in the final sorted order.
    detail_map = {_finding_key(f): d for f, d in zip(graph_findings, details, strict=True)}
    ordered_details = tuple(
        detail_map[_finding_key(f)] for f in findings if _finding_key(f) in detail_map
    )
    ordered_keys = tuple(_finding_key(f) for f in findings if _finding_key(f) in detail_map)
    status = STATUS_PARTIAL if warnings else STATUS_SCANNED
    return FileOutcome(
        display_path=display,
        status=status,
        kind=kind,
        findings=findings,
        details=ordered_details,
        detail_for=ordered_keys,
        warnings=tuple(warnings),
    )


def _scan_mcp_doc(doc: object, display: str, fixture_error: str) -> FileOutcome:
    if not isinstance(doc, dict) or ("mcpServers" not in doc and "servers" not in doc):
        return FileOutcome(
            display, STATUS_REJECTED, "other", reason=f"Not a fixture: {fixture_error[:300]}"
        )
    try:
        adapted = mcp_adapter.adapt_mcp_config(doc, source=display)
    except mcp_adapter.McpAdapterError as exc:
        return FileOutcome(display, STATUS_REJECTED, "mcp", reason=str(exc))
    outcome = _scan_fixture(adapted.fixture, display, kind="mcp", provenance=adapted.provenance)
    unsupported = adapted.unsupported
    warnings = outcome.warnings + adapted.warnings
    status = STATUS_PARTIAL if (unsupported or warnings) else STATUS_SCANNED
    return FileOutcome(
        display_path=outcome.display_path,
        status=status,
        kind="mcp",
        findings=outcome.findings,
        details=outcome.details,
        detail_for=outcome.detail_for,
        warnings=tuple(warnings),
        unsupported=tuple(unsupported),
    )


def _sort_key(finding: Finding) -> tuple[str, str, str, str]:
    return (
        finding.relative_file_path,
        finding.rule_id,
        finding.evidence.field_path,
        finding.evidence.tool_name or "",
    )


def _display(resolved: Path, scan_root: Path) -> str:
    try:
        return str(resolved.relative_to(scan_root)).replace("\\", "/")
    except ValueError:
        return resolved.name


def scan_path(scan_path: Path | str) -> ScanResult:
    """Collect and analyze every file under the explicit scan path."""
    root = resolve_scan_root(scan_path)
    if root.is_file():
        if root.suffix.lower() != SUPPORTED_SUFFIX:
            raise FixtureParseError(
                f"Unsupported file format {root.suffix!r}: "
                f"only {SUPPORTED_SUFFIX} files are supported."
            )
        effective = root.parent
        return ScanResult(outcomes=[scan_file(root, effective)], collector_warnings=())

    files, warnings = collect_json_files(root)
    outcomes: list[FileOutcome] = []
    seen = {p.resolve() for p in files}
    # Report skipped non-JSON files explicitly (never silently).
    for candidate in sorted(root.rglob("*")):
        if candidate.is_file() and not candidate.is_symlink():
            try:
                resolved = candidate.resolve(strict=True)
            except OSError:
                continue  # already reported as collector warning
            if resolved not in seen and resolved.suffix.lower() != SUPPORTED_SUFFIX:
                outcomes.append(
                    FileOutcome(
                        _display(resolved, root),
                        STATUS_SKIPPED,
                        "other",
                        reason=(
                            f"Unsupported file format {resolved.suffix!r}; only .json is scanned."
                        ),
                    )
                )
    for path in files:
        outcomes.append(scan_file(path, root))
    outcomes.sort(key=lambda o: o.display_path)
    return ScanResult(outcomes=outcomes, collector_warnings=tuple(warnings))
