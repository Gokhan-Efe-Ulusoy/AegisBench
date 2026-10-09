"""Finding rendering: human-readable text and stable machine-readable JSON."""

from __future__ import annotations

import json

from aegisbench.models import FINDING_SCHEMA_VERSION, Finding


def sanitize_terminal(text: str) -> str:
    """Replace terminal control characters to block log injection.

    Filenames and fixture strings are untrusted: a crafted name like
    ``"x\\nFake: ok"`` or ``"\\x1b[2J"`` must not forge output lines or
    emit escape sequences on a terminal. JSON output is unaffected (JSON
    string escaping already handles these) and keeps raw values.
    """
    return "".join("?" if (ord(ch) < 0x20 or ord(ch) == 0x7F) else ch for ch in text)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Deterministic ordering: file, rule, field path, tool name."""
    return sorted(
        findings,
        key=lambda f: (
            f.relative_file_path,
            f.rule_id,
            f.evidence.field_path,
            f.evidence.tool_name or "",
        ),
    )


def to_json(findings: list[Finding]) -> str:
    """Stable JSON document. No terminal decoration, keys sorted."""
    ordered = sort_findings(findings)
    payload = {
        "schema_version": FINDING_SCHEMA_VERSION,
        "finding_count": len(ordered),
        "findings": [f.model_dump(mode="json") for f in ordered],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def to_text(findings: list[Finding]) -> str:
    """Human-readable summary for terminal display."""
    ordered = sort_findings(findings)
    if not ordered:
        return "No findings. No risky patterns matched.\n"
    lines = [f"Findings: {len(ordered)}", ""]
    for f in ordered:
        lines.append(f"[{f.severity}/{f.confidence}] {f.rule_id}: {f.title}")
        lines.append(f"  file: {sanitize_terminal(f.relative_file_path)}")
        lines.append(
            f"  evidence: {sanitize_terminal(f.evidence.field_path)} = "
            f"{sanitize_terminal(f.evidence.matched_value)!r}"
            + (
                f" (tool: {sanitize_terminal(f.evidence.tool_name)})"
                if f.evidence.tool_name
                else ""
            )
        )
        lines.append(f"  explanation: {f.explanation}")
        lines.append(f"  limitations: {f.limitations}")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"
