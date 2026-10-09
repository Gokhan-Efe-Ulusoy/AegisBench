"""AegisBench CLI: static, local-first analysis of agent fixtures and MCP configs.

Commands:
- ``scan PATH``: findings for fixtures (`schema_version` 1.0/1.1) and
  supported MCP configs (`mcpServers`/`servers`), baseline + graph checks.
- ``validate PATH``: syntax + normalization check only (never a security verdict).
- ``rules``: rule catalog with severity/confidence semantics.
- ``version``: package, analyzer, adapter, and schema versions.

Exit codes: 0 = completed without actionable findings (or success for
informational commands); 1 = findings meet the failure threshold;
2 = invalid input, usage error, strict-mode violation, or analysis failure.
Diagnostics go to stderr; ``--format json`` keeps stdout purely machine-readable.
"""

from __future__ import annotations

import json
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from aegisbench import __version__, reporter
from aegisbench.adapters import mcp as mcp_adapter
from aegisbench.analyzers import graph as graph_analyzer
from aegisbench.models import (
    BASELINE_ANALYZER_VERSION,
    FINDING_SCHEMA_VERSION,
    FIXTURE_SCHEMA_VERSIONS,
    GRAPH_ANALYZER_VERSION,
    Finding,
)
from aegisbench.parser import FixtureParseError
from aegisbench.pipeline import (
    STATUS_PARTIAL,
    STATUS_REJECTED,
    STATUS_SCANNED,
    STATUS_SKIPPED,
    ScanResult,
    scan_path,
)
from aegisbench.reporter import sanitize_terminal
from aegisbench.rules import broad_permissions

app = typer.Typer(
    name="aegisbench",
    help="Static analyzer for agent fixture and MCP config files.",
    no_args_is_help=True,
)


@app.callback()
def _callback() -> None:
    """AegisBench: static analyzer for agent fixture files."""


class OutputFormat(StrEnum):
    text = "text"
    json = "json"


class FailOn(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    none = "none"


_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}

RULE_CATALOG = [
    {
        "rule_id": broad_permissions.RULE_ID,
        "title": broad_permissions.TITLE,
        "severity": "high",
        "confidence": "high",
        "scope": "Exact '*' entry in tools[].permissions.commands[] only.",
    },
    {
        "rule_id": graph_analyzer.RULE_ID,
        "title": graph_analyzer.TITLE,
        "severity": "high",
        "confidence": "medium",
        "scope": "Explicit sensitive-source -> tool -> external-destination paths "
        "via reads/invokes/sends_to IDs (max 6 edges).",
    },
]


def _meets_threshold(finding: Finding, fail_on: FailOn) -> bool:
    if fail_on == FailOn.none:
        return False
    return _SEVERITY_RANK[finding.severity] >= _SEVERITY_RANK[fail_on.value]


def _emit_file_statuses(result: ScanResult, verbose: bool) -> None:
    for outcome in result.outcomes:
        where = sanitize_terminal(outcome.display_path)
        if outcome.status == STATUS_SKIPPED:
            typer.echo(f"Skipped {where}: {sanitize_terminal(outcome.reason)}", err=True)
        elif outcome.status == STATUS_REJECTED:
            typer.echo(f"Rejected {where}: {sanitize_terminal(outcome.reason)}", err=True)
        elif outcome.status == STATUS_PARTIAL:
            typer.echo(f"Partial {where} [{outcome.kind}]: analyzed with caveats.", err=True)
            if verbose:
                for warning in outcome.warnings:
                    typer.echo(f"  warning: {sanitize_terminal(warning)}", err=True)
                for note in outcome.unsupported:
                    typer.echo(f"  unsupported: {sanitize_terminal(note)}", err=True)


def _strict_problems(result: ScanResult) -> list[str]:
    problems = []
    for outcome in result.outcomes:
        if outcome.status == STATUS_REJECTED:
            problems.append(f"{outcome.display_path}: {outcome.reason}")
        elif outcome.status == STATUS_PARTIAL:
            problems.append(
                f"{outcome.display_path}: analyzed with warnings/unsupported constructs."
            )
    return problems


def _verbose_text(result: ScanResult) -> str:
    lines = [f"Files: {len(result.outcomes)}", ""]
    for outcome in result.outcomes:
        lines.append(
            f"- {sanitize_terminal(outcome.display_path)}: {outcome.status} [{outcome.kind}]"
        )
        if outcome.reason and outcome.status in (STATUS_SKIPPED, STATUS_REJECTED):
            lines.append(f"  reason: {sanitize_terminal(outcome.reason)}")
        for warning in outcome.warnings:
            lines.append(f"  warning: {sanitize_terminal(warning)}")
        for note in outcome.unsupported:
            lines.append(f"  unsupported: {sanitize_terminal(note)}")
    lines.append("")
    findings = result.findings
    if not findings:
        lines.append("No findings. No risky patterns matched.")
        return "\n".join(lines) + "\n"
    lines.append(reporter.to_text(findings).rstrip("\n"))
    detail_map = {}
    for outcome in result.outcomes:
        for key, detail in zip(outcome.detail_for, outcome.details, strict=True):
            detail_map[key] = detail
    for finding in reporter.sort_findings(findings):
        key = f"{finding.rule_id}|{finding.evidence.field_path}|{finding.evidence.matched_value}"
        detail = detail_map.get(key)
        if detail is None:
            continue
        lines.append("")
        lines.append(
            f"Path for {finding.rule_id} @ {sanitize_terminal(finding.relative_file_path)}:"
        )
        lines.append(f"  {' -> '.join(sanitize_terminal(n) for n in detail['node_sequence'])}")
        for hop in detail["hops"]:
            prov = f" (was: {sanitize_terminal(hop['provenance'])})" if hop["provenance"] else ""
            lines.append(
                f"  hop {hop['edge']}: {sanitize_terminal(hop['from'])} -> "
                f"{sanitize_terminal(hop['to'])} via {sanitize_terminal(hop['field_path'])}{prov}"
            )
        lines.append(f"  review: {detail['review_action']}")
    return "\n".join(lines).rstrip("\n") + "\n"


def _verbose_json(result: ScanResult) -> str:
    findings = reporter.sort_findings(result.findings)
    detail_map = {}
    for outcome in result.outcomes:
        for key, detail in zip(outcome.detail_for, outcome.details, strict=True):
            detail_map[key] = detail
    items = []
    for finding in findings:
        dumped = finding.model_dump(mode="json")
        key = f"{finding.rule_id}|{finding.evidence.field_path}|{finding.evidence.matched_value}"
        if key in detail_map:
            dumped["detail"] = detail_map[key]
        items.append(dumped)
    payload = {
        "schema_version": FINDING_SCHEMA_VERSION,
        "finding_count": len(items),
        "findings": items,
        "files": [
            {
                "path": o.display_path,
                "status": o.status,
                "kind": o.kind,
                "reason": o.reason,
                "warnings": list(o.warnings),
                "unsupported": list(o.unsupported),
            }
            for o in result.outcomes
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


@app.command("scan")
def scan(
    path: Annotated[Path, typer.Argument(help="File or directory to scan (explicit, read-only).")],
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.text,
    fail_on: Annotated[
        FailOn, typer.Option("--fail-on", help="Minimum severity that triggers exit code 1.")
    ] = FailOn.medium,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Exit 2 on validation problems or unsupported constructs."),
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", help="Detailed evidence and per-file status.")
    ] = False,
) -> None:
    """Scan a file or directory. Examples:

    \b
    aegisbench scan ./agent.json
    aegisbench scan ./configs --format json
    aegisbench scan ./configs --strict
    aegisbench validate ./mcp.json
    """
    try:
        result = scan_path(path)
    except FixtureParseError as exc:
        typer.echo(f"Error: {sanitize_terminal(str(exc))}", err=True)
        raise typer.Exit(code=2) from exc
    except Exception as exc:  # fail safely, never suppress silently
        typer.echo(
            f"Error: unexpected failure while scanning: {sanitize_terminal(str(exc))}",
            err=True,
        )
        raise typer.Exit(code=2) from exc

    for warning in result.collector_warnings:
        typer.echo(f"Warning: {warning}", err=True)
    _emit_file_statuses(
        result, verbose or any(o.status == STATUS_REJECTED for o in result.outcomes)
    )

    findings = reporter.sort_findings(result.findings)
    if output_format == OutputFormat.json:
        # Plain stdout, no color/decoration, so output stays machine-readable.
        typer.echo(_verbose_json(result) if verbose else reporter.to_json(findings))
    else:
        typer.echo(_verbose_text(result) if verbose else reporter.to_text(findings), nl=False)

    if result.rejected:
        raise typer.Exit(code=2)
    if strict and _strict_problems(result):
        for problem in _strict_problems(result):
            typer.echo(f"Strict: {sanitize_terminal(problem)}", err=True)
        raise typer.Exit(code=2)
    if any(_meets_threshold(f, fail_on) for f in findings):
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command("validate")
def validate(
    path: Annotated[
        Path, typer.Argument(help="File or directory to validate (no security verdict).")
    ],
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.text,
) -> None:
    """Validate syntax and normalization only. Exit 0 if all files are
    valid, 2 otherwise. A valid result never claims the config is secure.
    """
    try:
        result = scan_path(path)
    except FixtureParseError as exc:
        typer.echo(f"Error: {sanitize_terminal(str(exc))}", err=True)
        raise typer.Exit(code=2) from exc
    except Exception as exc:
        typer.echo(
            f"Error: unexpected failure while validating: {sanitize_terminal(str(exc))}",
            err=True,
        )
        raise typer.Exit(code=2) from exc

    if output_format == OutputFormat.json:
        typer.echo(
            json.dumps(
                {
                    "files": [
                        {
                            "path": o.display_path,
                            "status": o.status,
                            "kind": o.kind,
                            "reason": o.reason,
                            "warnings": list(o.warnings),
                            "unsupported": list(o.unsupported),
                        }
                        for o in result.outcomes
                    ],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    else:
        for outcome in result.outcomes:
            where = sanitize_terminal(outcome.display_path)
            if outcome.status == STATUS_SCANNED:
                typer.echo(f"OK {where} [{outcome.kind}]")
            elif outcome.status == STATUS_PARTIAL:
                typer.echo(f"OK-WITH-CAVEATS {where} [{outcome.kind}]")
                for warning in outcome.warnings:
                    typer.echo(f"  warning: {sanitize_terminal(warning)}")
                for note in outcome.unsupported:
                    typer.echo(f"  unsupported: {sanitize_terminal(note)}")
            elif outcome.status == STATUS_SKIPPED:
                typer.echo(f"SKIPPED {where}: {sanitize_terminal(outcome.reason)}")
            else:
                typer.echo(f"INVALID {where}: {sanitize_terminal(outcome.reason)}")
    if any(o.status == STATUS_REJECTED for o in result.outcomes):
        raise typer.Exit(code=2)
    raise typer.Exit(code=0)


@app.command("rules")
def rules(
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.text,
) -> None:
    """Show rule IDs, titles, severity/confidence semantics, and scope."""
    if output_format == OutputFormat.json:
        typer.echo(json.dumps({"rules": RULE_CATALOG}, indent=2, sort_keys=True) + "\n")
        raise typer.Exit(code=0)
    typer.echo("Rules (static risk indicators, not vulnerability proofs):\n")
    for rule in RULE_CATALOG:
        typer.echo(f"{rule['rule_id']}: {rule['title']}")
        typer.echo(f"  severity={rule['severity']} confidence={rule['confidence']}")
        typer.echo(f"  scope: {rule['scope']}\n")
    typer.echo(
        "Severity describes hypothetical impact if the pattern were enforced "
        "literally; confidence describes certainty of the static match. "
        "Neither proves exploitability."
    )
    raise typer.Exit(code=0)


@app.command("version")
def version(
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.text,
) -> None:
    """Show package, analyzer, adapter, and schema versions."""
    payload = {
        "aegisbench": __version__,
        "baseline": BASELINE_ANALYZER_VERSION,
        "graph": GRAPH_ANALYZER_VERSION,
        "mcp_adapter": mcp_adapter.ADAPTER_VERSION,
        "finding_schema": FINDING_SCHEMA_VERSION,
        "fixture_schemas": list(FIXTURE_SCHEMA_VERSIONS),
    }
    if output_format == OutputFormat.json:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        raise typer.Exit(code=0)
    for key, value in payload.items():
        typer.echo(f"{key}: {value}")
    raise typer.Exit(code=0)


def main() -> None:
    app()


if __name__ == "__main__":  # pragma: no cover
    try:
        main()
    except Exception as exc:
        print(f"Error: unexpected failure: {exc}", file=sys.stderr)
        sys.exit(2)
