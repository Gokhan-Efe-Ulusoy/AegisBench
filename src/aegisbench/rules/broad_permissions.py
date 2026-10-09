"""Rule BROAD-CMD-001: explicitly modeled overly broad command permission.

Specification (narrow, syntactic):
- Reads ONLY ``tools[i].permissions.commands[j]`` (documented fixture field).
- Matches IFF the entry, after stripping surrounding ASCII whitespace,
  equals exactly ``"*"``.
- Does NOT match substrings or lookalikes such as ``"ls *"``,
  ``"sudo:*"``, ``"all"``, ``"shell:*"``. Those are benign for this rule.
- Emits severity ``high`` (broad allowlist is risky *if* enforced as
  described) with confidence ``high`` (the syntactic match is certain).
  This is a static risk indicator, NOT a confirmed exploitable
  vulnerability: the fixture does not model enforcement, sandboxing,
  or downstream capabilities.
- Never infers file or network access from a command entry. The fixture
  would have to model that capability explicitly in a future schema.
"""

from __future__ import annotations

from aegisbench.models import FINDING_SCHEMA_VERSION, Finding, FindingEvidence

RULE_ID = "BROAD-CMD-001"
TITLE = "Overly broad command permission ('*' allowlist entry)"

EXPLANATION = (
    "Tool allows any command via an explicit '*' entry in "
    "permissions.commands. If the host enforces this allowlist literally, "
    "the tool could invoke arbitrary commands, so this configuration "
    "should be narrowed to named commands."
)
LIMITATIONS = (
    "Static indicator only, not a confirmed vulnerability. "
    "The fixture does not describe enforcement, sandboxing, authentication, "
    "or what the commands can reach. Do not infer file or network access "
    "unless a future fixture schema explicitly models it."
)


def check(fixture, relative_file_path: str) -> list[Finding]:
    """Run BROAD-CMD-001 against one parsed fixture."""
    findings: list[Finding] = []
    for i, tool in enumerate(fixture.tools):
        perms = tool.permissions
        if perms is None or perms.commands is None:
            continue
        for j, entry in enumerate(perms.commands):
            if not isinstance(entry, str):
                continue
            if entry.strip() != "*":
                continue
            findings.append(
                Finding(
                    schema_version=FINDING_SCHEMA_VERSION,  # type: ignore[arg-type]
                    rule_id=RULE_ID,
                    title=TITLE,
                    severity="high",
                    confidence="high",
                    relative_file_path=relative_file_path,
                    evidence=FindingEvidence(
                        field_path=f"tools[{i}].permissions.commands[{j}]",
                        matched_value="*",
                        tool_name=tool.name,
                    ),
                    explanation=EXPLANATION,
                    limitations=LIMITATIONS,
                )
            )
    return findings
