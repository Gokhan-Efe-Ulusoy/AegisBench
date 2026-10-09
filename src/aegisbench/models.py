"""Validated data models for fixtures and findings.

Fixture schema is synthetic and versioned. Version "1.0" is the Phase 0
baseline (commands/file_access/network_access only). Version "1.1" is a
backward-compatible extension that adds explicit, inert capability fields
for the Phase 1 graph prototype:

- ``data_sources``: synthetic sources, some marked sensitive.
- ``destinations``: synthetic destinations, some marked external.
- ``permissions.reads``: explicit source IDs the tool can read.
- ``permissions.sends_to``: explicit destination IDs the tool can send to.
- ``permissions.invokes``: explicit tool names the tool can invoke.

All new fields are optional. "1.0" fixtures remain valid. Edges are only
created from explicit IDs; nothing is inferred from free-text descriptions.
Do not claim support for any real coding agent's format.

A minimal "1.1" fixture looks like:

    {
      "schema_version": "1.1",
      "agent_name": "example-agent",
      "data_sources": [{"id": "synthetic_hr_db", "sensitivity": "sensitive"}],
      "destinations": [{"id": "synthetic_external_api", "trust": "external"}],
      "tools": [
        {
          "name": "reader",
          "description": "Reads HR data (untrusted text, never executed).",
          "permissions": {"reads": ["synthetic_hr_db"], "invokes": ["sender"]}
        },
        {
          "name": "sender",
          "description": "Sends data outward.",
          "permissions": {"sends_to": ["synthetic_external_api"]}
        }
      ]
    }

Only documented fields above are matched by rules.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

FIXTURE_SCHEMA_VERSION = "1.0"
FIXTURE_SCHEMA_VERSIONS = ("1.0", "1.1")
FINDING_SCHEMA_VERSION = "1.0"

# Analyzer versions reported by the benchmark runner.
BASELINE_ANALYZER_VERSION = "BROAD-CMD-001 v1 (Phase 0, unchanged)"
GRAPH_ANALYZER_VERSION = "GRAPH-CHAIN-001 v1 (Phase 1 prototype)"


class Permissions(BaseModel):
    """Explicitly modeled tool permissions.

    `commands` is the ONLY field the broad-permission baseline reads.
    `file_access` / `network_access` are accepted for compatibility but
    no analyzer infers graph edges from them.
    `reads` / `sends_to` / `invokes` hold explicit synthetic IDs used
    ONLY by the graph analyzer. Free-text descriptions are never read.
    """

    commands: list[str] | None = None
    file_access: list[str] | None = None
    network_access: list[str] | None = None
    reads: list[str] | None = None
    sends_to: list[str] | None = None
    invokes: list[str] | None = None

    model_config = {"extra": "forbid"}


class ToolConfig(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    permissions: Permissions | None = None

    model_config = {"extra": "forbid"}


class DataSource(BaseModel):
    """A synthetic data source. `sensitive` marks benchmark-relevant data."""

    id: str = Field(min_length=1, max_length=200)
    sensitivity: Literal["sensitive", "non-sensitive"] = "non-sensitive"
    description: str | None = Field(default=None, max_length=2000)

    model_config = {"extra": "forbid"}


class Destination(BaseModel):
    """A synthetic destination. `external` marks benchmark-relevant sinks."""

    id: str = Field(min_length=1, max_length=200)
    trust: Literal["external", "internal"] = "internal"
    description: str | None = Field(default=None, max_length=2000)

    model_config = {"extra": "forbid"}


class AgentFixture(BaseModel):
    schema_version: Literal["1.0", "1.1"]
    agent_name: str | None = Field(default=None, max_length=200)
    tools: list[ToolConfig] = Field(default_factory=list, max_length=200)
    data_sources: list[DataSource] = Field(default_factory=list, max_length=100)
    destinations: list[Destination] = Field(default_factory=list, max_length=100)

    model_config = {"extra": "forbid"}


class FindingEvidence(BaseModel):
    field_path: str = Field(max_length=500)
    matched_value: str = Field(max_length=200)
    tool_name: str | None = Field(default=None, max_length=200)

    model_config = {"extra": "forbid"}


class Finding(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    rule_id: str = Field(max_length=100)
    title: str = Field(max_length=300)
    severity: Literal["low", "medium", "high"]
    confidence: Literal["low", "medium", "high"]
    relative_file_path: str = Field(max_length=1000)
    evidence: FindingEvidence
    explanation: str = Field(max_length=2000)
    limitations: str = Field(max_length=2000)

    model_config = {"extra": "forbid"}
