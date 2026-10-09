"""Tests for BROAD-CMD-001. Includes benign counterexamples."""

from __future__ import annotations

import pytest

from aegisbench.models import AgentFixture
from aegisbench.rules import broad_permissions


def _fixture(commands) -> AgentFixture:
    return AgentFixture.model_validate(
        {
            "schema_version": "1.0",
            "agent_name": "t",
            "tools": [{"name": "shell", "description": "d", "permissions": {"commands": commands}}],
        }
    )


def test_triggers_on_exact_star():
    findings = broad_permissions.check(_fixture(["ls", "*"]), "agent.json")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "BROAD-CMD-001"
    assert f.severity == "high"
    assert f.confidence == "high"
    assert f.relative_file_path == "agent.json"
    assert f.evidence.field_path == "tools[0].permissions.commands[1]"
    assert f.evidence.matched_value == "*"
    assert f.explanation
    assert f.limitations


def test_whitespace_star_still_matches():
    findings = broad_permissions.check(_fixture(["  *  "]), "a.json")
    assert len(findings) == 1


@pytest.mark.parametrize(
    "commands",
    [
        ["ls", "git status"],  # plain allowlist
        ["ls *"],  # glob for one command, not a full allowlist wildcard
        ["sudo:*"],  # namespaced pattern, out of scope for this narrow rule
        ["shell:*"],
        ["all"],
        ["* *"],  # two stars is not the exact "*" token
        [""],  # empty string
    ],
)
def test_benign_examples_do_not_trigger(commands):
    assert broad_permissions.check(_fixture(commands), "a.json") == []


def test_no_permissions_no_finding():
    fx = AgentFixture.model_validate(
        {"schema_version": "1.0", "tools": [{"name": "reader", "description": "d"}]}
    )
    assert broad_permissions.check(fx, "a.json") == []


def test_finding_does_not_dump_whole_config():
    findings = broad_permissions.check(_fixture(["*"]), "a.json")
    dumped = findings[0].model_dump_json()
    assert "git status" not in dumped
    assert len(findings[0].evidence.matched_value) <= 200
