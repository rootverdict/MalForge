"""Tests for core data models."""

import pytest

from core.models import (
    AttackMapping,
    Behavior,
    IOC,
    PipelineResult,
    RiskScore,
    SigmaRule,
    ValidationResult,
    WazuhRule,
)


def test_behavior_normalizes_severity() -> None:
    behavior = Behavior(
        category="process",
        description="Creates a suspicious child process",
        source="cuckoo",
        severity="HIGH",
    )

    assert behavior.severity == "high"


def test_ioc_rejects_invalid_confidence() -> None:
    with pytest.raises(ValueError):
        IOC(type="domain", value="bad.example", source="cape", confidence=1.5)


def test_sigma_rule_normalizes_level() -> None:
    rule = SigmaRule(
        title="Suspicious Process Tree",
        rule_id="sigma-001",
        description="Flags a suspicious process chain",
        logsource={"product": "windows"},
        detection={"selection": {"Image": "cmd.exe"}},
        level="CRITICAL",
    )

    assert rule.level == "critical"


def test_attack_mapping_validates_confidence() -> None:
    mapping = AttackMapping(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic="execution",
        source_behavior="process_spawn",
        confidence=0.9,
    )

    assert mapping.confidence == 0.9


def test_pipeline_result_serializes_nested_models() -> None:
    result = PipelineResult(
        source="anyrun",
        behaviors=[
            Behavior(
                category="network",
                description="Connects to an external host",
                source="anyrun",
            )
        ],
        iocs=[IOC(type="ip", value="10.0.0.7", source="anyrun")],
        sigma_rules=[
            SigmaRule(
                title="External Host Connection",
                rule_id="sigma-002",
                description="Flags outbound connection behavior",
                logsource={"category": "network_connection"},
                detection={"selection": {"DestinationIp": "10.0.0.7"}},
            )
        ],
        wazuh_rules=[
            WazuhRule(rule_id=100001, level=7, description="Outbound connection detected")
        ],
        attack_mappings=[
            AttackMapping(
                technique_id="T1071",
                technique_name="Application Layer Protocol",
                tactic="command_and_control",
                source_behavior="network_connection",
            )
        ],
        validation_results=[
            ValidationResult(is_valid=True, validator="schema", score=1.0)
        ],
        risk_score=RiskScore(score=75.0, severity="high"),
    )

    data = result.to_dict()

    assert data["source"] == "anyrun"
    assert data["behaviors"][0]["category"] == "network"
    assert data["wazuh_rules"][0]["rule_id"] == 100001
    assert data["risk_score"]["severity"] == "high"


def test_risk_score_rejects_negative_values() -> None:
    with pytest.raises(ValueError):
        RiskScore(score=-1, severity="medium")


def test_risk_score_rejects_values_above_hundred() -> None:
    with pytest.raises(ValueError):
        RiskScore(score=150, severity="high")
